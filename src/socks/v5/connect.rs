//! I/O-free coroutine running the SOCKS5 client `CONNECT` handshake
//! ([RFC 1928] method negotiation + request/reply, [RFC 1929] auth).
//!
//! On success the tunnel to the target is open and the socket is
//! positioned exactly at its first byte — the coroutine reads each
//! length-framed message with an exact byte count, so nothing past the
//! reply is ever consumed.
//!
//! [RFC 1928]: https://www.rfc-editor.org/rfc/rfc1928
//! [RFC 1929]: https://www.rfc-editor.org/rfc/rfc1929

use alloc::vec::Vec;

use log::{debug, trace};
use thiserror::Error;

use crate::{
    coroutine::{ProxyCoroutine, ProxyCoroutineState, ProxyYield},
    socks::v5::{
        ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, AUTH_VERSION, CMD_CONNECT, METHOD_NO_ACCEPTABLE,
        METHOD_NO_AUTH, METHOD_USER_PASS, RSV, VERSION, address::Socks5Address,
        auth::Socks5Credentials, message::Socks5Reply,
    },
};

/// Failure causes during the SOCKS5 `CONNECT` handshake.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum Socks5ConnectError {
    /// The proxy replied with a SOCKS version other than `0x05`.
    #[error("SOCKS5 connect failed: proxy returned version {0:#04x}, expected 0x05")]
    UnexpectedVersion(u8),
    /// The proxy accepted none of the offered authentication methods.
    #[error("SOCKS5 connect failed: proxy rejected all offered authentication methods")]
    NoAcceptableAuthMethod,
    /// The proxy selected an authentication method the client did not
    /// offer or does not support.
    #[error("SOCKS5 connect failed: proxy selected unsupported authentication method {0:#04x}")]
    UnsupportedAuthMethod(u8),
    /// The proxy asked for username/password auth but no credentials were
    /// configured.
    #[error(
        "SOCKS5 connect failed: proxy requires authentication but no credentials were provided"
    )]
    AuthRequired,
    /// The auth sub-negotiation carried a version other than `0x01`.
    #[error("SOCKS5 connect failed: invalid auth sub-negotiation version {0:#04x}, expected 0x01")]
    UnexpectedAuthVersion(u8),
    /// The proxy rejected the username/password credentials.
    #[error("SOCKS5 connect failed: proxy rejected the username/password credentials")]
    AuthRejected,
    /// The proxy refused the `CONNECT` with a known reply code.
    #[error("SOCKS5 connect failed: {0}")]
    Reply(Socks5Reply),
    /// The proxy replied with a reply code outside the RFC 1928 range.
    #[error("SOCKS5 connect failed: proxy returned unknown reply code {0:#04x}")]
    UnknownReply(u8),
    /// The proxy reply used an address type the client cannot parse.
    #[error("SOCKS5 connect failed: proxy returned unknown address type {0:#04x}")]
    UnknownAddressType(u8),
    /// A message from the proxy was shorter than its fixed framing
    /// requires (a misbehaving pump or proxy).
    #[error("SOCKS5 connect failed: proxy sent a malformed or truncated message")]
    Malformed,
}

/// Handshake step; each read step yields [`ProxyYield::WantsRead`] with an
/// exact length, then consumes exactly those bytes on the next resume.
#[derive(Debug)]
enum State {
    /// Emit the method-negotiation greeting.
    Greet,
    /// Read the 2-byte method selection.
    Method,
    /// Emit the username/password sub-negotiation.
    Auth,
    /// Read the 2-byte auth status.
    AuthStatus,
    /// Emit the `CONNECT` request.
    Request,
    /// Read the 4-byte reply head (`VER REP RSV ATYP`).
    ReplyHead,
    /// Read the 1-byte domain length of a domain-typed bound address.
    ReplyDomainLen,
    /// Read the remaining `n` bytes of `BND.ADDR` + `BND.PORT`.
    ReplyTail(usize),
    /// Handshake complete.
    Done,
}

/// I/O-free SOCKS5 `CONNECT` handshake coroutine.
#[derive(Debug)]
pub struct Socks5Connect {
    target: Socks5Address,
    credentials: Option<Socks5Credentials>,
    state: State,
}

impl Socks5Connect {
    /// Creates a coroutine that tunnels to `target`, authenticating with
    /// `credentials` if the proxy requests username/password.
    pub fn new(target: Socks5Address, credentials: Option<Socks5Credentials>) -> Self {
        debug!("prepare socks5 connect handshake");
        Self {
            target,
            credentials,
            state: State::Greet,
        }
    }

    /// `VER | NMETHODS | METHODS`: offer no-auth, plus username/password
    /// when credentials are available.
    fn greeting(&self) -> Vec<u8> {
        if self.credentials.is_some() {
            vec![VERSION, 2, METHOD_NO_AUTH, METHOD_USER_PASS]
        } else {
            vec![VERSION, 1, METHOD_NO_AUTH]
        }
    }

    /// `VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT`.
    fn request(&self) -> Vec<u8> {
        let mut out = vec![VERSION, CMD_CONNECT, RSV];
        self.target.encode_into(&mut out);
        out
    }
}

impl ProxyCoroutine for Socks5Connect {
    type Yield = ProxyYield;
    type Return = Result<(), Socks5ConnectError>;

    fn resume(&mut self, mut arg: Option<&[u8]>) -> ProxyCoroutineState<Self::Yield, Self::Return> {
        use ProxyCoroutineState::{Complete, Yielded};

        loop {
            match self.state {
                State::Greet => {
                    trace!("offering method negotiation");
                    self.state = State::Method;
                    return Yielded(ProxyYield::WantsWrite(self.greeting()));
                }

                State::Method => {
                    let Some(data) = arg.take() else {
                        return Yielded(ProxyYield::WantsRead(2));
                    };
                    let &[version, method] = data else {
                        return Complete(Err(Socks5ConnectError::Malformed));
                    };
                    if version != VERSION {
                        return Complete(Err(Socks5ConnectError::UnexpectedVersion(version)));
                    }
                    match method {
                        METHOD_NO_AUTH => {
                            trace!("proxy selected no-auth");
                            self.state = State::Request;
                        }
                        METHOD_USER_PASS => {
                            if self.credentials.is_none() {
                                return Complete(Err(Socks5ConnectError::AuthRequired));
                            }
                            trace!("proxy selected username/password auth");
                            self.state = State::Auth;
                        }
                        METHOD_NO_ACCEPTABLE => {
                            return Complete(Err(Socks5ConnectError::NoAcceptableAuthMethod));
                        }
                        other => {
                            return Complete(Err(Socks5ConnectError::UnsupportedAuthMethod(other)));
                        }
                    }
                }

                State::Auth => {
                    // NOTE: only reached with credentials present.
                    let bytes = self
                        .credentials
                        .as_ref()
                        .expect("credentials present in Auth state")
                        .encode();
                    self.state = State::AuthStatus;
                    return Yielded(ProxyYield::WantsWrite(bytes));
                }

                State::AuthStatus => {
                    let Some(data) = arg.take() else {
                        return Yielded(ProxyYield::WantsRead(2));
                    };
                    let &[version, status] = data else {
                        return Complete(Err(Socks5ConnectError::Malformed));
                    };
                    if version != AUTH_VERSION {
                        return Complete(Err(Socks5ConnectError::UnexpectedAuthVersion(version)));
                    }
                    if status != 0 {
                        return Complete(Err(Socks5ConnectError::AuthRejected));
                    }
                    trace!("username/password auth accepted");
                    self.state = State::Request;
                }

                State::Request => {
                    trace!("requesting connect to target");
                    self.state = State::ReplyHead;
                    return Yielded(ProxyYield::WantsWrite(self.request()));
                }

                State::ReplyHead => {
                    let Some(data) = arg.take() else {
                        return Yielded(ProxyYield::WantsRead(4));
                    };
                    let &[version, rep, _rsv, atyp] = data else {
                        return Complete(Err(Socks5ConnectError::Malformed));
                    };
                    if version != VERSION {
                        return Complete(Err(Socks5ConnectError::UnexpectedVersion(version)));
                    }
                    if rep != 0 {
                        let err = match Socks5Reply::from_u8(rep) {
                            Some(reply) => Socks5ConnectError::Reply(reply),
                            None => Socks5ConnectError::UnknownReply(rep),
                        };
                        return Complete(Err(err));
                    }
                    // consume the bound address so the socket is left at
                    // the tunnel start; its value is not needed
                    match atyp {
                        ATYP_IPV4 => self.state = State::ReplyTail(4 + 2),
                        ATYP_IPV6 => self.state = State::ReplyTail(16 + 2),
                        ATYP_DOMAIN => self.state = State::ReplyDomainLen,
                        other => {
                            return Complete(Err(Socks5ConnectError::UnknownAddressType(other)));
                        }
                    }
                }

                State::ReplyDomainLen => {
                    let Some(data) = arg.take() else {
                        return Yielded(ProxyYield::WantsRead(1));
                    };
                    let &[len] = data else {
                        return Complete(Err(Socks5ConnectError::Malformed));
                    };
                    self.state = State::ReplyTail(len as usize + 2);
                }

                State::ReplyTail(n) => {
                    if arg.take().is_none() {
                        return Yielded(ProxyYield::WantsRead(n));
                    }
                    debug!("socks5 tunnel established");
                    self.state = State::Done;
                    return Complete(Ok(()));
                }

                State::Done => panic!("Socks5Connect resumed after completion"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_auth() -> Socks5Connect {
        Socks5Connect::new(Socks5Address::Domain("example.com".into(), 993), None)
    }

    fn with_auth() -> Socks5Connect {
        let creds = Socks5Credentials::new("user", "pass").unwrap();
        Socks5Connect::new(Socks5Address::Ipv4([1, 2, 3, 4].into(), 25), Some(creds))
    }

    fn wants_write(cor: &mut Socks5Connect, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            ProxyCoroutineState::Yielded(ProxyYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn wants_read(cor: &mut Socks5Connect, arg: Option<&[u8]>) -> usize {
        match cor.resume(arg) {
            ProxyCoroutineState::Yielded(ProxyYield::WantsRead(n)) => n,
            state => panic!("expected WantsRead, got {state:?}"),
        }
    }

    fn complete_ok(cor: &mut Socks5Connect, arg: Option<&[u8]>) {
        match cor.resume(arg) {
            ProxyCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn complete_err(cor: &mut Socks5Connect, arg: Option<&[u8]>) -> Socks5ConnectError {
        match cor.resume(arg) {
            ProxyCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }

    #[test]
    fn no_auth_domain_reply_happy_path() {
        let mut cor = no_auth();

        // greeting: offer no-auth only
        assert_eq!(wants_write(&mut cor, None), [0x05, 0x01, 0x00]);
        // method selection read
        assert_eq!(wants_read(&mut cor, None), 2);
        // server picks no-auth -> connect request with domain address
        let req = wants_write(&mut cor, Some(&[0x05, 0x00]));
        let mut expected = vec![0x05, 0x01, 0x00, 0x03, 11];
        expected.extend_from_slice(b"example.com");
        expected.extend_from_slice(&993u16.to_be_bytes());
        assert_eq!(req, expected);
        // reply head read
        assert_eq!(wants_read(&mut cor, None), 4);
        // reply: success, domain-typed bound address
        assert_eq!(wants_read(&mut cor, Some(&[0x05, 0x00, 0x00, 0x03])), 1);
        // domain length = 3 -> tail of 3 + 2 port
        assert_eq!(wants_read(&mut cor, Some(&[0x03])), 5);
        complete_ok(&mut cor, Some(&[b'a', b'b', b'c', 0x00, 0x50]));
    }

    #[test]
    fn user_pass_ipv4_reply_happy_path() {
        let mut cor = with_auth();

        // greeting: offer no-auth + user/pass
        assert_eq!(wants_write(&mut cor, None), [0x05, 0x02, 0x00, 0x02]);
        assert_eq!(wants_read(&mut cor, None), 2);
        // server selects user/pass -> auth sub-negotiation
        let auth = wants_write(&mut cor, Some(&[0x05, 0x02]));
        assert_eq!(
            auth,
            [
                0x01, 0x04, b'u', b's', b'e', b'r', 0x04, b'p', b'a', b's', b's'
            ]
        );
        // auth status read
        assert_eq!(wants_read(&mut cor, None), 2);
        // auth ok -> connect request
        let _req = wants_write(&mut cor, Some(&[0x01, 0x00]));
        assert_eq!(wants_read(&mut cor, None), 4);
        // reply: success, IPv4 bound address -> tail of 4 + 2
        assert_eq!(wants_read(&mut cor, Some(&[0x05, 0x00, 0x00, 0x01])), 6);
        complete_ok(&mut cor, Some(&[0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn server_requires_auth_without_credentials() {
        let mut cor = no_auth();
        wants_write(&mut cor, None);
        wants_read(&mut cor, None);
        let err = complete_err(&mut cor, Some(&[0x05, 0x02]));
        assert_eq!(err, Socks5ConnectError::AuthRequired);
    }

    #[test]
    fn no_acceptable_method() {
        let mut cor = no_auth();
        wants_write(&mut cor, None);
        wants_read(&mut cor, None);
        let err = complete_err(&mut cor, Some(&[0x05, 0xFF]));
        assert_eq!(err, Socks5ConnectError::NoAcceptableAuthMethod);
    }

    #[test]
    fn rejected_auth() {
        let mut cor = with_auth();
        wants_write(&mut cor, None);
        wants_read(&mut cor, None);
        wants_write(&mut cor, Some(&[0x05, 0x02]));
        wants_read(&mut cor, None);
        let err = complete_err(&mut cor, Some(&[0x01, 0x01]));
        assert_eq!(err, Socks5ConnectError::AuthRejected);
    }

    #[test]
    fn reply_failure_maps_to_reply_error() {
        let mut cor = no_auth();
        wants_write(&mut cor, None);
        wants_read(&mut cor, None);
        wants_write(&mut cor, Some(&[0x05, 0x00]));
        wants_read(&mut cor, None);
        // REP = 0x04 host unreachable
        let err = complete_err(&mut cor, Some(&[0x05, 0x04, 0x00, 0x01]));
        assert_eq!(err, Socks5ConnectError::Reply(Socks5Reply::HostUnreachable));
    }

    #[test]
    fn unexpected_version() {
        let mut cor = no_auth();
        wants_write(&mut cor, None);
        wants_read(&mut cor, None);
        let err = complete_err(&mut cor, Some(&[0x04, 0x00]));
        assert_eq!(err, Socks5ConnectError::UnexpectedVersion(0x04));
    }
}
