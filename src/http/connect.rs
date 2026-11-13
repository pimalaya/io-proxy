//! I/O-free coroutine running the HTTP `CONNECT` tunnel handshake
//! ([RFC 9110 §9.3.6]).
//!
//! Sends `CONNECT host:port HTTP/1.1` in authority-form and treats any
//! `2xx` response as a live tunnel. The response head is read one byte at
//! a time up to the blank-line terminator, so no tunnel payload (a TLS
//! ServerHello, an IMAP/SMTP greeting) past the head is ever consumed:
//! the socket is left positioned exactly at the tunnel start.
//!
//! Only tunnelling is implemented; plaintext HTTP forward proxying
//! (absolute-URI request lines) and non-Basic proxy authentication
//! (Digest, NTLM, Negotiate) are out of scope.
//!
//! [RFC 9110 §9.3.6]: https://www.rfc-editor.org/rfc/rfc9110#section-9.3.6

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt, net::Ipv6Addr};

use base64_codec::codec::Base64Codec;
use log::{debug, trace};
use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

use crate::coroutine::{ProxyCoroutine, ProxyCoroutineState, ProxyYield};

/// Cap on the proxy response head, to bound memory against a proxy that
/// never sends the blank-line terminator.
const MAX_HEAD_SIZE: usize = 64 * 1024;

/// Failure causes during the HTTP `CONNECT` handshake.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum HttpConnectError {
    /// The target host is not a registered name or an IP literal.
    #[error("HTTP CONNECT failed: invalid target host")]
    InvalidHost,
    /// The stream reached EOF before the response head was complete.
    #[error("HTTP CONNECT failed: reached unexpected EOF")]
    Eof,
    /// The proxy refused the tunnel with a non-2xx status.
    #[error("HTTP CONNECT failed: proxy refused the tunnel with status {0}")]
    Refused(u16),
    /// The proxy status line could not be parsed.
    #[error("HTTP CONNECT failed: malformed status line")]
    MalformedStatus,
    /// The response head exceeded the internal cap without terminating.
    #[error("HTTP CONNECT failed: proxy response head too large")]
    HeadTooLarge,
}

/// `Proxy-Authorization: Basic` credentials ([RFC 7617]).
///
/// The password is redacted from the [`Debug`] output. Per RFC 7617 the
/// username must not contain a colon; that is the caller's responsibility.
///
/// [RFC 7617]: https://www.rfc-editor.org/rfc/rfc7617
#[derive(Clone)]
pub struct HttpCredentials {
    username: String,
    password: SecretString,
}

impl HttpCredentials {
    /// Builds Basic credentials from a username and password.
    pub fn new(username: &str, password: SecretString) -> HttpCredentials {
        HttpCredentials {
            username: username.to_string(),
            password,
        }
    }

    /// Renders the `Proxy-Authorization` header value: `Basic <base64>`.
    fn header_value(&self) -> String {
        let password = self.password.expose_secret();

        // NOTE: the exact capacity lets the secret box take the buffer as is.
        let mut pair = String::with_capacity(self.username.len() + 1 + password.len());
        pair.push_str(&self.username);
        pair.push(':');
        pair.push_str(password);
        let pair = SecretString::from(pair);

        let mut value = b"Basic ".to_vec();
        Base64Codec::default().encode_vec(pair.expose_secret().as_bytes(), &mut value);
        // NOTE: the base64 alphabet is ASCII, so this never falls back.
        String::from_utf8(value).unwrap_or_default()
    }
}

impl fmt::Debug for HttpCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpCredentials")
            .field("username", &self.username)
            .field("password", &"***")
            .finish()
    }
}

/// Handshake step.
#[derive(Debug)]
enum State {
    /// Emit the `CONNECT` request.
    SendRequest,
    /// Read the response head, one byte at a time, up to `\r\n\r\n`.
    ReadHead,
    /// Handshake complete.
    Done,
}

/// I/O-free HTTP `CONNECT` handshake coroutine.
#[derive(Debug)]
pub struct HttpConnect {
    authority: String,
    credentials: Option<HttpCredentials>,
    head: Vec<u8>,
    state: State,
}

impl HttpConnect {
    /// Creates a coroutine tunnelling to `host:port`, sending
    /// `Proxy-Authorization: Basic` when `credentials` are provided.
    ///
    /// The host is a registered name or an IP literal ([RFC 3986 §3.2.2]);
    /// an IPv6 literal is bracketed when it is not already.
    ///
    /// [RFC 3986 §3.2.2]: https://www.rfc-editor.org/rfc/rfc3986#section-3.2.2
    pub fn new(
        host: &str,
        port: u16,
        credentials: Option<HttpCredentials>,
    ) -> Result<Self, HttpConnectError> {
        let literal = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'));

        let authority = if host.parse::<Ipv6Addr>().is_ok() {
            format!("[{host}]:{port}")
        } else if literal.is_some_and(|ip| ip.parse::<Ipv6Addr>().is_ok()) || is_reg_name(host) {
            format!("{host}:{port}")
        } else {
            return Err(HttpConnectError::InvalidHost);
        };

        debug!("prepare http connect handshake");
        Ok(Self {
            authority,
            credentials,
            head: Vec::new(),
            state: State::SendRequest,
        })
    }

    /// Renders the authority-form `CONNECT` request.
    fn request(&self) -> Vec<u8> {
        let authority = &self.authority;
        let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");

        if let Some(credentials) = &self.credentials {
            request.push_str("Proxy-Authorization: ");
            request.push_str(&credentials.header_value());
            request.push_str("\r\n");
        }

        request.push_str("\r\n");
        request.into_bytes()
    }

    /// Parses the status code from the accumulated head's first line.
    fn status_code(&self) -> Result<u16, HttpConnectError> {
        let head = String::from_utf8_lossy(&self.head);
        let line = head.lines().next().unwrap_or_default();
        line.split_whitespace()
            .nth(1)
            .and_then(|code| code.parse::<u16>().ok())
            .ok_or(HttpConnectError::MalformedStatus)
    }
}

impl ProxyCoroutine for HttpConnect {
    type Yield = ProxyYield;
    type Return = Result<(), HttpConnectError>;

    fn resume(&mut self, arg: Option<&[u8]>) -> ProxyCoroutineState<Self::Yield, Self::Return> {
        use ProxyCoroutineState::{Complete, Yielded};

        match self.state {
            State::SendRequest => {
                trace!("requesting connect tunnel");
                self.state = State::ReadHead;
                Yielded(ProxyYield::WantsWrite(self.request()))
            }

            State::ReadHead => {
                match arg {
                    Some([]) => {
                        self.state = State::Done;
                        return Complete(Err(HttpConnectError::Eof));
                    }
                    Some(data) => self.head.extend_from_slice(data),
                    None => {}
                }

                if self.head.ends_with(b"\r\n\r\n") {
                    self.state = State::Done;
                    let code = match self.status_code() {
                        Ok(code) => code,
                        Err(err) => return Complete(Err(err)),
                    };
                    if (200..300).contains(&code) {
                        debug!("http tunnel established");
                        return Complete(Ok(()));
                    }
                    return Complete(Err(HttpConnectError::Refused(code)));
                }

                if self.head.len() > MAX_HEAD_SIZE {
                    self.state = State::Done;
                    return Complete(Err(HttpConnectError::HeadTooLarge));
                }

                // one byte at a time so the terminator is never overshot
                // into tunnel payload
                Yielded(ProxyYield::WantsRead(1))
            }

            State::Done => panic!("HttpConnect resumed after completion"),
        }
    }
}

/// Tells whether `host` is a non-empty `reg-name` of RFC 3986 §3.2.2.
fn is_reg_name(host: &str) -> bool {
    let mut bytes = host.bytes();

    while let Some(byte) = bytes.next() {
        let valid = match byte {
            b'%' => (0..2).all(|_| bytes.next().is_some_and(|hex| hex.is_ascii_hexdigit())),
            b'-' | b'.' | b'_' | b'~' => true,
            b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' => true,
            _ => byte.is_ascii_alphanumeric(),
        };

        if !valid {
            return false;
        }
    }

    !host.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wants_write(cor: &mut HttpConnect, arg: Option<&[u8]>) -> Vec<u8> {
        match cor.resume(arg) {
            ProxyCoroutineState::Yielded(ProxyYield::WantsWrite(bytes)) => bytes,
            state => panic!("expected WantsWrite, got {state:?}"),
        }
    }

    fn complete_ok(cor: &mut HttpConnect, arg: Option<&[u8]>) {
        match cor.resume(arg) {
            ProxyCoroutineState::Complete(Ok(())) => {}
            state => panic!("expected Complete(Ok), got {state:?}"),
        }
    }

    fn complete_err(cor: &mut HttpConnect, arg: Option<&[u8]>) -> HttpConnectError {
        match cor.resume(arg) {
            ProxyCoroutineState::Complete(Err(err)) => err,
            state => panic!("expected Complete(Err), got {state:?}"),
        }
    }

    #[test]
    fn request_authority_form_no_auth() {
        let mut cor = HttpConnect::new("imap.example.com", 993, None).unwrap();
        let req = wants_write(&mut cor, None);
        assert_eq!(
            req,
            b"CONNECT imap.example.com:993 HTTP/1.1\r\nHost: imap.example.com:993\r\n\r\n"
        );
    }

    #[test]
    fn request_includes_basic_auth() {
        let creds = HttpCredentials::new("user", SecretString::from("pass"));
        let mut cor = HttpConnect::new("h", 1, Some(creds)).unwrap();
        let req = wants_write(&mut cor, None);
        let req = String::from_utf8(req).unwrap();
        // base64("user:pass") = dXNlcjpwYXNz
        assert!(req.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));

        let creds = HttpCredentials::new("a", SecretString::from("b1"));
        let mut cor = HttpConnect::new("h", 1, Some(creds)).unwrap();
        let req = wants_write(&mut cor, None);
        let req = String::from_utf8(req).unwrap();
        // base64("a:b1") = YTpiMQ==
        assert!(req.contains("Proxy-Authorization: Basic YTpiMQ==\r\n"));
    }

    #[test]
    fn established_on_2xx() {
        let mut cor = HttpConnect::new("h", 1, None).unwrap();
        wants_write(&mut cor, None);
        // request WantsRead(1) first; feeding the whole head at once still
        // completes because the coroutine scans for the terminator.
        assert!(matches!(
            cor.resume(None),
            ProxyCoroutineState::Yielded(ProxyYield::WantsRead(1))
        ));
        complete_ok(
            &mut cor,
            Some(b"HTTP/1.1 200 Connection established\r\n\r\n"),
        );
    }

    #[test]
    fn accepts_http10_and_bare_200() {
        let mut cor = HttpConnect::new("h", 1, None).unwrap();
        wants_write(&mut cor, None);
        complete_ok(&mut cor, Some(b"HTTP/1.0 200 OK\r\n\r\n"));
    }

    #[test]
    fn refused_on_non_2xx() {
        let mut cor = HttpConnect::new("h", 1, None).unwrap();
        wants_write(&mut cor, None);
        let err = complete_err(&mut cor, Some(b"HTTP/1.1 403 Forbidden\r\n\r\n"));
        assert_eq!(err, HttpConnectError::Refused(403));
    }

    #[test]
    fn malformed_status_line() {
        let mut cor = HttpConnect::new("h", 1, None).unwrap();
        wants_write(&mut cor, None);
        let err = complete_err(&mut cor, Some(b"garbage-without-code\r\n\r\n"));
        assert_eq!(err, HttpConnectError::MalformedStatus);
    }

    #[test]
    fn debug_redacts_password() {
        let creds = HttpCredentials::new("alice", SecretString::from("secret"));
        let rendered = format!("{creds:?}");
        assert!(rendered.contains("alice"));
        assert!(!rendered.contains("secret"));
    }

    #[test]
    fn ipv6_host_is_bracketed() {
        for host in ["2001:db8::1", "[2001:db8::1]"] {
            let mut cor = HttpConnect::new(host, 443, None).unwrap();
            let req = wants_write(&mut cor, None);
            assert_eq!(
                String::from_utf8(req).unwrap(),
                "CONNECT [2001:db8::1]:443 HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n"
            );
        }
    }

    #[test]
    fn host_outside_the_grammar_is_rejected() {
        let hosts = [
            "h:1 HTTP/1.1\r\nX-Injected: 1\r\n\r\n",
            "",
            "a b",
            "a\tb",
            "a/b",
            "user@h",
            "h:1",
            "[::1",
            "[h]",
            "a%2",
            "h\u{e9}",
        ];

        for host in hosts {
            let err = HttpConnect::new(host, 1, None).unwrap_err();
            assert_eq!(err, HttpConnectError::InvalidHost, "host: {host:?}");
        }
    }

    #[test]
    fn eof_in_head_returns_eof() {
        let mut cor = HttpConnect::new("h", 1, None).unwrap();
        wants_write(&mut cor, None);
        let err = complete_err(&mut cor, Some(b""));
        assert_eq!(err, HttpConnectError::Eof);
    }

    #[test]
    fn debug_omits_credentials() {
        let creds = HttpCredentials::new("user", SecretString::from("pass"));
        let cor = HttpConnect::new("h", 1, Some(creds)).unwrap();
        let rendered = format!("{cor:?}");
        let encoded = format!("{:?}", b"dXNlcjpwYXNz");
        let encoded = encoded.trim_matches(['[', ']']);
        assert!(!rendered.contains(encoded), "debug: {rendered}");
    }
}
