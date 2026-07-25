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
use core::fmt;

use base64::{Engine, engine::general_purpose::STANDARD};
use log::{debug, trace};
use thiserror::Error;

use crate::coroutine::{ProxyCoroutine, ProxyCoroutineState, ProxyYield};

/// Cap on the proxy response head, to bound memory against a proxy that
/// never sends the blank-line terminator.
const MAX_HEAD_SIZE: usize = 64 * 1024;

/// Failure causes during the HTTP `CONNECT` handshake.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum HttpConnectError {
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
    password: String,
}

impl HttpCredentials {
    /// Builds Basic credentials from a username and password.
    pub fn new(username: &str, password: &str) -> HttpCredentials {
        HttpCredentials {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    /// Renders the `Proxy-Authorization` header value: `Basic <base64>`.
    fn header_value(&self) -> String {
        let token = STANDARD.encode(format!("{}:{}", self.username, self.password));
        format!("Basic {token}")
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
    request: Vec<u8>,
    head: Vec<u8>,
    state: State,
}

impl HttpConnect {
    /// Creates a coroutine tunnelling to `host:port`, sending
    /// `Proxy-Authorization: Basic` when `credentials` are provided.
    pub fn new(host: &str, port: u16, credentials: Option<HttpCredentials>) -> Self {
        let mut request = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
        if let Some(credentials) = &credentials {
            request.push_str(&format!(
                "Proxy-Authorization: {}\r\n",
                credentials.header_value()
            ));
        }
        request.push_str("\r\n");

        debug!("prepare http connect handshake");
        Self {
            request: request.into_bytes(),
            head: Vec::new(),
            state: State::SendRequest,
        }
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
                Yielded(ProxyYield::WantsWrite(core::mem::take(&mut self.request)))
            }

            State::ReadHead => {
                if let Some(data) = arg {
                    self.head.extend_from_slice(data);
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
        let mut cor = HttpConnect::new("imap.example.com", 993, None);
        let req = wants_write(&mut cor, None);
        assert_eq!(
            req,
            b"CONNECT imap.example.com:993 HTTP/1.1\r\nHost: imap.example.com:993\r\n\r\n"
        );
    }

    #[test]
    fn request_includes_basic_auth() {
        let creds = HttpCredentials::new("user", "pass");
        let mut cor = HttpConnect::new("h", 1, Some(creds));
        let req = wants_write(&mut cor, None);
        let req = String::from_utf8(req).unwrap();
        // base64("user:pass") = dXNlcjpwYXNz
        assert!(req.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
    }

    #[test]
    fn established_on_2xx() {
        let mut cor = HttpConnect::new("h", 1, None);
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
        let mut cor = HttpConnect::new("h", 1, None);
        wants_write(&mut cor, None);
        complete_ok(&mut cor, Some(b"HTTP/1.0 200 OK\r\n\r\n"));
    }

    #[test]
    fn refused_on_non_2xx() {
        let mut cor = HttpConnect::new("h", 1, None);
        wants_write(&mut cor, None);
        let err = complete_err(&mut cor, Some(b"HTTP/1.1 403 Forbidden\r\n\r\n"));
        assert_eq!(err, HttpConnectError::Refused(403));
    }

    #[test]
    fn malformed_status_line() {
        let mut cor = HttpConnect::new("h", 1, None);
        wants_write(&mut cor, None);
        let err = complete_err(&mut cor, Some(b"garbage-without-code\r\n\r\n"));
        assert_eq!(err, HttpConnectError::MalformedStatus);
    }

    #[test]
    fn debug_redacts_password() {
        let creds = HttpCredentials::new("alice", "secret");
        let rendered = format!("{creds:?}");
        assert!(rendered.contains("alice"));
        assert!(!rendered.contains("secret"));
    }
}
