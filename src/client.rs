//! Standard, blocking pump driving the proxy coroutines over any
//! `Read + Write` stream.
//!
//! On success the stream is a live tunnel to the target, positioned at
//! its first byte, ready for the caller's TLS handshake or plaintext
//! protocol.

use std::io::{Read, Write};

use thiserror::Error;

use crate::coroutine::{ProxyCoroutine, ProxyCoroutineState, ProxyYield};
#[cfg(feature = "http")]
use crate::http::connect::{HttpConnect, HttpCredentials};
#[cfg(feature = "socks5")]
use crate::socks::v5::{
    address::Socks5Address,
    auth::Socks5Credentials,
    connect::{Socks5Connect, Socks5ConnectError},
};

/// Largest single read any handshake requests: a SOCKS5 domain-typed
/// bound address is `1 + 255 + 2` bytes; every other read is smaller.
const READ_BUFFER_SIZE: usize = 258;

/// Errors returned by the client pump.
#[derive(Debug, Error)]
pub enum ProxyClientError {
    /// The SOCKS5 handshake coroutine failed.
    #[cfg(feature = "socks5")]
    #[error(transparent)]
    Socks5(#[from] Socks5ConnectError),
    /// The HTTP `CONNECT` handshake coroutine failed.
    #[cfg(feature = "http")]
    #[error(transparent)]
    Http(#[from] crate::http::connect::HttpConnectError),
    /// The underlying stream failed to read or write.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Drives a proxy coroutine against `stream` until it completes.
///
/// Every read is exact (`read_exact`), so on return the stream holds no
/// buffered tunnel bytes.
fn run<S, C, E>(stream: &mut S, mut coroutine: C) -> Result<(), ProxyClientError>
where
    S: Read + Write,
    C: ProxyCoroutine<Yield = ProxyYield, Return = Result<(), E>>,
    ProxyClientError: From<E>,
{
    let mut buf = [0u8; READ_BUFFER_SIZE];
    let mut arg: Option<&[u8]> = None;

    loop {
        match coroutine.resume(arg.take()) {
            ProxyCoroutineState::Complete(Ok(())) => return Ok(()),
            ProxyCoroutineState::Complete(Err(err)) => return Err(err.into()),
            ProxyCoroutineState::Yielded(ProxyYield::WantsWrite(bytes)) => {
                stream.write_all(&bytes)?;
                arg = None;
            }
            ProxyCoroutineState::Yielded(ProxyYield::WantsRead(n)) => {
                stream.read_exact(&mut buf[..n])?;
                arg = Some(&buf[..n]);
            }
        }
    }
}

/// Runs the SOCKS5 `CONNECT` handshake on `stream` (already connected to
/// the proxy), tunnelling to `target` and authenticating with
/// `credentials` if the proxy asks for username/password.
#[cfg(feature = "socks5")]
#[cfg_attr(docsrs, doc(cfg(feature = "socks5")))]
pub fn connect_socks5<S: Read + Write>(
    stream: &mut S,
    target: Socks5Address,
    credentials: Option<Socks5Credentials>,
) -> Result<(), ProxyClientError> {
    run(stream, Socks5Connect::new(target, credentials))
}

/// Runs the HTTP `CONNECT` handshake on `stream` (already connected to the
/// proxy), tunnelling to `host:port` and sending `Proxy-Authorization:
/// Basic` if `credentials` are provided.
#[cfg(feature = "http")]
#[cfg_attr(docsrs, doc(cfg(feature = "http")))]
pub fn connect_http<S: Read + Write>(
    stream: &mut S,
    host: &str,
    port: u16,
    credentials: Option<HttpCredentials>,
) -> Result<(), ProxyClientError> {
    run(stream, HttpConnect::new(host, port, credentials))
}

#[cfg(all(test, feature = "socks5"))]
mod socks5_tests {
    use std::{
        io::{self, Cursor, Read, Write},
        vec::Vec,
    };

    use super::*;

    /// A fake proxy: hands out `to_read` on reads, records writes.
    struct Fake {
        to_read: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl Read for Fake {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.to_read.read(buf)
        }
    }

    impl Write for Fake {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn drives_handshake_and_leaves_tunnel_bytes() {
        // method selection (no-auth) + success reply (IPv4) + one extra
        // byte that belongs to the tunnel and must NOT be consumed.
        let mut server = vec![0x05, 0x00];
        server.extend_from_slice(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        server.push(0xAB); // tunnel payload

        let mut fake = Fake {
            to_read: Cursor::new(server),
            written: Vec::new(),
        };

        connect_socks5(
            &mut fake,
            Socks5Address::Domain("example.com".into(), 993),
            None,
        )
        .unwrap();

        // greeting was written
        assert_eq!(&fake.written[..3], [0x05, 0x01, 0x00]);

        // the tunnel byte is still unread on the stream
        let mut rest = Vec::new();
        fake.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, [0xAB]);
    }
}

#[cfg(all(test, feature = "http"))]
mod http_tests {
    use std::{
        io::{self, Cursor, Read, Write},
        vec::Vec,
    };

    use super::*;

    struct Fake {
        to_read: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl Read for Fake {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.to_read.read(buf)
        }
    }

    impl Write for Fake {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn drives_connect_and_leaves_tunnel_bytes() {
        // a 200 response head, then a tunnel byte the byte-at-a-time reader
        // must leave untouched.
        let mut server = b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec();
        server.push(0xAB);

        let mut fake = Fake {
            to_read: Cursor::new(server),
            written: Vec::new(),
        };

        connect_http(&mut fake, "imap.example.com", 993, None).unwrap();

        assert!(fake.written.starts_with(b"CONNECT imap.example.com:993"));

        let mut rest = Vec::new();
        fake.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, [0xAB]);
    }
}
