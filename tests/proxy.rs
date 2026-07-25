//! End-to-end tests against real SOCKS5 and HTTP CONNECT proxies.
//!
//! Ignored by default; the proxies (and a TCP target that greets each
//! connection with a banner) are spawned by tests/proxy.sh:
//!
//! ```sh
//! ./tests/proxy.sh
//! cargo test --test proxy -- --ignored
//! ```
//!
//! Each test opens a TCP connection to a proxy, runs the handshake to
//! tunnel to the `echo:7` target, then reads the banner back through the
//! tunnel — proving the tunnel carries the target's bytes and that the
//! handshake left them unread (the no-over-read guarantee, for real).

use std::{io::Read, net::TcpStream, time::Duration};

use io_proxy::{
    client::{ProxyClientError, connect_http, connect_socks5},
    http::connect::{HttpConnectError, HttpCredentials},
    socks::v5::{address::Socks5Address, auth::Socks5Credentials, connect::Socks5ConnectError},
};

const PROXY_HOST: &str = "127.0.0.1";
const TARGET_HOST: &str = "echo";
const TARGET_PORT: u16 = 7;
const BANNER: &str = "io-proxy-tunnel-ok";

/// Opens a TCP connection to a proxy listener with a bounded read timeout
/// so a broken tunnel fails the test instead of hanging.
fn proxy(port: u16) -> TcpStream {
    let tcp = TcpStream::connect((PROXY_HOST, port)).expect("connect to proxy");
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    tcp
}

/// Reads the target's banner through an established tunnel and asserts it.
fn assert_banner(mut stream: TcpStream) {
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .expect("read banner through tunnel");
    let got = String::from_utf8_lossy(&buf);
    assert_eq!(got.trim(), BANNER, "unexpected banner through tunnel");
}

fn target() -> Socks5Address {
    Socks5Address::new(TARGET_HOST, TARGET_PORT).unwrap()
}

#[test]
#[ignore = "requires proxies via tests/proxy.sh and --ignored"]
fn socks5_no_auth() {
    let _ = env_logger::try_init();
    let mut tcp = proxy(1080);
    connect_socks5(&mut tcp, target(), None).expect("socks5 handshake");
    assert_banner(tcp);
}

#[test]
#[ignore = "requires proxies via tests/proxy.sh and --ignored"]
fn socks5_auth() {
    let _ = env_logger::try_init();
    let mut tcp = proxy(1081);
    let creds = Socks5Credentials::new("test", "secret").unwrap();
    connect_socks5(&mut tcp, target(), Some(creds)).expect("socks5 auth handshake");
    assert_banner(tcp);
}

#[test]
#[ignore = "requires proxies via tests/proxy.sh and --ignored"]
fn socks5_wrong_credentials() {
    let _ = env_logger::try_init();
    let mut tcp = proxy(1081);
    let creds = Socks5Credentials::new("test", "wrong").unwrap();
    let err = connect_socks5(&mut tcp, target(), Some(creds)).unwrap_err();
    // How a proxy signals bad credentials is implementation-dependent:
    // some fail the RFC 1929 sub-negotiation (AuthRejected), others accept
    // it and then deny the request (e.g. 3proxy → ConnectionNotAllowed).
    // Both are correctly surfaced; assert the failure, not the mechanism.
    assert!(
        matches!(
            err,
            ProxyClientError::Socks5(
                Socks5ConnectError::AuthRejected | Socks5ConnectError::Reply(_)
            )
        ),
        "expected an auth/authorization failure, got {err:?}"
    );
}

#[test]
#[ignore = "requires proxies via tests/proxy.sh and --ignored"]
fn http_no_auth() {
    let _ = env_logger::try_init();
    let mut tcp = proxy(3128);
    connect_http(&mut tcp, TARGET_HOST, TARGET_PORT, None).expect("http connect");
    assert_banner(tcp);
}

#[test]
#[ignore = "requires proxies via tests/proxy.sh and --ignored"]
fn http_auth() {
    let _ = env_logger::try_init();
    let mut tcp = proxy(3129);
    let creds = HttpCredentials::new("test", "secret");
    connect_http(&mut tcp, TARGET_HOST, TARGET_PORT, Some(creds)).expect("http auth connect");
    assert_banner(tcp);
}

#[test]
#[ignore = "requires proxies via tests/proxy.sh and --ignored"]
fn http_wrong_credentials() {
    let _ = env_logger::try_init();
    let mut tcp = proxy(3129);
    let creds = HttpCredentials::new("test", "wrong");
    let err = connect_http(&mut tcp, TARGET_HOST, TARGET_PORT, Some(creds)).unwrap_err();
    assert!(
        matches!(err, ProxyClientError::Http(HttpConnectError::Refused(407))),
        "expected Refused(407), got {err:?}"
    );
}
