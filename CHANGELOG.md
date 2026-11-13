# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added `socks::v5::address::Socks5Domain`, a domain name of 1 to 255 bytes that only `Socks5Address::new` builds.

- Added the `Eof` variant to `http::connect::HttpConnectError` and `socks::v5::connect::Socks5ConnectError`.

  A coroutine resumed with an empty read (`Some(&[])`) completes with it. An exhaustive match on either enum needs the new arm.

- Added `http::connect::HttpConnectError::InvalidHost`.

- Added `socks::v5::address::Socks5AddressError::DomainEmpty`.

### Changed

- **BREAKING**: Changed `http::connect::HttpConnect::new` to return a `Result`, failing with `InvalidHost` on a host that is not a registered name or an IP literal.

  An IPv6 literal is written between brackets, added when missing. `client::connect_http` keeps its signature and reports the rejection through `ProxyClientError::Http`.

- **BREAKING**: Changed `socks::v5::address::Socks5Address::Domain` to hold a `Socks5Domain` instead of a `String`.

- **BREAKING**: Changed `http::connect::HttpCredentials::new` and `socks::v5::auth::Socks5Credentials::new` to take the password as a `secrecy::SecretString`.

- Added a dependency on [secrecy](https://crates.io/crates/secrecy) 0.10 for the proxy passwords.

- Changed the `Debug` output of `coroutine::ProxyYield::WantsWrite` to the length of its bytes.

### Fixed

- Fixed `socks::v5::address::Socks5Address::new` accepting an empty domain name.

- Fixed `socks::v5::connect::Socks5Connect` reporting an open tunnel when the read of the bound address was short or empty.

- Fixed `http::connect::HttpConnect` asking for one more byte forever once the stream had ended.

### Security

- Fixed `http::connect::HttpConnect` writing a host holding a line break or a space into the request unchecked.

- Fixed `http::connect::HttpConnect` printing the encoded `Proxy-Authorization` header through its `Debug` output.

## [0.1.1] - 2026-11-03

### Changed

- Replaced the base64 crate with [base64-codec](https://crates.io/crates/base64-codec) for the HTTP `Proxy-Authorization` header.

- Changed the minimum Rust version to 1.89, base64-codec's.

## [0.1.0] - 2026-07-26

### Added

- Added the `ProxyCoroutine` trait mirroring `core::ops::Coroutine`.

  Composed of `Yield` and `Return` associated types and a two-variant `ProxyCoroutineState<Y, R>` (`Yielded` and `Complete`). Every handshake yields the shared `ProxyYield { WantsRead(usize), WantsWrite(Vec<u8>) }`, where `WantsRead` carries an exact byte count so no tunnel payload past the handshake is ever consumed.

- Added the I/O-free SOCKS5 `CONNECT` handshake coroutine following RFC 1928 and RFC 1929.

  `Socks5Connect` drives method negotiation, the optional username/password sub-negotiation, and the request/reply exchange, tunnelling to a `Socks5Address` (an IP literal, or a hostname the proxy resolves) with optional `Socks5Credentials`. The bound address in the reply is consumed so the socket is left exactly at the tunnel start. `Socks5Reply` maps the RFC 1928 reply codes.

- Added the I/O-free HTTP `CONNECT` handshake coroutine following RFC 9110 §9.3.6.

  `HttpConnect` sends an authority-form `CONNECT` request, optionally with a `Proxy-Authorization: Basic` header built from `HttpCredentials` (RFC 7617), and treats any 2xx response as an open tunnel. The response head is read one byte at a time up to the blank-line terminator, so no tunnel payload past the head is consumed.

- Added the `client` cargo feature enabling the std-blocking pump.

  `connect_socks5` and `connect_http` drive a handshake coroutine over any `Read + Write` stream via exact reads, returning once the tunnel is open with the stream positioned on the target's first byte. Errors surface through `ProxyClientError`.

- Added the `socks5` and `http` cargo features gating each protocol independently, with credentials redacted from debug output and logs.

[unreleased]: https://github.com/pimalaya/io-proxy/compare/v0.1.1..HEAD
[0.1.1]: https://github.com/pimalaya/io-proxy/compare/v0.1.0..v0.1.1
[0.1.0]: https://github.com/pimalaya/io-proxy/compare/root..v0.1.0
