# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[unreleased]: https://github.com/pimalaya/io-proxy/compare/v0.1.0..HEAD
[0.1.0]: https://github.com/pimalaya/io-proxy/compare/root..v0.1.0
