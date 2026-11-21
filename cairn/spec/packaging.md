---
cairn: spec
capability: packaging
status: current
---

# Packaging

io-proxy is an I/O-free library following the Pimalaya crate conventions: a `no_std` core with an optional std-blocking client, dual-licensed MIT OR Apache-2.0.

### Requirement: no_std core
The crate SHALL be `#![no_std]` unconditionally, pulling in `alloc` for its owned buffers. std SHALL be reachable only through the `std` feature.

### Requirement: Feature layering
The crate SHALL follow the family's layered feature shape (GUIDELINES cargo-006) without a TLS layer, since it opens no connection: a `client` feature SHALL gate the client side (the `coroutine` contract), the `socks5` and `http` protocol features SHALL each imply `client` and gate their own coroutines, and a `std` feature, implying `client`, SHALL gate the std-blocking pump. Beside `client`, the one exception the rule names, a feature is justified only when it changes the crate set. The default SHALL enable `client`, `socks5`, `http` and `std`. The crate has no server side, no TLS features and no `vendored` feature. The `http` feature SHALL pull in base64-codec for Basic proxy authorization. The crate SHALL depend on secrecy, without its default features, for the proxy passwords of both protocols.

### Requirement: No TLS layer
The crate SHALL NOT ship a full client with connection or TLS handling. It tunnels a stream the caller already holds; TLS is negotiated on top of the established tunnel by the caller.

### Requirement: Source layout
The source tree SHALL be organised one module per protocol (`socks`, `http`), each behind its feature, with the SOCKS protocol versioned from within (`socks::v5`). The shared coroutine contract and the std pump SHALL live at the crate root (`coroutine`, `client`).
