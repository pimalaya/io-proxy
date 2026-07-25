---
cairn: spec
capability: packaging
status: current
---

# Packaging

io-proxy is an I/O-free library following the Pimalaya crate conventions: a `no_std` core with an optional std-blocking client, dual-licensed MIT OR Apache-2.0.

### Requirement: no_std core
The crate SHALL be `#![no_std]` unconditionally, pulling in `alloc` for its owned buffers. std SHALL be reachable only through the `client` feature.

### Requirement: Feature layering
The crate SHALL expose `socks5` and `http` protocol features and a `client` feature gating the std-blocking pump, following the golden rule that a feature is justified only when it changes the crate set. The default SHALL enable `socks5`, `http` and `client`. The `http` feature SHALL pull in base64 for Basic proxy authorization.

### Requirement: No TLS layer
The crate SHALL NOT ship a full client with connection or TLS handling. It tunnels a stream the caller already holds; TLS is negotiated on top of the established tunnel by the caller.

### Requirement: Source layout
The source tree SHALL be organised one module per protocol (`socks`, `http`), each behind its feature, with the SOCKS protocol versioned from within (`socks::v5`). The shared coroutine contract and the std pump SHALL live at the crate root (`coroutine`, `client`).
