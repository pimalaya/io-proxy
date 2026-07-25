---
cairn: spec
capability: client
status: current
---

# Client

An optional standard, blocking pump driving the proxy coroutines over any `Read + Write` stream, behind the `client` feature. This is the only layer that touches std; the crate opens no connections of its own and negotiates no TLS. The caller connects to the proxy, runs a handshake, then owns the live tunnel.

### Requirement: Feature gate
The pump SHALL be gated on the `client` feature (the only feature that pulls std into the build), and compiled only when at least one protocol feature (`socks5` or `http`) is also enabled.

### Requirement: Exact-read pump
The pump SHALL drive a coroutine to completion, writing every `WantsWrite` in full and satisfying every `WantsRead(n)` with an exact read of `n` bytes, so on return the stream holds no buffered tunnel bytes.

### Requirement: Entry points
`connect_socks5` SHALL run a SOCKS5 handshake to a `Socks5Address` with optional `Socks5Credentials`; `connect_http` SHALL run an HTTP `CONNECT` handshake to a host and port with optional `HttpCredentials`. Both SHALL surface failures through `ProxyClientError`, wrapping the protocol handshake error and any stream I/O error.
