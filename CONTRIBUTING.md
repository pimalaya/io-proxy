# Contributing guide

Thank you for investing your time in contributing to I/O Proxy.

Whether you are a human or an AI agent, read these in order before touching the code:

1. the [Pimalaya README](https://github.com/pimalaya) for what the project is and how its repositories stack;
2. the [Pimalaya CONTRIBUTING](https://github.com/pimalaya/.github/blob/master/CONTRIBUTING.md) guide, which chains to the shared architecture and guidelines;
3. the inline header documentation, starting with src/lib.rs: it is the architecture document of this crate;
4. the cairn/ folder for the development history and living plans (the Cairn convention: spec/, changes/, log/).

Everything below documents only what differs from the Pimalaya standards.

## Feature matrix

io-proxy ships the I/O-free coroutines plus one optional std-blocking pump. There is no TLS layer: the crate opens no connections, it tunnels a stream the caller already holds, and any TLS handshake happens on top of the tunnel afterwards. Each protocol is gated on its own feature so a consumer pulls in only what it tunnels through.

```sh
cargo build --no-default-features --features socks5           # SOCKS5 coroutines only, no std leak
cargo build --no-default-features --features http             # HTTP CONNECT coroutines only
cargo build --no-default-features --features socks5,http,client  # both protocols plus the blocking pump
cargo build                                                   # default: socks5 + http + client
```

## Integration tests

The unit tests drive the coroutines against in-memory byte streams and run everywhere. The end-to-end tests in tests/proxy.rs instead tunnel through real SOCKS5 and HTTP CONNECT proxies, so they are marked `#[ignore]` and need Docker. Bring the proxies up, then run them explicitly:

```sh
./tests/proxy.sh
cargo test --test proxy -- --ignored
```

tests/proxy.sh spawns a 3proxy instance (no-auth and authenticated ports for each protocol) plus a banner-emitting TCP target on a private Docker network, and prints the port map it exposes.
