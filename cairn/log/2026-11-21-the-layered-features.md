---
cairn: log
change: the-layered-features
landed: 2026-11-21
---

# The layered features

The crate moves to the family's layered feature shape (GUIDELINES cargo-006), the one io-imap, io-smtp and io-webdav ship, minus the TLS layer: io-proxy opens no connection, so it has no TLS features and no `vendored`. The old `client` feature, which gated the std-blocking pump and std, is renamed `std`. `client` now gates the coroutine contract (`coroutine`) and `extern crate alloc`, and `socks5` and `http` imply it; `std` implies `client`. The default set is `client`, `socks5`, `http` and `std`, the same code as before. The std_socks5 example requires `std` and `socks5`, and tests/proxy.rs is gated on `std`, `socks5` and `http`, which it needs (it failed to build under `socks5` alone before).

No change folder: the shape is the family rule, applied as io-webdav applied it on 2026-11-18.

Capabilities moved: packaging ("no_std core" and "Feature layering" modified), client ("Feature gate" modified).

Verified: `cargo build` with no features, `client`, `std`, `socks5`, `http`, `std,http`, default and all features, all warning-free; `cargo test --all-features` (37 unit, 6 live tests ignored) and `--no-default-features --features socks5` (22 unit); `cargo clippy --all-features --all-targets` and `cargo fmt --check` clean.
