---
cairn: log
change: bootstrap
landed: 2026-07-26
---

# Bootstrap and guidelines alignment

Brought the freshly bootstrapped crate up to the Pimalaya standard. The I/O-free coroutines already existed (`ProxyCoroutine`/`ProxyCoroutineState`/`ProxyYield`, the SOCKS5 and HTTP `CONNECT` handshakes, and the std pump); this change added everything a standard Pimalaya library ships around them and aligned the public API with the naming guidelines.

The SOCKS5 wire types gained the `Socks5` domain prefix (`Address` to `Socks5Address`, `AddressError` to `Socks5AddressError`, the auth `Credentials` to `Socks5Credentials`, `CredentialsError` to `Socks5CredentialsError`, `Reply` to `Socks5Reply`), and the HTTP `Credentials` became `HttpCredentials`, so every public item now carries its domain prefix. The `Socks5ConnectError::Reply` variant kept its name, only its payload type moved.

Added the repository skeleton: README, CHANGELOG, dual LICENSE-MIT/LICENSE-APACHE, deny.toml, SECURITY.md, a CONTRIBUTING.md documenting the feature matrix and the Docker-backed integration tests, the Nix flake and shell, .gitignore and .envrc, an example, and this Cairn folder with its AGENTS.md activation stanza.

Capabilities recorded for the first time: coroutines, socks5, http-connect, client, packaging.
