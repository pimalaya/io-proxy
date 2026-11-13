---
cairn: tasks
change: validated-targets-eof-and-secrets
---

# Tasks

- [x] src/http/connect.rs: `HttpConnect::new` returns `Result<Self, HttpConnectError>`, validates the host (`is_reg_name`, IPv6 literal bare or bracketed) and brackets a bare IPv6 literal; new `HttpConnectError::InvalidHost`
- [x] Tests `http::connect::tests::ipv6_host_is_bracketed` and `host_outside_the_grammar_is_rejected` (both failed before the fix, in their first form); `client::http_tests::invalid_host_writes_nothing`
- [x] src/client.rs: `connect_http` propagates the rejection through `ProxyClientError::Http`
- [x] src/socks/v5/address.rs: `Socks5Domain` with a private field, `Socks5Address::Domain(Socks5Domain, u16)`, new `Socks5AddressError::DomainEmpty`
- [x] Test `socks::v5::address::tests::new_rejects_empty_domain` (failed before the fix); the over-long name through the variant, which encoded a length byte of 44 for 300 bytes, no longer compiles; `encode_longest_domain` pins the 255-byte edge
- [x] src/coroutine.rs: `Some(&[])` documented as the end of the stream
- [x] src/socks/v5/connect.rs: `Socks5ConnectError::Eof` on an empty read, length check in the bound-address step
- [x] src/http/connect.rs: `HttpConnectError::Eof` on an empty read
- [x] Tests `socks::v5::connect::tests::eof_in_reply_tail_returns_eof`, `short_reply_tail_returns_malformed`, `http::connect::tests::eof_in_head_returns_eof` (all three failed before the fix), plus `eof_in_method_selection_returns_eof` and `client::socks5_tests::end_of_stream_surfaces_as_io_error`
- [x] Cargo.toml: secrecy 0.10 without default features; `HttpCredentials` and `Socks5Credentials` hold and take a `SecretString`
- [x] src/http/connect.rs: `HttpConnect` keeps the authority and the credentials, renders the request on the way out; test `debug_omits_credentials` (failed before the fix)
- [x] src/coroutine.rs: hand-written `Debug` for `ProxyYield`; test `coroutine::tests::debug_omits_written_bytes` (failed before the fix)
- [x] Existing tests moved to the new signatures (no assertion changed)
- [x] Spec folded (coroutines, http-connect, socks5, client, packaging), CHANGELOG under [Unreleased], log
- [ ] pimalaya-stream, once this is released: pass `auth.pass.clone()` where it exposes the secret today (src/proxy.rs, both credential constructors)
