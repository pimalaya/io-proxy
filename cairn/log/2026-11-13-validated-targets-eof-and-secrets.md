---
cairn: log
change: validated-targets-eof-and-secrets
landed: 2026-11-13
---

# Targets are validated, the end of a stream is an error, secrets stay wrapped

Four findings of the family audit of 2026-11-13 (PROXY-01 to PROXY-04), all low and none reachable through the family's own callers, closed in one change. Each was reproduced first with a test that failed on the old code.

**HTTP CONNECT target (PROXY-01).** `HttpConnect::new` in src/http/connect.rs now returns `Result<Self, HttpConnectError>`. It accepts a non-empty registered name of RFC 3986 section 3.2.2 (checked by the private `is_reg_name`: unreserved characters, `%` followed by two hex digits, sub-delimiters), which covers IPv4 literals, or an IPv6 literal that `core::net::Ipv6Addr` parses, bare or already bracketed; everything else is `HttpConnectError::InvalidHost`. The bare literal gets its brackets, the bracketed one is kept as is. Before the fix the host `h:1 HTTP/1.1\r\nX-Injected: 1\r\n\r\n` produced a request holding the injected header line, and `2001:db8::1` produced `CONNECT 2001:db8::1:443 HTTP/1.1`. `connect_http` in src/client.rs keeps its signature: the rejection travels through `ProxyClientError::Http` and nothing is written. An IPv6 zone identifier and a host outside ASCII are rejected: a caller passes the A-label form, as a parsed URL gives it.

**SOCKS5 domain (PROXY-02).** `Socks5Address::Domain` in src/socks/v5/address.rs holds a `Socks5Domain`, a tuple struct with a private field and an `as_str` accessor, built by `Socks5Address::new` alone. Before the fix `Socks5Address::Domain("a".repeat(300), 80)` encoded a length byte of 44; that expression no longer compiles. `Socks5Address::new("", 1)` returned `Ok(Domain("", 1))` and now fails with the new `Socks5AddressError::DomainEmpty`.

**End of stream (PROXY-03).** `ProxyCoroutine::resume` documents `Some(&[])` as the end of the stream. `Socks5Connect` completes with the new `Socks5ConnectError::Eof` on an empty read in any state but the completed one, and its bound-address step compares the length it is handed with the one it asked for (`Malformed` otherwise) where it used to complete `Ok` on any argument. `HttpConnect` completes with the new `HttpConnectError::Eof` where it used to yield `WantsRead(1)` again without end. The blocking pump is unchanged: `read_exact` fails first with `UnexpectedEof`, now pinned by a test. Resuming after completion still panics, as the spec records.

**Secrets (PROXY-04).** `HttpCredentials` and `Socks5Credentials` hold and take the password as a `secrecy::SecretString` (secrecy 0.10 without default features, a new dependency the sister crates already carry). `HttpConnect` no longer keeps the rendered request: it keeps the validated authority and the credentials and renders the request when it yields it, so the derived `Debug` prints the authority and the redacted credentials. This was chosen over the hand-written `Debug` the audit suggested, because the encoded credentials then no longer sit in a plain buffer before the first resume and the coroutine has the same shape as `Socks5Connect`. The `user:password` pair is built at its exact capacity inside a `SecretString`, so it is wiped once encoded. `ProxyYield` gets a hand-written `Debug` printing `WantsWrite([n bytes])`: the audit did not list it for this crate, but the CONNECT request and the SOCKS5 sub-negotiation (the password in clear) leave the coroutine through that value, and the old output printed them byte by byte.

Breaking for a 0.x minor: `HttpConnect::new` returns a `Result`; `Socks5Address::Domain` holds a `Socks5Domain`; both credential constructors take a `SecretString`; `HttpConnectError` gains `InvalidHost` and `Eof`, `Socks5ConnectError` gains `Eof`, `Socks5AddressError` gains `DomainEmpty` (none of the three enums is non-exhaustive). pimalaya-stream, the family's only consumer, builds its credentials from an exposed `&str` in src/proxy.rs and will pass `auth.pass.clone()` once it moves to the release holding this change; its `connect_http` and `Socks5Address::new` calls compile unchanged.

Existing tests moved to the new signatures without any assertion changing: the `HttpConnect::new(..)` calls gained `.unwrap()`, the credential constructors a `SecretString::from`, and the three tests that built `Socks5Address::Domain(..)` directly go through `Socks5Address::new`.

Capabilities moved: coroutines (end of stream, yield redaction), http-connect (target host validation, response handling, credential redaction), socks5 (target addressing, reply handling, credential redaction), client (exact-read pump, entry points), packaging (secrecy).

Verified: `cargo test --all-features` (37 unit tests passed, the 6 proxy tests ignored as they need Docker), `cargo clippy --all-features --all-targets -- -D warnings` clean, `cargo build --no-default-features` alone, with `socks5` and with `http`.
