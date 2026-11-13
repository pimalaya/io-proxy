---
cairn: change
id: validated-targets-eof-and-secrets
status: landed
created: 2026-11-13
---

# Targets are validated, the end of a stream is an error, secrets stay wrapped

## Why

Four defects from the family audit of 2026-11-13 (PROXY-01 to PROXY-04), each checked against the code on 2026-11-13 with a test that failed before the fix.

- **The CONNECT target host went out unchecked (PROXY-01).** `HttpConnect::new` formatted its `host` straight into the request line and the `Host` header. A host holding a line break added header lines or a second request ahead of the `Proxy-Authorization` line, a space rewrote the request line, and a bare IPv6 literal gave `CONNECT 2001:db8::1:443`, which is not the authority-form of RFC 9110 section 9.3.6. No caller in the family can supply such a host today (they all pass a parsed URL's host, already bracketed), so this is hardening of a public entry point that takes a bare string.
- **The SOCKS5 domain limit had a way around it (PROXY-02).** `Socks5Address::Domain(String, u16)` was a public variant and only `Socks5Address::new` checked the 255-byte limit. A 300-byte name built through the variant went out with a length byte of 44: the proxy connected to the first 44 bytes, read the next two as the port, and took the rest as tunnel payload. The empty name was accepted by both ways.
- **The end of the stream was outside the contract (PROXY-03).** The contract only said "exactly the `n` bytes" and gave a caller no way to report an end of stream. A caller following the family convention of an empty read got a success from the SOCKS5 bound-address step (any argument of any length completed the handshake), an endless `WantsRead(1)` from `HttpConnect`, and `Malformed` from the other SOCKS5 steps, where a closed connection could not be told from a protocol violation. The blocking pump was not affected: its exact read fails first.
- **Proxy passwords were plain strings and one Debug output printed them encoded (PROXY-04).** `HttpCredentials` redacted its own `Debug`, but `HttpConnect` kept the rendered request, `Proxy-Authorization` line included, in a field its derived `Debug` printed. `ProxyYield` printed the bytes to write the same way, which covers that request and the SOCKS5 sub-negotiation holding the password in clear. Both credential types kept the password in a `String`, dropped without being wiped, and a caller holding a `SecretString` had to expose it to build them.

## What

- `HttpConnect::new` returns a `Result` and accepts only a non-empty registered name of RFC 3986 section 3.2.2 (which covers IPv4 literals) or an IPv6 literal, bare or bracketed; anything else fails with the new `HttpConnectError::InvalidHost`. An IPv6 literal is written between brackets, added when missing and never doubled. `connect_http` keeps its signature and reports the rejection through `ProxyClientError::Http`, before any byte is written.
- `Socks5Address::Domain` holds a `Socks5Domain`, a name of 1 to 255 bytes with a private field that only `Socks5Address::new` builds. The empty name fails with the new `Socks5AddressError::DomainEmpty`.
- An empty read (`Some(&[])`) is the end of the stream in the contract, and both coroutines complete on it with a new `Eof` variant of their error. The SOCKS5 bound-address step checks the length it is handed, as the other steps do.
- `HttpCredentials::new` and `Socks5Credentials::new` take and keep the password as a `secrecy::SecretString`. `HttpConnect` keeps the validated authority and the credentials and renders the request when it yields it, so its derived `Debug` has no secret to print. `ProxyYield` gets a hand-written `Debug` giving the length of the bytes to write.

Resuming a coroutine after completion still panics: that is the recorded contract and stays.

## Choices

- The ledger asked for a hand-written `Debug` on `HttpConnect`. Not keeping the rendered request at all was preferred: the coroutine then mirrors `Socks5Connect` (target and credentials kept, messages rendered on the way out), and the encoded credentials no longer sit in a plain buffer between construction and the first resume.
- The host check is an allow-list (the `reg-name` grammar) and not a deny-list of dangerous bytes, so a host outside ASCII is rejected too: an internationalised name must be passed in its A-label form, which is what a parsed URL already gives.
- The `ProxyYield` part was not in the audit's list for this crate. It is the same leak one step further (the request and the SOCKS5 password leave the coroutine through that value), so it is closed in the same change.
- The password is taken by value, the caller cloning its `SecretString` when it keeps one, so no extra copy of the secret is made.
- The blocking pump keeps its exact read: an end of stream there stays the stream's `UnexpectedEof` I/O error.
