---
cairn: delta
change: validated-targets-eof-and-secrets
---

## ADDED Requirements

### Requirement: End of stream (coroutines)

A coroutine resumed with an empty read (`Some(&[])`) while the handshake is not complete SHALL complete with the `Eof` variant of its handshake error. A length-framed coroutine handed a non-empty read of another length than the one it requested SHALL complete with its malformed-message error, never with success.

#### Scenario: The proxy closes after the SOCKS5 reply head

- **WHEN** `Socks5Connect` asked for the 6 bytes of an IPv4 bound address and is resumed with `Some(&[])`
- **THEN** it completes with `Socks5ConnectError::Eof`

#### Scenario: A short bound address

- **WHEN** `Socks5Connect` asked for 6 bytes and is resumed with 2
- **THEN** it completes with `Socks5ConnectError::Malformed`

#### Scenario: The proxy closes inside the HTTP response head

- **WHEN** `HttpConnect` asked for one more byte of the head and is resumed with `Some(&[])`
- **THEN** it completes with `HttpConnectError::Eof`

### Requirement: Yield redaction (coroutines)

The `Debug` output of `ProxyYield` SHALL give the length of a `WantsWrite` payload and never its bytes, which may carry credentials.

### Requirement: Target host validation (http-connect)

`HttpConnect::new` SHALL accept as host only a non-empty registered name of RFC 3986 section 3.2.2 (unreserved characters, percent-encoded octets and sub-delimiters, which covers IPv4 literals) or an IPv6 literal, bare or bracketed, and SHALL fail with `HttpConnectError::InvalidHost` otherwise. It SHALL write an IPv6 literal between brackets, adding them when missing.

#### Scenario: A bare IPv6 literal

- **WHEN** the host is `2001:db8::1` and the port 443
- **THEN** the request line is `CONNECT [2001:db8::1]:443 HTTP/1.1`, the same as for the host `[2001:db8::1]`

#### Scenario: A host holding a line break

- **WHEN** the host holds a CR, a LF, a space, a `/`, an `@`, a `:` outside an IPv6 literal, a byte outside ASCII, or is empty
- **THEN** `HttpConnect::new` fails with `HttpConnectError::InvalidHost` and nothing is written

### Requirement: Credential redaction (socks5)

`Socks5Credentials` SHALL hold the password in a `SecretString` and redact it from its `Debug` output.

## MODIFIED Requirements

### Requirement: Shared yield (coroutines)

Coroutines SHALL yield the shared `ProxyYield`: `WantsWrite(Vec<u8>)` for bytes to send, and `WantsRead(usize)` for an exact number of bytes to read and hand back on the next resume. The caller SHALL pass `None` initially and after every `WantsWrite`, and after a `WantsRead(n)` either `Some(data)` carrying exactly the requested `n` bytes or `Some(&[])` when the stream ended before them.

### Requirement: Response handling (http-connect)

`HttpConnect` SHALL read the response head one byte at a time up to the `\r\n\r\n` terminator, so no tunnel payload past the head is consumed. It SHALL treat any 2xx status as an open tunnel, fail with a refused error carrying the status code otherwise, fail on a status line it cannot parse, fail with an end-of-stream error when the stream ends inside the head, and bound the head against a proxy that never terminates it.

### Requirement: Credential redaction (http-connect)

`HttpCredentials` SHALL hold the password in a `SecretString` and redact it from its `Debug` output. `HttpConnect` SHALL NOT keep the rendered request: it renders it when it yields it, so its `Debug` output carries the target authority and the redacted credentials only.

### Requirement: Target addressing (socks5)

The `CONNECT` request SHALL carry a `Socks5Address`: an IPv4 or IPv6 literal, or a domain name of 1 to 255 bytes that the proxy resolves (socks5h semantics). `Socks5Address::new` SHALL classify a host string, parsing IP literals and otherwise treating it as a domain, and SHALL be the only way to build the domain form: the name is held in a `Socks5Domain` whose content cannot be set from outside the crate.

### Requirement: Reply handling (socks5)

`Socks5Connect` SHALL parse the reply head, surface a non-zero reply code as a `Socks5Reply` (or an unknown-reply error outside the RFC 1928 range), and consume the bound address (IPv4, IPv6, or length-prefixed domain) so the socket is left exactly at the tunnel start. It SHALL report the tunnel open only once it was handed the whole bound address.

### Requirement: Exact-read pump (client)

The pump SHALL drive a coroutine to completion, writing every `WantsWrite` in full and satisfying every `WantsRead(n)` with an exact read of `n` bytes, so on return the stream holds no buffered tunnel bytes. A stream that ends before those `n` bytes SHALL surface as the I/O error of the exact read.

### Requirement: Entry points (client)

`connect_socks5` SHALL run a SOCKS5 handshake to a `Socks5Address` with optional `Socks5Credentials`; `connect_http` SHALL run an HTTP `CONNECT` handshake to a host and port with optional `HttpCredentials`, failing before any write when the host is invalid. Both SHALL surface failures through `ProxyClientError`, wrapping the protocol handshake error and any stream I/O error.

### Requirement: Feature layering (packaging)

The crate SHALL expose `socks5` and `http` protocol features and a `client` feature gating the std-blocking pump, following the golden rule that a feature is justified only when it changes the crate set. The default SHALL enable `socks5`, `http` and `client`. The `http` feature SHALL pull in base64-codec for Basic proxy authorization. The crate SHALL depend on secrecy, without its default features, for the proxy passwords of both protocols.
