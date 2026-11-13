---
cairn: spec
capability: http-connect
status: current
---

# HTTP CONNECT

Client-side HTTP `CONNECT` tunnelling (RFC 9110 §9.3.6), behind the `http` feature. `CONNECT` exists only to establish a proxy tunnel, so it lives in this proxy crate rather than in a general HTTP crate. Plaintext HTTP forward proxying (absolute-URI request lines) and non-Basic proxy authentication (Digest, NTLM, Negotiate) are out of scope.

### Requirement: CONNECT request
`HttpConnect` SHALL send an authority-form `CONNECT host:port HTTP/1.1` request carrying a matching `Host` header. When `HttpCredentials` are provided it SHALL add a `Proxy-Authorization: Basic` header (RFC 7617) built from them.

### Requirement: Target host validation
`HttpConnect::new` SHALL accept as host only a non-empty registered name of RFC 3986 section 3.2.2 (unreserved characters, percent-encoded octets and sub-delimiters, which covers IPv4 literals) or an IPv6 literal, bare or bracketed, and SHALL fail with `HttpConnectError::InvalidHost` otherwise. It SHALL write an IPv6 literal between brackets, adding them when missing.

#### Scenario: A bare IPv6 literal
- **WHEN** the host is `2001:db8::1` and the port 443
- **THEN** the request line is `CONNECT [2001:db8::1]:443 HTTP/1.1`, the same as for the host `[2001:db8::1]`

#### Scenario: A host holding a line break
- **WHEN** the host holds a CR, a LF, a space, a `/`, an `@`, a `:` outside an IPv6 literal, a byte outside ASCII, or is empty
- **THEN** `HttpConnect::new` fails with `HttpConnectError::InvalidHost` and nothing is written

### Requirement: Response handling
`HttpConnect` SHALL read the response head one byte at a time up to the `\r\n\r\n` terminator, so no tunnel payload past the head is consumed. It SHALL treat any 2xx status as an open tunnel, fail with a refused error carrying the status code otherwise, fail on a status line it cannot parse, fail with an end-of-stream error when the stream ends inside the head, and bound the head against a proxy that never terminates it.

### Requirement: Credential redaction
`HttpCredentials` SHALL hold the password in a `SecretString` and redact it from its `Debug` output. `HttpConnect` SHALL NOT keep the rendered request: it renders it when it yields it, so its `Debug` output carries the target authority and the redacted credentials only.
