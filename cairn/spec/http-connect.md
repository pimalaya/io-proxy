---
cairn: spec
capability: http-connect
status: current
---

# HTTP CONNECT

Client-side HTTP `CONNECT` tunnelling (RFC 9110 §9.3.6), behind the `http` feature. `CONNECT` exists only to establish a proxy tunnel, so it lives in this proxy crate rather than in a general HTTP crate. Plaintext HTTP forward proxying (absolute-URI request lines) and non-Basic proxy authentication (Digest, NTLM, Negotiate) are out of scope.

### Requirement: CONNECT request
`HttpConnect` SHALL send an authority-form `CONNECT host:port HTTP/1.1` request carrying a matching `Host` header. When `HttpCredentials` are provided it SHALL add a `Proxy-Authorization: Basic` header (RFC 7617) built from them.

### Requirement: Response handling
`HttpConnect` SHALL read the response head one byte at a time up to the `\r\n\r\n` terminator, so no tunnel payload past the head is consumed. It SHALL treat any 2xx status as an open tunnel, fail with a refused error carrying the status code otherwise, fail on a status line it cannot parse, and bound the head against a proxy that never terminates it.

### Requirement: Credential redaction
`HttpCredentials` SHALL redact the password from its `Debug` output.
