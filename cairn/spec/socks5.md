---
cairn: spec
capability: socks5
status: current
---

# SOCKS5

Client-side SOCKS5 `CONNECT` tunnelling (RFC 1928) with username/password authentication (RFC 1929), behind the `socks5` feature. `BIND`, `UDP ASSOCIATE` and the server side are out of scope. The protocol is versioned from within the source tree (`socks::v5`) so a future SOCKS4/4a slots in alongside.

### Requirement: Method negotiation
`Socks5Connect` SHALL open the handshake by offering the no-authentication method, plus the username/password method when credentials are present. It SHALL fail if the proxy returns a version other than `0x05`, selects the no-acceptable-methods sentinel, or selects a method that was not offered.

### Requirement: Username/password authentication
When the proxy selects username/password, `Socks5Connect` SHALL run the RFC 1929 sub-negotiation with the caller's `Socks5Credentials` and fail on a rejected status or an auth version other than `0x01`. When the proxy requires authentication but no credentials were provided, it SHALL fail with an authentication-required error rather than proceeding.

### Requirement: Target addressing
The `CONNECT` request SHALL carry a `Socks5Address`: an IPv4 or IPv6 literal, or a domain name (bounded to 255 bytes) that the proxy resolves (socks5h semantics). `Socks5Address::new` SHALL classify a host string, parsing IP literals and otherwise treating it as a domain.

### Requirement: Reply handling
`Socks5Connect` SHALL parse the reply head, surface a non-zero reply code as a `Socks5Reply` (or an unknown-reply error outside the RFC 1928 range), and consume the bound address (IPv4, IPv6, or length-prefixed domain) so the socket is left exactly at the tunnel start.
