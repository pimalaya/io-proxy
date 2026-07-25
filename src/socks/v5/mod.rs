//! SOCKS version 5 ([RFC 1928]) with username/password authentication
//! ([RFC 1929]).
//!
//! [`connect`] is the client `CONNECT` handshake coroutine; [`address`],
//! [`auth`] and [`message`] hold the wire types it exchanges.
//!
//! [RFC 1928]: https://www.rfc-editor.org/rfc/rfc1928
//! [RFC 1929]: https://www.rfc-editor.org/rfc/rfc1929

pub mod address;
pub mod auth;
pub mod connect;
pub mod message;

/// Protocol version byte (`0x05`) prefixing the greeting, request and
/// reply.
pub(crate) const VERSION: u8 = 0x05;
/// Version byte (`0x01`) of the RFC 1929 auth sub-negotiation — distinct
/// from [`VERSION`], and the classic source of interop bugs.
pub(crate) const AUTH_VERSION: u8 = 0x01;
/// Reserved byte, must be `0x00`.
pub(crate) const RSV: u8 = 0x00;

/// `CONNECT` command.
pub(crate) const CMD_CONNECT: u8 = 0x01;

/// No-authentication method.
pub(crate) const METHOD_NO_AUTH: u8 = 0x00;
/// Username/password authentication method (RFC 1929).
pub(crate) const METHOD_USER_PASS: u8 = 0x02;
/// Sentinel the server returns when it accepts none of the offered
/// methods.
pub(crate) const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

/// IPv4 address type.
pub(crate) const ATYP_IPV4: u8 = 0x01;
/// Domain-name address type.
pub(crate) const ATYP_DOMAIN: u8 = 0x03;
/// IPv6 address type.
pub(crate) const ATYP_IPV6: u8 = 0x04;
