//! SOCKS proxy protocol, versioned from within.
//!
//! Only [`v5`] ([RFC 1928] + [RFC 1929]) is implemented today; a future
//! SOCKS4/4a would slot in as its own module alongside.
//!
//! [RFC 1928]: https://www.rfc-editor.org/rfc/rfc1928
//! [RFC 1929]: https://www.rfc-editor.org/rfc/rfc1929

pub mod v5;
