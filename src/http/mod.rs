//! HTTP proxy tunnelling.
//!
//! [`connect`] is the client `CONNECT` handshake coroutine ([RFC 9110
//! §9.3.6]). `CONNECT` exists only to open a proxy tunnel, so it lives in
//! this proxy crate rather than in a general HTTP crate.
//!
//! [RFC 9110 §9.3.6]: https://www.rfc-editor.org/rfc/rfc9110#section-9.3.6

pub mod connect;
