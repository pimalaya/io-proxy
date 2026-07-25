#![no_std]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

//! # io-proxy
//!
//! I/O-free proxy client coroutines. A proxy handshake is a resumable
//! state machine that emits read and write requests instead of
//! performing I/O itself: the caller owns the socket and pumps the
//! coroutine with the bytes it read, whatever the runtime (blocking,
//! async, in-memory tests). The `client` feature ships a ready-made
//! std-blocking pump for callers who just want a tunnelled socket.
//!
//! ## Scope
//!
//! Client-side tunnelling only — enough to carry an arbitrary TCP
//! connection (IMAP, SMTP, HTTP, ...) through a proxy:
//!
//! - [`socks`] — SOCKS5 `CONNECT` ([RFC 1928] + [RFC 1929]), behind the
//!   `socks5` feature. The proxy resolves the target hostname (socks5h
//!   semantics).
//! - [`http`] — HTTP `CONNECT` tunnelling ([RFC 9110 §9.3.6]), behind the
//!   `http` feature. `CONNECT` exists only to establish a proxy tunnel,
//!   so it lives here rather than in a general HTTP crate.
//!
//! `BIND`, `UDP ASSOCIATE`, plaintext HTTP forward proxying and the
//! server side of either protocol are out of scope.
//!
//! ## Layout
//!
//! One module per protocol, each behind a cargo feature, versioned from
//! within (`socks::v5`) so a future SOCKS4 or protocol revision slots in
//! alongside. [`coroutine`] spans them and holds the shared contract; the
//! optional [`client`] module (`client` feature) is the std-blocking pump.
//!
//! ## The coroutine contract
//!
//! Every coroutine implements [`coroutine::ProxyCoroutine`]: a resume
//! method taking the bytes read since the last step and returning either
//! an intermediate yield or a terminal completion. The read yield carries
//! an exact byte count ([`coroutine::ProxyYield::WantsRead`]): SOCKS5
//! reads its length-framed messages directly, and HTTP CONNECT scans for
//! the header terminator one byte at a time — so neither ever consumes
//! tunnel payload past the handshake, leaving the socket positioned
//! exactly at the start of the tunnel.
//!
//! ## Conventions
//!
//! The conventions every Pimalaya repository shares are described in the
//! org
//! [ARCHITECTURE](https://github.com/pimalaya/.github/blob/master/ARCHITECTURE.md)
//! and
//! [GUIDELINES](https://github.com/pimalaya/.github/blob/master/GUIDELINES.md);
//! this crate's own deviations and its build matrix live in
//! CONTRIBUTING.md, and its living spec and history in the cairn/ folder.
//! Logging follows the library rules: debug marks the lifecycle points,
//! trace carries the data; credentials never reach the logs.
//!
//! A runnable example driving the SOCKS5 pump lives in examples/.
//!
//! [RFC 1928]: https://www.rfc-editor.org/rfc/rfc1928
//! [RFC 1929]: https://www.rfc-editor.org/rfc/rfc1929
//! [RFC 9110 §9.3.6]: https://www.rfc-editor.org/rfc/rfc9110#section-9.3.6

#[cfg(any(feature = "socks5", feature = "http"))]
#[macro_use]
extern crate alloc;
#[cfg(all(feature = "client", any(feature = "socks5", feature = "http")))]
extern crate std;

#[cfg(all(feature = "client", any(feature = "socks5", feature = "http")))]
pub mod client;
#[cfg(any(feature = "socks5", feature = "http"))]
pub mod coroutine;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "socks5")]
pub mod socks;
