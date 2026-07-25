//! Generator-shape coroutine driver mirroring `core::ops::Coroutine`:
//! a `Yield` associated type for intermediate progress, a `Return` for
//! terminal output, and a two-variant [`ProxyCoroutineState`]
//! (`Yielded` / `Complete`). Shared by every proxy protocol.

use alloc::vec::Vec;

/// State yielded by a [`ProxyCoroutine::resume`] step.
#[derive(Debug)]
pub enum ProxyCoroutineState<Y, R> {
    /// Intermediate step: the coroutine needs the caller to perform the
    /// carried I/O request before the next resume.
    Yielded(Y),
    /// Terminal step: the coroutine is done and carries its final output
    /// or error.
    Complete(R),
}

/// Standard-shape proxy coroutine: owns its internal state, declares a
/// per-step `Yield`, and returns `Result<Output, Error>` on completion.
pub trait ProxyCoroutine {
    /// The intermediate value emitted on every yielded step.
    type Yield;
    /// The terminal value emitted on completion.
    type Return;

    /// Advances one step.
    ///
    /// Pass [`None`] initially and after every [`ProxyYield::WantsWrite`];
    /// pass `Some(data)` after a [`ProxyYield::WantsRead(n)`] with exactly
    /// the `n` bytes that were read.
    ///
    /// [`ProxyYield::WantsRead(n)`]: ProxyYield::WantsRead
    fn resume(&mut self, arg: Option<&[u8]>) -> ProxyCoroutineState<Self::Yield, Self::Return>;
}

/// I/O request emitted by a yielded coroutine step.
///
/// [`WantsRead`] carries an exact byte count rather than an open-ended
/// "read some": the pump reads exactly that many bytes (e.g. via
/// `read_exact`) and never consumes tunnel payload that arrives right
/// after the handshake. Length-framed protocols (SOCKS5) request whole
/// messages; delimiter-framed ones (HTTP CONNECT) request one byte at a
/// time while scanning.
///
/// [`WantsRead`]: ProxyYield::WantsRead
#[derive(Debug)]
pub enum ProxyYield {
    /// The coroutine wants exactly this many bytes read from the stream
    /// and handed back on the next resume.
    WantsRead(usize),
    /// The coroutine wants these bytes written to the stream.
    WantsWrite(Vec<u8>),
}
