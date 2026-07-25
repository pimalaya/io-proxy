---
cairn: spec
capability: coroutines
status: current
---

# Coroutines

Every proxy handshake is exposed as an I/O-free coroutine: a resumable state machine that emits read and write requests instead of performing I/O itself. The caller owns the socket and pumps the coroutine with the bytes it read, whatever the runtime (blocking, async, in-memory tests). The contract is shared by every protocol and lives in the crate-root `coroutine` module.

### Requirement: Coroutine contract
Each coroutine SHALL implement `ProxyCoroutine`, declaring a `Yield` associated type for intermediate progress and a `Return` for terminal output, with a single `resume(&mut self, arg: Option<&[u8]>)` method returning `ProxyCoroutineState<Yield, Return>` (`Yielded` or `Complete`). `Return` SHALL be `Result<(), Error>` where `Error` is the protocol-specific handshake error.

### Requirement: Shared yield
Coroutines SHALL yield the shared `ProxyYield`: `WantsWrite(Vec<u8>)` for bytes to send, and `WantsRead(usize)` for an exact number of bytes to read and hand back on the next resume. The caller SHALL pass `None` initially and after every `WantsWrite`, and `Some(data)` carrying exactly the requested `n` bytes after a `WantsRead(n)`.

### Requirement: No over-read
A coroutine SHALL request only the bytes its framing needs, never an open-ended read. Length-framed protocols request whole messages by their exact length; delimiter-framed protocols request one byte at a time while scanning for their terminator. On completion the socket SHALL be positioned exactly on the target's first byte, with no tunnel payload consumed.

### Requirement: Resume after completion
Resuming a coroutine after it has returned `Complete` is a programming error and SHALL panic.
