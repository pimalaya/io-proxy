//! SOCKS5 reply codes ([RFC 1928 §6]).
//!
//! [RFC 1928 §6]: https://www.rfc-editor.org/rfc/rfc1928#section-6

use core::fmt;

/// Reply code carried in the `REP` field of a SOCKS5 reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Socks5Reply {
    /// `0x00` succeeded.
    Succeeded,
    /// `0x01` general SOCKS server failure.
    GeneralFailure,
    /// `0x02` connection not allowed by ruleset.
    ConnectionNotAllowed,
    /// `0x03` network unreachable.
    NetworkUnreachable,
    /// `0x04` host unreachable.
    HostUnreachable,
    /// `0x05` connection refused.
    ConnectionRefused,
    /// `0x06` TTL expired.
    TtlExpired,
    /// `0x07` command not supported.
    CommandNotSupported,
    /// `0x08` address type not supported.
    AddressTypeNotSupported,
}

impl Socks5Reply {
    /// Maps a raw `REP` byte to its [`Socks5Reply`], or [`None`] for a
    /// code outside the RFC 1928 range.
    pub fn from_u8(byte: u8) -> Option<Socks5Reply> {
        let reply = match byte {
            0x00 => Socks5Reply::Succeeded,
            0x01 => Socks5Reply::GeneralFailure,
            0x02 => Socks5Reply::ConnectionNotAllowed,
            0x03 => Socks5Reply::NetworkUnreachable,
            0x04 => Socks5Reply::HostUnreachable,
            0x05 => Socks5Reply::ConnectionRefused,
            0x06 => Socks5Reply::TtlExpired,
            0x07 => Socks5Reply::CommandNotSupported,
            0x08 => Socks5Reply::AddressTypeNotSupported,
            _ => return None,
        };
        Some(reply)
    }
}

impl fmt::Display for Socks5Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Socks5Reply::Succeeded => "succeeded",
            Socks5Reply::GeneralFailure => "general SOCKS server failure",
            Socks5Reply::ConnectionNotAllowed => "connection not allowed by ruleset",
            Socks5Reply::NetworkUnreachable => "network unreachable",
            Socks5Reply::HostUnreachable => "host unreachable",
            Socks5Reply::ConnectionRefused => "connection refused",
            Socks5Reply::TtlExpired => "TTL expired",
            Socks5Reply::CommandNotSupported => "command not supported",
            Socks5Reply::AddressTypeNotSupported => "address type not supported",
        };
        f.write_str(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_u8_covers_rfc_range() {
        assert_eq!(Socks5Reply::from_u8(0x00), Some(Socks5Reply::Succeeded));
        assert_eq!(
            Socks5Reply::from_u8(0x08),
            Some(Socks5Reply::AddressTypeNotSupported)
        );
        assert_eq!(Socks5Reply::from_u8(0x09), None);
        assert_eq!(Socks5Reply::from_u8(0xFF), None);
    }
}
