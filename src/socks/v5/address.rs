//! SOCKS5 target address ([RFC 1928 §4]): the `ATYP`/`DST.ADDR`/`DST.PORT`
//! fields of the `CONNECT` request.
//!
//! [RFC 1928 §4]: https://www.rfc-editor.org/rfc/rfc1928#section-4

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::net::IpAddr;

use thiserror::Error;

use crate::socks::v5::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6};

/// Failure building an [`Socks5Address`].
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum Socks5AddressError {
    /// The domain name exceeds the 255-byte field limit.
    #[error("SOCKS5 domain name too long: {0} bytes (max 255)")]
    DomainTooLong(usize),
}

/// A SOCKS5 target address.
///
/// A hostname is kept as a [`Domain`](Socks5Address::Domain) so the *proxy*
/// resolves it (socks5h semantics); a literal IP is sent as
/// [`Ipv4`](Socks5Address::Ipv4) / [`Ipv6`](Socks5Address::Ipv6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Socks5Address {
    /// IPv4 address and port.
    Ipv4(core::net::Ipv4Addr, u16),
    /// IPv6 address and port.
    Ipv6(core::net::Ipv6Addr, u16),
    /// Domain name (≤ 255 bytes) and port, resolved by the proxy.
    Domain(String, u16),
}

impl Socks5Address {
    /// Builds an address from a host string and port.
    ///
    /// A host that parses as an IP literal becomes [`Ipv4`]/[`Ipv6`];
    /// anything else becomes a [`Domain`] (validated against the 255-byte
    /// limit) for the proxy to resolve.
    ///
    /// [`Ipv4`]: Socks5Address::Ipv4
    /// [`Ipv6`]: Socks5Address::Ipv6
    /// [`Domain`]: Socks5Address::Domain
    pub fn new(host: &str, port: u16) -> Result<Socks5Address, Socks5AddressError> {
        match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => Ok(Socks5Address::Ipv4(ip, port)),
            Ok(IpAddr::V6(ip)) => Ok(Socks5Address::Ipv6(ip, port)),
            Err(_) => {
                if host.len() > 255 {
                    return Err(Socks5AddressError::DomainTooLong(host.len()));
                }
                Ok(Socks5Address::Domain(host.to_string(), port))
            }
        }
    }

    /// Appends the `ATYP`/`DST.ADDR`/`DST.PORT` encoding to `out`.
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Socks5Address::Ipv4(ip, port) => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&port.to_be_bytes());
            }
            Socks5Address::Ipv6(ip, port) => {
                out.push(ATYP_IPV6);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&port.to_be_bytes());
            }
            Socks5Address::Domain(name, port) => {
                out.push(ATYP_DOMAIN);
                out.push(name.len() as u8);
                out.extend_from_slice(name.as_bytes());
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    fn encode(addr: &Socks5Address) -> Vec<u8> {
        let mut out = Vec::new();
        addr.encode_into(&mut out);
        out
    }

    #[test]
    fn new_classifies_host() {
        assert!(matches!(
            Socks5Address::new("1.2.3.4", 993),
            Ok(Socks5Address::Ipv4(_, 993))
        ));
        assert!(matches!(
            Socks5Address::new("::1", 25),
            Ok(Socks5Address::Ipv6(_, 25))
        ));
        assert!(matches!(
            Socks5Address::new("imap.example.com", 993),
            Ok(Socks5Address::Domain(_, 993))
        ));
    }

    #[test]
    fn new_rejects_overlong_domain() {
        let host = "a".repeat(256);
        assert_eq!(
            Socks5Address::new(&host, 1),
            Err(Socks5AddressError::DomainTooLong(256))
        );
    }

    #[test]
    fn encode_ipv4() {
        // ATYP=1, 1.2.3.4, port 993 = 0x03E1
        assert_eq!(
            encode(&Socks5Address::Ipv4([1, 2, 3, 4].into(), 993)),
            [0x01, 1, 2, 3, 4, 0x03, 0xE1]
        );
    }

    #[test]
    fn encode_domain() {
        // ATYP=3, len=3, "abc", port 80 = 0x0050
        assert_eq!(
            encode(&Socks5Address::Domain("abc".into(), 80)),
            [0x03, 0x03, b'a', b'b', b'c', 0x00, 0x50]
        );
    }

    #[test]
    fn encode_ipv6() {
        let addr = Socks5Address::Ipv6(core::net::Ipv6Addr::LOCALHOST, 443);
        let mut expected = vec![0x04u8];
        expected.extend_from_slice(&core::net::Ipv6Addr::LOCALHOST.octets());
        expected.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(encode(&addr), expected);
    }
}
