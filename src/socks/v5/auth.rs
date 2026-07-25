//! SOCKS5 username/password sub-negotiation ([RFC 1929]).
//!
//! [RFC 1929]: https://www.rfc-editor.org/rfc/rfc1929

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

use thiserror::Error;

use crate::socks::v5::AUTH_VERSION;

/// Failure building [`Socks5Credentials`].
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum Socks5CredentialsError {
    /// The username exceeds the 255-byte field limit.
    #[error("SOCKS5 username too long: {0} bytes (max 255)")]
    UsernameTooLong(usize),
    /// The password exceeds the 255-byte field limit.
    #[error("SOCKS5 password too long: {0} bytes (max 255)")]
    PasswordTooLong(usize),
}

/// RFC 1929 username/password credentials.
///
/// The password is redacted from the [`Debug`] output.
#[derive(Clone)]
pub struct Socks5Credentials {
    username: String,
    password: String,
}

impl Socks5Credentials {
    /// Builds credentials, validating both fields against the 255-byte
    /// limit RFC 1929 imposes on each.
    pub fn new(
        username: &str,
        password: &str,
    ) -> Result<Socks5Credentials, Socks5CredentialsError> {
        if username.len() > 255 {
            return Err(Socks5CredentialsError::UsernameTooLong(username.len()));
        }
        if password.len() > 255 {
            return Err(Socks5CredentialsError::PasswordTooLong(password.len()));
        }
        Ok(Socks5Credentials {
            username: username.to_string(),
            password: password.to_string(),
        })
    }

    /// Encodes the sub-negotiation request:
    /// `VER(0x01) | ULEN | UNAME | PLEN | PASSWD`.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let user = self.username.as_bytes();
        let pass = self.password.as_bytes();

        let mut out = Vec::with_capacity(3 + user.len() + pass.len());
        out.push(AUTH_VERSION);
        out.push(user.len() as u8);
        out.extend_from_slice(user);
        out.push(pass.len() as u8);
        out.extend_from_slice(pass);
        out
    }
}

impl fmt::Debug for Socks5Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socks5Credentials")
            .field("username", &self.username)
            .field("password", &"***")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_matches_rfc1929() {
        let creds = Socks5Credentials::new("user", "pass").unwrap();
        // VER=1, ULEN=4, "user", PLEN=4, "pass"
        assert_eq!(
            creds.encode(),
            [
                0x01, 0x04, b'u', b's', b'e', b'r', 0x04, b'p', b'a', b's', b's'
            ]
        );
    }

    #[test]
    fn rejects_overlong_fields() {
        let long = "x".repeat(256);
        assert!(matches!(
            Socks5Credentials::new(&long, "p"),
            Err(Socks5CredentialsError::UsernameTooLong(256))
        ));
        assert!(matches!(
            Socks5Credentials::new("u", &long),
            Err(Socks5CredentialsError::PasswordTooLong(256))
        ));
    }

    #[test]
    fn debug_redacts_password() {
        let creds = Socks5Credentials::new("alice", "secret").unwrap();
        let rendered = format!("{creds:?}");
        assert!(rendered.contains("alice"));
        assert!(!rendered.contains("secret"));
    }
}
