use core::fmt;

/// Errors returned by SuikaAuthenticator cryptographic operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// A password must not be empty.
    EmptyPassword,
    /// A password exceeds the application input limit.
    PasswordTooLong,
    /// KDF parameters fall outside the application's accepted bounds.
    InvalidKdfParameters,
    /// The operating system could not provide cryptographically secure random bytes.
    RandomnessUnavailable,
    /// Argon2id failed to derive key material.
    KeyDerivationFailed,
    /// The encrypted payload is too short to contain an authentication tag.
    InvalidCiphertext,
    /// Encryption could not be completed.
    EncryptionFailed,
    /// Decryption failed because authentication did not succeed.
    AuthenticationFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyPassword => "password must not be empty",
            Self::PasswordTooLong => "password exceeds the application input limit",
            Self::InvalidKdfParameters => "invalid or unsupported Argon2id parameters",
            Self::RandomnessUnavailable => "operating-system randomness is unavailable",
            Self::KeyDerivationFailed => "Argon2id key derivation failed",
            Self::InvalidCiphertext => "encrypted payload is malformed",
            Self::EncryptionFailed => "authenticated encryption failed",
            Self::AuthenticationFailed => "encrypted payload authentication failed",
        };

        f.write_str(message)
    }
}

impl std::error::Error for CryptoError {}
