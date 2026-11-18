use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::{Zeroize, Zeroizing};

use super::CryptoError;

/// Length of a generated salt in bytes.
pub const SALT_BYTES: usize = 32;

/// Length of vault encryption keys in bytes.
pub const KEY_BYTES: usize = 32;

/// Initial production Argon2id memory cost in KiB (128 MiB).
pub const PRODUCTION_MEMORY_KIB: u32 = 128 * 1024;

/// Initial production Argon2id iteration count.
pub const PRODUCTION_ITERATIONS: u32 = 3;

/// Initial production Argon2id lane count.
pub const PRODUCTION_LANES: u32 = 4;

const MIN_MEMORY_KIB: u32 = 64 * 1024;
const MAX_MEMORY_KIB: u32 = 256 * 1024;
const MAX_ITERATIONS: u32 = 10;
const MAX_LANES: u32 = 4;
const MAX_PASSWORD_BYTES: usize = 1024;

/// Bounded Argon2id parameters stored with a future vault header.
///
/// Bounds are checked before allocating Argon2 working memory. This prevents a
/// malformed vault header from requesting unbounded memory or computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
}

impl KdfParams {
    /// Initial production profile: 128 MiB, three passes, four lanes.
    pub const PRODUCTION: Self = Self {
        memory_kib: PRODUCTION_MEMORY_KIB,
        iterations: PRODUCTION_ITERATIONS,
        lanes: PRODUCTION_LANES,
    };

    /// Construct parameters after enforcing application safety bounds.
    pub fn new(memory_kib: u32, iterations: u32, lanes: u32) -> Result<Self, CryptoError> {
        if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&memory_kib)
            || !(1..=MAX_ITERATIONS).contains(&iterations)
            || !(1..=MAX_LANES).contains(&lanes)
            || memory_kib < lanes.saturating_mul(8)
        {
            return Err(CryptoError::InvalidKdfParameters);
        }

        Ok(Self {
            memory_kib,
            iterations,
            lanes,
        })
    }

    /// Return the configured memory cost in KiB.
    #[must_use]
    pub const fn memory_kib(self) -> u32 {
        self.memory_kib
    }

    /// Return the configured iteration count.
    #[must_use]
    pub const fn iterations(self) -> u32 {
        self.iterations
    }

    /// Return the configured lane count.
    #[must_use]
    pub const fn lanes(self) -> u32 {
        self.lanes
    }
}

/// A 256-bit secret key that is cleared when dropped.
///
/// Debug output never reveals key bytes. The type is not Clone to discourage
/// accidental duplication of key material.
pub struct SecretKey([u8; KEY_BYTES]);

impl SecretKey {
    /// Construct a key from exactly 32 bytes.
    ///
    /// The caller must ensure that the bytes came from a cryptographically
    /// secure random source or an authenticated decryption operation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self(bytes)
    }

    /// Generate a fresh key using the operating-system CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = Zeroizing::new([0_u8; KEY_BYTES]);
        getrandom::fill(&mut *bytes).map_err(|_| CryptoError::RandomnessUnavailable)?;
        Ok(Self::from_bytes(*bytes))
    }

    pub(crate) fn expose(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}

/// Generate a new 256-bit salt using the operating-system CSPRNG.
pub fn generate_salt() -> Result<[u8; SALT_BYTES], CryptoError> {
    let mut salt = [0_u8; SALT_BYTES];
    getrandom::fill(&mut salt).map_err(|_| CryptoError::RandomnessUnavailable)?;
    Ok(salt)
}

/// Derive a 256-bit wrapping key from a password and a vault salt.
///
/// The returned key is intended to wrap a randomly generated data-encryption
/// key; it should not directly encrypt the entire vault. The salt must be
/// random and unique for each vault password setup.
pub fn derive_wrapping_key(
    password: &[u8],
    salt: &[u8; SALT_BYTES],
    params: KdfParams,
) -> Result<SecretKey, CryptoError> {
    if password.is_empty() {
        return Err(CryptoError::EmptyPassword);
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(CryptoError::PasswordTooLong);
    }

    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.lanes,
        Some(KEY_BYTES),
    )
    .map_err(|_| CryptoError::InvalidKdfParameters)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut output = Zeroizing::new([0_u8; KEY_BYTES]);

    argon2
        .hash_password_into(password, salt, &mut output[..])
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    Ok(SecretKey::from_bytes(*output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_profile_matches_project_decision() {
        assert_eq!(KdfParams::PRODUCTION.memory_kib(), 131_072);
        assert_eq!(KdfParams::PRODUCTION.iterations(), 3);
        assert_eq!(KdfParams::PRODUCTION.lanes(), 4);
    }

    #[test]
    fn kdf_rejects_out_of_bounds_parameters() {
        assert!(KdfParams::new(32 * 1024, 3, 4).is_err());
        assert!(KdfParams::new(512 * 1024, 3, 4).is_err());
        assert!(KdfParams::new(128 * 1024, 0, 4).is_err());
        assert!(KdfParams::new(128 * 1024, 3, 8).is_err());
    }

    #[test]
    fn derives_a_256_bit_key() {
        // A smaller test profile keeps routine tests lighter. Production vaults
        // use KdfParams::PRODUCTION.
        let params = KdfParams::new(64 * 1024, 1, 1).expect("valid test parameters");
        let salt = [0x5A; SALT_BYTES];
        let key = derive_wrapping_key(b"test-only password", &salt, params)
            .expect("key derivation should succeed");

        assert_ne!(key.expose(), &[0_u8; KEY_BYTES]);
    }

    #[test]
    fn rejects_an_empty_password() {
        assert_eq!(
            derive_wrapping_key(b"", &[0_u8; SALT_BYTES], KdfParams::PRODUCTION).err(),
            Some(CryptoError::EmptyPassword)
        );
    }

    #[test]
    fn generated_salts_are_not_constant() {
        let first = generate_salt().expect("system RNG should be available");
        let second = generate_salt().expect("system RNG should be available");
        assert_ne!(first, second);
    }
}
