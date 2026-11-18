//! Versioned, portable encrypted vault container.
//!
//! Filesystem operations remain in platform frontends. This module owns only
//! the binary format and its cryptographic transitions.

use zeroize::Zeroizing;

use crate::crypto::{
    CryptoError, EncryptedPayload, KdfParams, NONCE_BYTES, SALT_BYTES, SecretKey, TAG_BYTES,
    decrypt, derive_wrapping_key, encrypt, generate_salt,
};

/// Eight-byte vault magic identifier.
pub const VAULT_MAGIC: &[u8; 8] = b"SUIKAVLT";
/// Current on-disk vault format version.
pub const VAULT_FORMAT_VERSION: u16 = 1;
/// Maximum plaintext account database size (16 MiB).
pub const MAX_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum serialized vault file size, including the fixed header and AEAD tag.
pub const MAX_VAULT_FILE_BYTES: usize = 158 + MAX_PLAINTEXT_BYTES + TAG_BYTES;
/// Minimum serialized vault file size for an empty encrypted payload.
pub const MIN_VAULT_FILE_BYTES: usize = 158 + TAG_BYTES;

const KDF_ARGON2ID: u8 = 1;
const AEAD_XCHACHA20_POLY1305: u8 = 1;
const PREFIX_BYTES: usize = 58;
const WRAPPED_DEK_CIPHERTEXT_BYTES: usize = 32 + TAG_BYTES;
const HEADER_BYTES: usize =
    PREFIX_BYTES + NONCE_BYTES + WRAPPED_DEK_CIPHERTEXT_BYTES + NONCE_BYTES + 4;
const WRAP_AAD_DOMAIN: &[u8] = b"SuikaAuthenticator/vault/v1/dek-wrap\0";
const PAYLOAD_AAD_DOMAIN: &[u8] = b"SuikaAuthenticator/vault/v1/payload\0";

/// Errors returned while creating, parsing, or unlocking a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    /// The input is truncated, malformed, or contains unexpected trailing bytes.
    InvalidContainer,
    /// The file uses a vault version that this build does not understand.
    UnsupportedVersion,
    /// The file contains unsupported algorithm identifiers.
    UnsupportedAlgorithm,
    /// The stored Argon2id parameters are outside the application's accepted range.
    InvalidKdfParameters,
    /// The encrypted account database exceeds the supported size.
    PayloadTooLarge,
    /// The password was incorrect or authenticated vault data was modified.
    UnlockFailed,
    /// A lower-level cryptographic operation failed.
    Crypto(CryptoError),
}

impl core::fmt::Display for VaultError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidContainer => f.write_str("vault container is malformed or truncated"),
            Self::UnsupportedVersion => f.write_str("vault format version is not supported"),
            Self::UnsupportedAlgorithm => {
                f.write_str("vault cryptographic algorithm is not supported")
            }
            Self::InvalidKdfParameters => {
                f.write_str("vault key-derivation parameters are invalid")
            }
            Self::PayloadTooLarge => f.write_str("vault payload exceeds the supported size"),
            Self::UnlockFailed => f.write_str(
                "vault could not be unlocked; password may be incorrect or data corrupted",
            ),
            Self::Crypto(error) => write!(f, "vault cryptographic operation failed: {error}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<CryptoError> for VaultError {
    fn from(error: CryptoError) -> Self {
        match error {
            CryptoError::AuthenticationFailed => Self::UnlockFailed,
            other => Self::Crypto(other),
        }
    }
}

/// Operations on the portable encrypted vault byte format.
pub struct Vault;

impl Vault {
    /// Create a new vault containing the supplied plaintext account database.
    ///
    /// Production application code must use KdfParams::PRODUCTION. The caller
    /// owns filesystem persistence and must use atomic file replacement.
    pub fn create(
        plaintext: &[u8],
        password: &[u8],
        params: KdfParams,
    ) -> Result<Vec<u8>, VaultError> {
        validate_payload_size(plaintext.len())?;
        let data_key = SecretKey::generate()?;
        let session = VaultSession {
            data_key,
            plaintext: Zeroizing::new(plaintext.to_vec()),
        };
        session.seal(password, params)
    }

    /// Validate the public container structure without decrypting it.
    ///
    /// This checks the magic, version, algorithm identifiers, bounded KDF
    /// parameters, ciphertext lengths, and exact file length. It does not
    /// authenticate encrypted data; that requires the master password.
    pub fn validate_serialized(serialized: &[u8]) -> Result<(), VaultError> {
        LockedVault::parse(serialized).map(|_| ())
    }

    /// Parse and unlock a vault using its master password.
    ///
    /// Wrong passwords and authenticated-data failures intentionally return
    /// the same UnlockFailed error.
    pub fn unlock(serialized: &[u8], password: &[u8]) -> Result<VaultSession, VaultError> {
        let locked = LockedVault::parse(serialized)?;
        let wrapping_key =
            derive_wrapping_key(password, &locked.salt, locked.params).map_err(VaultError::from)?;

        let wrapped_key_aad = build_wrap_aad(&locked.prefix);
        let decrypted_key = decrypt(&wrapping_key, &locked.wrapped_key, &wrapped_key_aad)
            .map_err(|_| VaultError::UnlockFailed)?;

        if decrypted_key.len() != 32 {
            return Err(VaultError::UnlockFailed);
        }

        let mut data_key_bytes = Zeroizing::new([0_u8; 32]);
        data_key_bytes.copy_from_slice(&decrypted_key);
        let data_key = SecretKey::from_bytes(*data_key_bytes);

        let payload_aad = build_payload_aad(
            &locked.prefix,
            &locked.wrapped_key,
            u32::try_from(locked.payload.ciphertext().len())
                .map_err(|_| VaultError::InvalidContainer)?,
        );
        let plaintext = decrypt(&data_key, &locked.payload, &payload_aad)
            .map_err(|_| VaultError::UnlockFailed)?;

        Ok(VaultSession {
            data_key,
            plaintext,
        })
    }
}

/// An unlocked vault session.
///
/// The data-encryption key and plaintext payload are zeroized on drop where
/// supported. This type intentionally does not implement Clone or Debug.
pub struct VaultSession {
    data_key: SecretKey,
    plaintext: Zeroizing<Vec<u8>>,
}

impl VaultSession {
    /// Borrow the decrypted account database.
    #[must_use]
    pub fn plaintext(&self) -> &[u8] {
        self.plaintext.as_slice()
    }

    /// Replace the decrypted account database with a zeroizing buffer.
    pub fn replace_plaintext(&mut self, plaintext: Zeroizing<Vec<u8>>) -> Result<(), VaultError> {
        validate_payload_size(plaintext.len())?;
        self.plaintext = plaintext;
        Ok(())
    }

    /// Encrypt the current session into a new vault file.
    ///
    /// A fresh salt and fresh AEAD nonces are generated. Calling this with a
    /// new password changes the master password and rewraps the same random
    /// data-encryption key. The payload is also re-encrypted with fresh nonce
    /// material and authenticated header data.
    pub fn seal(&self, password: &[u8], params: KdfParams) -> Result<Vec<u8>, VaultError> {
        validate_payload_size(self.plaintext.len())?;

        let salt = generate_salt()?;
        let prefix = build_prefix(params, &salt);
        let wrapping_key = derive_wrapping_key(password, &salt, params)?;

        let wrapped_key_aad = build_wrap_aad(&prefix);
        let wrapped_key = encrypt(&wrapping_key, self.data_key.expose(), &wrapped_key_aad)?;

        let encrypted_payload_len = self
            .plaintext
            .len()
            .checked_add(TAG_BYTES)
            .ok_or(VaultError::PayloadTooLarge)?;
        let payload_len =
            u32::try_from(encrypted_payload_len).map_err(|_| VaultError::PayloadTooLarge)?;
        let payload_aad = build_payload_aad(&prefix, &wrapped_key, payload_len);
        let encrypted_payload = encrypt(&self.data_key, self.plaintext(), &payload_aad)?;

        serialize_container(&prefix, wrapped_key, encrypted_payload, payload_len)
    }
}

struct LockedVault {
    prefix: [u8; PREFIX_BYTES],
    salt: [u8; SALT_BYTES],
    params: KdfParams,
    wrapped_key: EncryptedPayload,
    payload: EncryptedPayload,
}

impl LockedVault {
    fn parse(serialized: &[u8]) -> Result<Self, VaultError> {
        if serialized.len() < HEADER_BYTES + TAG_BYTES
            || serialized.len() > HEADER_BYTES + MAX_PLAINTEXT_BYTES + TAG_BYTES
        {
            return Err(VaultError::InvalidContainer);
        }

        let prefix: [u8; PREFIX_BYTES] = serialized[..PREFIX_BYTES]
            .try_into()
            .map_err(|_| VaultError::InvalidContainer)?;

        if &prefix[0..8] != VAULT_MAGIC {
            return Err(VaultError::InvalidContainer);
        }

        let version = u16::from_be_bytes([prefix[8], prefix[9]]);
        if version != VAULT_FORMAT_VERSION {
            return Err(VaultError::UnsupportedVersion);
        }

        if prefix[10] != KDF_ARGON2ID || prefix[11] != AEAD_XCHACHA20_POLY1305 {
            return Err(VaultError::UnsupportedAlgorithm);
        }

        if prefix[12] != 0 || prefix[13] != 0 {
            return Err(VaultError::InvalidContainer);
        }

        let memory_kib = u32::from_be_bytes([prefix[14], prefix[15], prefix[16], prefix[17]]);
        let iterations = u32::from_be_bytes([prefix[18], prefix[19], prefix[20], prefix[21]]);
        let lanes = u32::from_be_bytes([prefix[22], prefix[23], prefix[24], prefix[25]]);
        let params = KdfParams::new(memory_kib, iterations, lanes)
            .map_err(|_| VaultError::InvalidKdfParameters)?;
        let salt: [u8; SALT_BYTES] = prefix[26..58]
            .try_into()
            .map_err(|_| VaultError::InvalidContainer)?;

        let mut offset = PREFIX_BYTES;
        let wrap_nonce = take::<NONCE_BYTES>(serialized, &mut offset)?;
        let wrapped_key_ciphertext = take::<WRAPPED_DEK_CIPHERTEXT_BYTES>(serialized, &mut offset)?;
        let wrapped_key = EncryptedPayload::from_parts(wrap_nonce, wrapped_key_ciphertext.to_vec())
            .map_err(VaultError::from)?;

        let payload_nonce = take::<NONCE_BYTES>(serialized, &mut offset)?;
        let payload_len_bytes = take::<4>(serialized, &mut offset)?;
        let payload_len = u32::from_be_bytes(payload_len_bytes) as usize;

        if !(TAG_BYTES..=(MAX_PLAINTEXT_BYTES + TAG_BYTES)).contains(&payload_len) {
            return Err(VaultError::InvalidContainer);
        }

        let expected_total = offset
            .checked_add(payload_len)
            .ok_or(VaultError::InvalidContainer)?;
        if expected_total != serialized.len() {
            return Err(VaultError::InvalidContainer);
        }

        let payload = EncryptedPayload::from_parts(
            payload_nonce,
            serialized[offset..expected_total].to_vec(),
        )
        .map_err(VaultError::from)?;

        Ok(Self {
            prefix,
            salt,
            params,
            wrapped_key,
            payload,
        })
    }
}

fn take<const N: usize>(serialized: &[u8], offset: &mut usize) -> Result<[u8; N], VaultError> {
    let end = (*offset)
        .checked_add(N)
        .ok_or(VaultError::InvalidContainer)?;
    let slice = serialized
        .get(*offset..end)
        .ok_or(VaultError::InvalidContainer)?;
    let result = slice.try_into().map_err(|_| VaultError::InvalidContainer)?;
    *offset = end;
    Ok(result)
}

fn validate_payload_size(length: usize) -> Result<(), VaultError> {
    if length > MAX_PLAINTEXT_BYTES {
        return Err(VaultError::PayloadTooLarge);
    }
    Ok(())
}

fn build_prefix(params: KdfParams, salt: &[u8; SALT_BYTES]) -> [u8; PREFIX_BYTES] {
    let mut prefix = [0_u8; PREFIX_BYTES];
    prefix[0..8].copy_from_slice(VAULT_MAGIC);
    prefix[8..10].copy_from_slice(&VAULT_FORMAT_VERSION.to_be_bytes());
    prefix[10] = KDF_ARGON2ID;
    prefix[11] = AEAD_XCHACHA20_POLY1305;
    prefix[12..14].copy_from_slice(&0_u16.to_be_bytes());
    prefix[14..18].copy_from_slice(&params.memory_kib().to_be_bytes());
    prefix[18..22].copy_from_slice(&params.iterations().to_be_bytes());
    prefix[22..26].copy_from_slice(&params.lanes().to_be_bytes());
    prefix[26..58].copy_from_slice(salt);
    prefix
}

fn build_wrap_aad(prefix: &[u8; PREFIX_BYTES]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(WRAP_AAD_DOMAIN.len() + PREFIX_BYTES);
    aad.extend_from_slice(WRAP_AAD_DOMAIN);
    aad.extend_from_slice(prefix);
    aad
}

fn build_payload_aad(
    prefix: &[u8; PREFIX_BYTES],
    wrapped_key: &EncryptedPayload,
    payload_len: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        PAYLOAD_AAD_DOMAIN.len() + PREFIX_BYTES + NONCE_BYTES + wrapped_key.ciphertext().len() + 4,
    );
    aad.extend_from_slice(PAYLOAD_AAD_DOMAIN);
    aad.extend_from_slice(prefix);
    aad.extend_from_slice(wrapped_key.nonce());
    aad.extend_from_slice(wrapped_key.ciphertext());
    aad.extend_from_slice(&payload_len.to_be_bytes());
    aad
}

fn serialize_container(
    prefix: &[u8; PREFIX_BYTES],
    wrapped_key: EncryptedPayload,
    payload: EncryptedPayload,
    payload_len: u32,
) -> Result<Vec<u8>, VaultError> {
    let (wrap_nonce, wrapped_key_ciphertext) = wrapped_key.into_parts();
    let (payload_nonce, payload_ciphertext) = payload.into_parts();

    if wrapped_key_ciphertext.len() != WRAPPED_DEK_CIPHERTEXT_BYTES
        || payload_ciphertext.len() != payload_len as usize
    {
        return Err(VaultError::InvalidContainer);
    }

    let total_len = HEADER_BYTES
        .checked_add(payload_ciphertext.len())
        .ok_or(VaultError::PayloadTooLarge)?;
    let mut serialized = Vec::with_capacity(total_len);
    serialized.extend_from_slice(prefix);
    serialized.extend_from_slice(&wrap_nonce);
    serialized.extend_from_slice(&wrapped_key_ciphertext);
    serialized.extend_from_slice(&payload_nonce);
    serialized.extend_from_slice(&payload_len.to_be_bytes());
    serialized.extend_from_slice(&payload_ciphertext);

    Ok(serialized)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> KdfParams {
        KdfParams::new(64 * 1024, 1, 1).expect("valid test KDF profile")
    }

    #[test]
    fn creates_and_unlocks_a_portable_vault() {
        let plaintext = br#"{"accounts":[],"version":1}"#;
        let password = b"correct horse battery staple";

        let serialized = Vault::create(plaintext, password, test_params())
            .expect("vault creation should succeed");
        let session = Vault::unlock(&serialized, password).expect("vault unlock should succeed");

        assert_eq!(session.plaintext(), plaintext);
        assert_eq!(&serialized[..8], VAULT_MAGIC);
    }

    #[test]
    fn wrong_password_returns_generic_unlock_failure() {
        let serialized = Vault::create(b"secret account data", b"right password", test_params())
            .expect("vault creation should succeed");

        assert_eq!(
            Vault::unlock(&serialized, b"wrong password").err(),
            Some(VaultError::UnlockFailed)
        );
    }

    #[test]
    fn rejects_modified_payload_ciphertext() {
        let mut serialized = Vault::create(b"secret account data", b"password", test_params())
            .expect("vault creation should succeed");
        let last = serialized.len() - 1;
        serialized[last] ^= 0x80;

        assert_eq!(
            Vault::unlock(&serialized, b"password").err(),
            Some(VaultError::UnlockFailed)
        );
    }

    #[test]
    fn rejects_truncated_and_trailing_data() {
        let serialized = Vault::create(b"payload", b"password", test_params())
            .expect("vault creation should succeed");

        assert_eq!(
            Vault::unlock(&serialized[..serialized.len() - 1], b"password").err(),
            Some(VaultError::InvalidContainer)
        );

        let mut trailing = serialized;
        trailing.push(0);
        assert_eq!(
            Vault::unlock(&trailing, b"password").err(),
            Some(VaultError::InvalidContainer)
        );
    }

    #[test]
    fn rejects_unbounded_kdf_parameters_before_derivation() {
        let mut serialized = Vault::create(b"payload", b"password", test_params())
            .expect("vault creation should succeed");

        // Argon2 memory cost starts at byte offset 14 in the fixed prefix.
        serialized[14..18].copy_from_slice(&(512 * 1024_u32).to_be_bytes());

        assert_eq!(
            Vault::unlock(&serialized, b"password").err(),
            Some(VaultError::InvalidKdfParameters)
        );
    }

    #[test]
    fn password_can_be_changed_without_exporting_plaintext() {
        let original = Vault::create(b"account records", b"old password", test_params())
            .expect("vault creation should succeed");
        let session =
            Vault::unlock(&original, b"old password").expect("original unlock should succeed");

        let rewrapped = session
            .seal(b"new password", test_params())
            .expect("password change should succeed");

        assert_eq!(
            Vault::unlock(&rewrapped, b"old password").err(),
            Some(VaultError::UnlockFailed)
        );
        let reopened =
            Vault::unlock(&rewrapped, b"new password").expect("new password should unlock");
        assert_eq!(reopened.plaintext(), b"account records");
    }

    #[test]
    fn rejects_oversized_payloads_before_encryption() {
        let oversized = vec![0_u8; MAX_PLAINTEXT_BYTES + 1];
        assert_eq!(
            Vault::create(&oversized, b"password", test_params()).err(),
            Some(VaultError::PayloadTooLarge)
        );
    }
}
