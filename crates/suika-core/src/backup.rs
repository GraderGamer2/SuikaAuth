//! Portable password-encrypted backup files.
//!
//! Backups contain the versioned account database, including OTP secrets,
//! HOTP counters, favorites, and group metadata. The backup password is
//! independent from the vault master password. Backup files use the same
//! DEK/KEK hierarchy as vaults, but a distinct magic, version namespace, and
//! domain-separated associated data.

use crate::accounts::AccountDatabase;
use crate::crypto::{
    CryptoError, EncryptedPayload, KdfParams, NONCE_BYTES, SALT_BYTES, SecretKey, TAG_BYTES,
    decrypt, derive_wrapping_key, encrypt, generate_salt,
};
use zeroize::Zeroizing;

/// Eight-byte magic identifier for portable backup files.
pub const BACKUP_MAGIC: &[u8; 8] = b"SUIKABAK";
/// Current portable backup format version.
pub const BACKUP_FORMAT_VERSION: u16 = 1;
/// Maximum plaintext account database accepted in a backup (16 MiB).
pub const MAX_BACKUP_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;
/// Fixed header length, excluding the encrypted account database.
pub const BACKUP_HEADER_BYTES: usize = 158;
/// Maximum total serialized backup length, including its authentication tag.
pub const MAX_BACKUP_FILE_BYTES: usize =
    BACKUP_HEADER_BYTES + MAX_BACKUP_PLAINTEXT_BYTES + TAG_BYTES;
/// Minimum serialized length for an empty account database.
pub const MIN_BACKUP_FILE_BYTES: usize = BACKUP_HEADER_BYTES + TAG_BYTES;

const KDF_ARGON2ID: u8 = 1;
const AEAD_XCHACHA20_POLY1305: u8 = 1;
const PREFIX_BYTES: usize = 58;
const WRAPPED_DEK_CIPHERTEXT_BYTES: usize = 32 + TAG_BYTES;
const WRAP_AAD_DOMAIN: &[u8] = b"SuikaAuthenticator/backup/v1/dek-wrap\0";
const PAYLOAD_AAD_DOMAIN: &[u8] = b"SuikaAuthenticator/backup/v1/payload\0";

/// Errors returned while creating or restoring a portable backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupError {
    /// The backup is truncated, malformed, or contains unexpected trailing bytes.
    InvalidContainer,
    /// The file uses a backup version this build does not understand.
    UnsupportedVersion,
    /// The file declares unsupported cryptographic algorithms.
    UnsupportedAlgorithm,
    /// The file contains out-of-range Argon2id parameters.
    InvalidKdfParameters,
    /// The encrypted account database exceeds the supported size.
    PayloadTooLarge,
    /// The backup password was incorrect or authenticated content was modified.
    UnlockFailed,
    /// The decrypted payload is not a valid SuikaAuthenticator account database.
    InvalidAccountDatabase,
    /// A lower-level cryptographic operation failed.
    Crypto(CryptoError),
}

impl core::fmt::Display for BackupError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidContainer => f.write_str("backup file is malformed or truncated"),
            Self::UnsupportedVersion => f.write_str("backup format version is not supported"),
            Self::UnsupportedAlgorithm => {
                f.write_str("backup cryptographic algorithm is not supported")
            }
            Self::InvalidKdfParameters => {
                f.write_str("backup key-derivation parameters are invalid")
            }
            Self::PayloadTooLarge => f.write_str("backup exceeds the supported size"),
            Self::UnlockFailed => {
                f.write_str("backup password is incorrect or backup data is corrupted")
            }
            Self::InvalidAccountDatabase => {
                f.write_str("backup does not contain a valid SuikaAuthenticator account database")
            }
            Self::Crypto(error) => write!(f, "backup cryptographic operation failed: {error}"),
        }
    }
}

impl std::error::Error for BackupError {}

impl From<CryptoError> for BackupError {
    fn from(error: CryptoError) -> Self {
        match error {
            CryptoError::AuthenticationFailed => Self::UnlockFailed,
            CryptoError::InvalidCiphertext => Self::InvalidContainer,
            other => Self::Crypto(other),
        }
    }
}

/// Create and restore the portable encrypted backup format.
pub struct Backup;

impl Backup {
    /// Encrypt a validated account database with a separate backup password.
    ///
    /// The backup is portable across Linux and Android and does not depend on
    /// the source vault's password, DEK, KEK, device, or filesystem location.
    /// Production application code must pass `KdfParams::PRODUCTION`.
    pub fn create(
        plaintext: &[u8],
        password: &[u8],
        params: KdfParams,
    ) -> Result<Vec<u8>, BackupError> {
        validate_plaintext(plaintext)?;

        let data_key = SecretKey::generate()?;
        let salt = generate_salt()?;
        let wrapping_key = derive_wrapping_key(password, &salt, params)?;
        let prefix = build_prefix(params, &salt);
        let wrapped_key_aad = build_wrap_aad(&prefix);
        let wrapped_key = encrypt(&wrapping_key, data_key.expose(), &wrapped_key_aad)?;

        let encrypted_payload_len = plaintext
            .len()
            .checked_add(TAG_BYTES)
            .ok_or(BackupError::PayloadTooLarge)?;
        let payload_len =
            u32::try_from(encrypted_payload_len).map_err(|_| BackupError::PayloadTooLarge)?;
        let payload_aad = build_payload_aad(&prefix, &wrapped_key, payload_len);
        let payload = encrypt(&data_key, plaintext, &payload_aad)?;

        serialize_container(&prefix, wrapped_key, payload, payload_len)
    }

    /// Check the public structure and bounds without deriving a key.
    ///
    /// This does not authenticate the backup. Call `restore` with the
    /// backup password to verify its contents.
    pub fn validate_serialized(serialized: &[u8]) -> Result<(), BackupError> {
        LockedBackup::parse(serialized).map(|_| ())
    }

    /// Decrypt and fully validate a backup, returning a zeroizing database.
    ///
    /// Wrong passwords and AEAD authentication failures intentionally produce
    /// the same `UnlockFailed` error. The decoded account database is checked
    /// before any plaintext bytes are returned.
    pub fn restore(serialized: &[u8], password: &[u8]) -> Result<Zeroizing<Vec<u8>>, BackupError> {
        let locked = LockedBackup::parse(serialized)?;
        let wrapping_key = derive_wrapping_key(password, &locked.salt, locked.params)?;
        let wrapped_key_aad = build_wrap_aad(&locked.prefix);
        let decrypted_key = decrypt(&wrapping_key, &locked.wrapped_key, &wrapped_key_aad)
            .map_err(|_| BackupError::UnlockFailed)?;
        if decrypted_key.len() != 32 {
            return Err(BackupError::UnlockFailed);
        }

        let mut data_key_bytes = Zeroizing::new([0_u8; 32]);
        data_key_bytes.copy_from_slice(&decrypted_key);
        let data_key = SecretKey::from_bytes(*data_key_bytes);
        let payload_aad =
            build_payload_aad(&locked.prefix, &locked.wrapped_key, locked.payload_len);
        let plaintext = decrypt(&data_key, &locked.payload, &payload_aad)
            .map_err(|_| BackupError::UnlockFailed)?;
        validate_plaintext(&plaintext)?;
        Ok(plaintext)
    }
}

fn validate_plaintext(plaintext: &[u8]) -> Result<(), BackupError> {
    if plaintext.len() > MAX_BACKUP_PLAINTEXT_BYTES {
        return Err(BackupError::PayloadTooLarge);
    }
    let accounts =
        AccountDatabase::decode(plaintext).map_err(|_| BackupError::InvalidAccountDatabase)?;
    drop(accounts);
    Ok(())
}

fn build_prefix(params: KdfParams, salt: &[u8; SALT_BYTES]) -> [u8; PREFIX_BYTES] {
    let mut prefix = [0_u8; PREFIX_BYTES];
    prefix[..8].copy_from_slice(BACKUP_MAGIC);
    prefix[8..10].copy_from_slice(&BACKUP_FORMAT_VERSION.to_be_bytes());
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
) -> Result<Vec<u8>, BackupError> {
    let (wrap_nonce, wrapped_key_ciphertext) = wrapped_key.into_parts();
    let (payload_nonce, payload_ciphertext) = payload.into_parts();
    let expected_payload_len =
        usize::try_from(payload_len).map_err(|_| BackupError::InvalidContainer)?;
    if wrapped_key_ciphertext.len() != WRAPPED_DEK_CIPHERTEXT_BYTES
        || payload_ciphertext.len() != expected_payload_len
    {
        return Err(BackupError::InvalidContainer);
    }

    let total_len = BACKUP_HEADER_BYTES
        .checked_add(payload_ciphertext.len())
        .ok_or(BackupError::PayloadTooLarge)?;
    if total_len > MAX_BACKUP_FILE_BYTES {
        return Err(BackupError::PayloadTooLarge);
    }

    let mut serialized = Vec::with_capacity(total_len);
    serialized.extend_from_slice(prefix);
    serialized.extend_from_slice(&wrap_nonce);
    serialized.extend_from_slice(&wrapped_key_ciphertext);
    serialized.extend_from_slice(&payload_nonce);
    serialized.extend_from_slice(&payload_len.to_be_bytes());
    serialized.extend_from_slice(&payload_ciphertext);
    Ok(serialized)
}

struct LockedBackup {
    prefix: [u8; PREFIX_BYTES],
    salt: [u8; SALT_BYTES],
    params: KdfParams,
    wrapped_key: EncryptedPayload,
    payload: EncryptedPayload,
    payload_len: u32,
}

impl LockedBackup {
    fn parse(serialized: &[u8]) -> Result<Self, BackupError> {
        if serialized.len() < MIN_BACKUP_FILE_BYTES {
            return Err(BackupError::InvalidContainer);
        }
        if serialized.len() > MAX_BACKUP_FILE_BYTES {
            return Err(BackupError::PayloadTooLarge);
        }

        let prefix: [u8; PREFIX_BYTES] = serialized[..PREFIX_BYTES]
            .try_into()
            .map_err(|_| BackupError::InvalidContainer)?;
        if &prefix[..8] != BACKUP_MAGIC {
            return Err(BackupError::InvalidContainer);
        }
        let version = u16::from_be_bytes([prefix[8], prefix[9]]);
        if version != BACKUP_FORMAT_VERSION {
            return Err(BackupError::UnsupportedVersion);
        }
        if prefix[10] != KDF_ARGON2ID || prefix[11] != AEAD_XCHACHA20_POLY1305 {
            return Err(BackupError::UnsupportedAlgorithm);
        }
        if prefix[12] != 0 || prefix[13] != 0 {
            return Err(BackupError::InvalidContainer);
        }

        let memory_kib = u32::from_be_bytes([prefix[14], prefix[15], prefix[16], prefix[17]]);
        let iterations = u32::from_be_bytes([prefix[18], prefix[19], prefix[20], prefix[21]]);
        let lanes = u32::from_be_bytes([prefix[22], prefix[23], prefix[24], prefix[25]]);
        let params = KdfParams::new(memory_kib, iterations, lanes)
            .map_err(|_| BackupError::InvalidKdfParameters)?;
        let salt: [u8; SALT_BYTES] = prefix[26..58]
            .try_into()
            .map_err(|_| BackupError::InvalidContainer)?;

        let mut offset = PREFIX_BYTES;
        let wrap_nonce = take::<NONCE_BYTES>(serialized, &mut offset)?;
        let wrapped_key_ciphertext = take::<WRAPPED_DEK_CIPHERTEXT_BYTES>(serialized, &mut offset)?;
        let wrapped_key = EncryptedPayload::from_parts(wrap_nonce, wrapped_key_ciphertext.to_vec())
            .map_err(BackupError::from)?;
        let payload_nonce = take::<NONCE_BYTES>(serialized, &mut offset)?;
        let length_bytes = take::<4>(serialized, &mut offset)?;
        let payload_len = u32::from_be_bytes(length_bytes);
        let payload_len_usize =
            usize::try_from(payload_len).map_err(|_| BackupError::InvalidContainer)?;
        if !(TAG_BYTES..=(MAX_BACKUP_PLAINTEXT_BYTES + TAG_BYTES)).contains(&payload_len_usize) {
            return Err(BackupError::InvalidContainer);
        }

        let expected_total = offset
            .checked_add(payload_len_usize)
            .ok_or(BackupError::InvalidContainer)?;
        if expected_total != serialized.len() {
            return Err(BackupError::InvalidContainer);
        }
        let payload = EncryptedPayload::from_parts(
            payload_nonce,
            serialized[offset..expected_total].to_vec(),
        )
        .map_err(BackupError::from)?;

        Ok(Self {
            prefix,
            salt,
            params,
            wrapped_key,
            payload,
            payload_len,
        })
    }
}

fn take<const N: usize>(serialized: &[u8], offset: &mut usize) -> Result<[u8; N], BackupError> {
    let end = (*offset)
        .checked_add(N)
        .ok_or(BackupError::InvalidContainer)?;
    let slice = serialized
        .get(*offset..end)
        .ok_or(BackupError::InvalidContainer)?;
    let result = slice
        .try_into()
        .map_err(|_| BackupError::InvalidContainer)?;
    *offset = end;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{Account, AccountMode};
    use crate::otp::OtpAlgorithm;

    const TEST_PASSWORD: &[u8] = b"separate backup password";

    fn test_params() -> KdfParams {
        KdfParams::new(64 * 1024, 1, 1).expect("test KDF profile should be valid")
    }

    fn sample_database() -> Zeroizing<Vec<u8>> {
        let secret = Zeroizing::new(vec![0x11; 20]);
        let mut account = Account::new_totp(
            "Example",
            "alice@example.com",
            secret,
            OtpAlgorithm::Sha256,
            8,
            60,
        )
        .expect("test TOTP account should be valid");
        account
            .set_group(Some("Personal".to_owned()))
            .expect("group is valid");
        account.set_favorite(true);

        let hotp = Account::new_hotp(
            "Backup",
            "hardware key",
            Zeroizing::new(vec![0x22; 20]),
            OtpAlgorithm::Sha512,
            7,
            987,
        )
        .expect("test HOTP account should be valid");

        let mut database = AccountDatabase::new();
        database
            .insert(account)
            .expect("TOTP insert should succeed");
        database.insert(hotp).expect("HOTP insert should succeed");
        database
            .encode()
            .expect("test account database should encode")
    }

    #[test]
    fn round_trips_the_complete_account_database() {
        let database = sample_database();
        let backup = Backup::create(&database, TEST_PASSWORD, test_params())
            .expect("backup creation should succeed");
        let restored =
            Backup::restore(&backup, TEST_PASSWORD).expect("backup restoration should succeed");
        let accounts =
            AccountDatabase::decode(&restored).expect("restored account database should decode");

        assert_eq!(accounts.len(), 2);
        let totp = &accounts.accounts()[0];
        assert_eq!(totp.issuer(), "Example");
        assert_eq!(totp.label(), "alice@example.com");
        assert_eq!(totp.algorithm(), OtpAlgorithm::Sha256);
        assert_eq!(totp.digits(), 8);
        assert_eq!(totp.mode(), AccountMode::Totp { period_seconds: 60 });
        assert_eq!(totp.group(), Some("Personal"));
        assert!(totp.is_favorite());

        let hotp = &accounts.accounts()[1];
        assert_eq!(hotp.mode(), AccountMode::Hotp { counter: 987 });
        assert_eq!(hotp.algorithm(), OtpAlgorithm::Sha512);
        assert_eq!(hotp.digits(), 7);
    }

    #[test]
    fn backup_password_is_independent_of_vault_password() {
        let database = sample_database();
        let backup = Backup::create(&database, TEST_PASSWORD, test_params())
            .expect("backup creation should succeed");
        assert!(Backup::restore(&backup, b"vault master password").is_err());
        assert!(Backup::restore(&backup, TEST_PASSWORD).is_ok());
    }

    #[test]
    fn rejects_wrong_password_and_authenticated_modification() {
        let database = sample_database();
        let backup = Backup::create(&database, TEST_PASSWORD, test_params())
            .expect("backup creation should succeed");
        assert_eq!(
            Backup::restore(&backup, b"wrong backup password").err(),
            Some(BackupError::UnlockFailed)
        );

        let mut modified = backup.clone();
        let last = modified.len() - 1;
        modified[last] ^= 0x40;
        assert_eq!(
            Backup::restore(&modified, TEST_PASSWORD).err(),
            Some(BackupError::UnlockFailed)
        );
    }

    #[test]
    fn rejects_plaintext_secrets_instead_of_accepting_arbitrary_bytes() {
        assert_eq!(
            Backup::create(b"plaintext OTP secret", TEST_PASSWORD, test_params()).err(),
            Some(BackupError::InvalidAccountDatabase)
        );
    }

    #[test]
    fn rejects_malformed_headers_and_trailing_bytes_before_kdf() {
        let database = sample_database();
        let backup = Backup::create(&database, TEST_PASSWORD, test_params())
            .expect("backup creation should succeed");

        assert_eq!(
            Backup::validate_serialized(&backup[..BACKUP_HEADER_BYTES - 1]).err(),
            Some(BackupError::InvalidContainer)
        );
        let mut trailing = backup.clone();
        trailing.push(0);
        assert_eq!(
            Backup::validate_serialized(&trailing).err(),
            Some(BackupError::InvalidContainer)
        );

        let mut invalid_kdf = backup.clone();
        invalid_kdf[14..18].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            Backup::validate_serialized(&invalid_kdf).err(),
            Some(BackupError::InvalidKdfParameters)
        );
    }

    #[test]
    fn rejects_oversized_backup_inputs_before_key_derivation() {
        let oversized = vec![0_u8; MAX_BACKUP_FILE_BYTES + 1];
        assert_eq!(
            Backup::validate_serialized(&oversized).err(),
            Some(BackupError::PayloadTooLarge)
        );
    }

    #[test]
    fn restores_the_shared_cross_platform_v1_fixture() {
        let fixture = include_bytes!("../tests/fixtures/portable_backup_v1.suikabak");
        let plaintext = Backup::restore(fixture, b"portable-backup-fixture-password")
            .expect("shared portable backup fixture should restore");
        let accounts = AccountDatabase::decode(&plaintext)
            .expect("shared fixture account database should decode");

        assert_eq!(accounts.len(), 2);
        let totp = &accounts.accounts()[0];
        assert_eq!(totp.issuer(), "CrossPlatform");
        assert_eq!(totp.label(), "fixture-totp");
        assert_eq!(totp.algorithm(), OtpAlgorithm::Sha256);
        assert_eq!(totp.digits(), 8);
        assert_eq!(totp.mode(), AccountMode::Totp { period_seconds: 60 });
        assert_eq!(totp.group(), Some("Portable"));
        assert!(totp.is_favorite());

        let hotp = &accounts.accounts()[1];
        assert_eq!(hotp.issuer(), "CrossPlatform");
        assert_eq!(hotp.label(), "fixture-hotp");
        assert_eq!(hotp.algorithm(), OtpAlgorithm::Sha512);
        assert_eq!(hotp.digits(), 7);
        assert_eq!(hotp.mode(), AccountMode::Hotp { counter: 9 });
    }

    #[test]
    fn encrypted_backup_does_not_contain_the_plaintext_database() {
        let database = sample_database();
        let backup = Backup::create(&database, TEST_PASSWORD, test_params())
            .expect("backup creation should succeed");
        assert!(
            !backup
                .windows(database.len())
                .any(|part| part == &database[..])
        );
    }
}
