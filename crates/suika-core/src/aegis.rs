//! Offline import support for Aegis Authenticator JSON exports.
//!
//! The parser accepts plaintext and password-encrypted Aegis version-1 vault
//! files. Imported token secrets, passwords, KDF output, and decrypted database
//! buffers are kept in zeroizing allocations. Unsupported OTP families are
//! counted and skipped; malformed TOTP/HOTP entries reject the import.

use std::collections::HashMap;
use std::fmt;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer};
use zeroize::Zeroizing;

use crate::accounts::{Account, AccountError};
use crate::base32::decode_base32;
use crate::otp::OtpAlgorithm;

const MAX_EXPORT_BYTES: usize = 16 * 1024 * 1024;
const MAX_DATABASE_BYTES: usize = 8 * 1024 * 1024;
const MAX_ACCOUNTS: usize = 10_000;
const MAX_GROUPS: usize = 10_000;
const MAX_SLOTS: usize = 16;
const MAX_PASSWORD_SLOTS: usize = 4;
const MAX_PASSWORD_BYTES: usize = 4096;
const MAX_BASE64_BYTES: usize = ((MAX_DATABASE_BYTES + AES_TAG_BYTES + 2) / 3) * 4;
const MAX_SCRYPT_MEMORY_BYTES: u64 = 128 * 1024 * 1024;
const MAX_SCRYPT_WORK: u64 = 2 * 1024 * 1024;
const AES_KEY_BYTES: usize = 32;
const AES_NONCE_BYTES: usize = 12;
const AES_TAG_BYTES: usize = 16;

/// Errors returned while importing an Aegis export.
///
/// Messages deliberately avoid echoing JSON fields, secrets, ciphertext, or
/// password material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AegisImportError {
    InputTooLarge,
    InvalidFile,
    UnsupportedVersion,
    PasswordRequired,
    PasswordTooLong,
    NoPasswordSlot,
    WrongPassword,
    InvalidEncryptionParameters,
    InvalidSecret,
    InvalidAccount,
    TooManyAccounts,
}

impl fmt::Display for AegisImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge => f.write_str("The Aegis export or its encrypted database payload exceeds the supported size limit."),
            Self::InvalidFile => f.write_str("The selected file is not a supported Aegis export."),
            Self::UnsupportedVersion => f.write_str("This Aegis vault or database version is not supported."),
            Self::PasswordRequired => f.write_str("This Aegis export is encrypted. Enter its export password."),
            Self::PasswordTooLong => f.write_str("The Aegis export password exceeds the supported 4096-byte limit."),
            Self::NoPasswordSlot => f.write_str("The encrypted Aegis export has no supported password slot."),
            Self::WrongPassword => f.write_str("The Aegis export password is incorrect."),
            Self::InvalidEncryptionParameters => f.write_str("The Aegis export uses invalid or excessive encryption parameters."),
            Self::InvalidSecret => f.write_str("An Aegis TOTP/HOTP entry contains an invalid Base32 secret."),
            Self::InvalidAccount => f.write_str("An Aegis TOTP/HOTP entry contains unsupported or invalid account settings."),
            Self::TooManyAccounts => f.write_str("The Aegis export contains more than 10,000 accounts or groups."),
        }
    }
}

impl std::error::Error for AegisImportError {}

impl From<AccountError> for AegisImportError {
    fn from(_: AccountError) -> Self {
        Self::InvalidAccount
    }
}

/// The result of a successful import. Entries from Aegis-only OTP types are
/// skipped and counted rather than silently converted to a different algorithm.
pub struct AegisImportResult {
    pub accounts: Vec<Account>,
    pub skipped_unsupported: usize,
}

#[derive(Deserialize)]
struct AegisExport {
    version: u32,
    header: AegisHeader,
    db: AegisDb,
}

#[derive(Default, Deserialize)]
struct AegisHeader {
    slots: Option<Vec<AegisSlot>>,
    params: Option<AegisCipherParameters>,
}

#[derive(Deserialize)]
struct AegisSlot {
    #[serde(rename = "type")]
    kind: u8,
    key: String,
    key_params: AegisCipherParameters,
    n: Option<u32>,
    r: Option<u32>,
    p: Option<u32>,
    salt: Option<String>,
}

#[derive(Deserialize)]
struct AegisCipherParameters {
    nonce: String,
    tag: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AegisDb {
    Plain(AegisDatabase),
    Encrypted(String),
}

#[derive(Deserialize)]
struct AegisDatabase {
    version: u32,
    entries: Vec<AegisEntry>,
    #[serde(default)]
    groups: Vec<AegisGroup>,
}

#[derive(Deserialize)]
struct AegisGroup {
    uuid: String,
    name: String,
}

#[derive(Deserialize)]
struct AegisEntry {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    issuer: String,
    #[serde(default)]
    favorite: bool,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    group: Option<String>,
    info: AegisOtpInfo,
}

#[derive(Deserialize)]
struct AegisOtpInfo {
    secret: SensitiveString,
    #[serde(default)]
    algo: Option<String>,
    #[serde(default)]
    digits: Option<u8>,
    #[serde(default)]
    period: Option<u64>,
    #[serde(default)]
    counter: Option<u64>,
}

/// Owns the JSON string as soon as Serde has produced it and clears it on drop.
/// The input JSON buffer is also zeroizing, covering borrowed source bytes.
struct SensitiveString(Zeroizing<String>);

impl<'de> Deserialize<'de> for SensitiveString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SensitiveStringVisitor;

        impl<'de> Visitor<'de> for SensitiveStringVisitor {
            type Value = SensitiveString;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a Base32 string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(SensitiveString(Zeroizing::new(value.to_owned())))
            }

            fn visit_string<E>(self, mut value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(SensitiveString(Zeroizing::new(std::mem::take(&mut value))))
            }
        }

        deserializer.deserialize_string(SensitiveStringVisitor)
    }
}

/// Import an Aegis JSON export using its optional export password.
///
/// Aegis encrypts the database with AES-256-GCM and wraps the random database
/// key in one or more password slots. Each slot derives a wrapping key with
/// scrypt. Biometric slots are intentionally ignored; they are device-local.
pub fn import_aegis_export(
    input: &[u8],
    password: Option<&[u8]>,
) -> Result<AegisImportResult, AegisImportError> {
    if input.is_empty() {
        return Err(AegisImportError::InvalidFile);
    }
    if input.len() > MAX_EXPORT_BYTES {
        return Err(AegisImportError::InputTooLarge);
    }

    let input = Zeroizing::new(input.to_vec());
    let export: AegisExport =
        serde_json::from_slice(&input).map_err(|_| AegisImportError::InvalidFile)?;
    if export.version != 1 {
        return Err(AegisImportError::UnsupportedVersion);
    }

    let database = match export.db {
        AegisDb::Plain(database) => {
            if export.header.slots.is_some() || export.header.params.is_some() {
                return Err(AegisImportError::InvalidFile);
            }
            database
        }
        AegisDb::Encrypted(encoded_database) => {
            let password = password
                .filter(|value| !value.is_empty())
                .ok_or(AegisImportError::PasswordRequired)?;
            if password.len() > MAX_PASSWORD_BYTES {
                return Err(AegisImportError::PasswordTooLong);
            }
            if export.header.slots.is_none() || export.header.params.is_none() {
                return Err(AegisImportError::InvalidFile);
            }
            let database_bytes =
                decrypt_aegis_database(encoded_database.as_bytes(), &export.header, password)?;
            serde_json::from_slice::<AegisDatabase>(&database_bytes)
                .map_err(|_| AegisImportError::InvalidFile)?
        }
    };

    convert_aegis_database(database)
}

fn decrypt_aegis_database(
    encoded_database: &[u8],
    header: &AegisHeader,
    password: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AegisImportError> {
    if encoded_database.len() > MAX_BASE64_BYTES {
        return Err(AegisImportError::InputTooLarge);
    }
    let parameters = header
        .params
        .as_ref()
        .ok_or(AegisImportError::InvalidFile)?;
    validate_nonce_and_tag(parameters)?;
    let encrypted_database = Zeroizing::new(
        BASE64
            .decode(encoded_database)
            .map_err(|_| AegisImportError::InvalidFile)?,
    );
    if encrypted_database.len() < AES_TAG_BYTES
        || encrypted_database.len() > MAX_DATABASE_BYTES + AES_TAG_BYTES
    {
        return Err(AegisImportError::InvalidFile);
    }

    let slots = header.slots.as_deref().unwrap_or_default();
    if slots.len() > MAX_SLOTS {
        return Err(AegisImportError::InvalidEncryptionParameters);
    }
    let password_slots = slots
        .iter()
        .filter(|slot| slot.kind == 1)
        .collect::<Vec<_>>();
    if password_slots.is_empty() {
        return Err(AegisImportError::NoPasswordSlot);
    }
    if password_slots.len() > MAX_PASSWORD_SLOTS {
        return Err(AegisImportError::InvalidEncryptionParameters);
    }

    let mut master_key: Option<Zeroizing<Vec<u8>>> = None;
    for slot in password_slots {
        let n = slot
            .n
            .ok_or(AegisImportError::InvalidEncryptionParameters)?;
        let r = slot
            .r
            .ok_or(AegisImportError::InvalidEncryptionParameters)?;
        let p = slot
            .p
            .ok_or(AegisImportError::InvalidEncryptionParameters)?;
        let salt_text = slot
            .salt
            .as_deref()
            .ok_or(AegisImportError::InvalidEncryptionParameters)?;
        let salt = decode_hex(salt_text)?;
        let wrapped_key = decode_hex(&slot.key)?;
        validate_nonce_and_tag(&slot.key_params)?;

        if n < 2 || !n.is_power_of_two() || r == 0 || p == 0 {
            return Err(AegisImportError::InvalidEncryptionParameters);
        }
        let log_n = u8::try_from(n.trailing_zeros())
            .map_err(|_| AegisImportError::InvalidEncryptionParameters)?;
        let block_bytes = 128_u64
            .checked_mul(u64::from(r))
            .ok_or(AegisImportError::InvalidEncryptionParameters)?;
        let romix_bytes = block_bytes
            .checked_mul(u64::from(n))
            .ok_or(AegisImportError::InvalidEncryptionParameters)?;
        let parallel_bytes = block_bytes
            .checked_mul(u64::from(p))
            .ok_or(AegisImportError::InvalidEncryptionParameters)?;
        let memory = romix_bytes
            .checked_add(parallel_bytes)
            .and_then(|value| value.checked_add(block_bytes))
            .ok_or(AegisImportError::InvalidEncryptionParameters)?;
        let work = u64::from(n)
            .checked_mul(u64::from(r))
            .and_then(|value| value.checked_mul(u64::from(p)))
            .ok_or(AegisImportError::InvalidEncryptionParameters)?;
        if memory > MAX_SCRYPT_MEMORY_BYTES
            || work > MAX_SCRYPT_WORK
            || r > 8
            || p > 4
            || salt.len() != 32
            || wrapped_key.len() != AES_KEY_BYTES
        {
            return Err(AegisImportError::InvalidEncryptionParameters);
        }

        let params = scrypt::Params::new(log_n, r, p)
            .map_err(|_| AegisImportError::InvalidEncryptionParameters)?;
        let mut derived_key = Zeroizing::new([0_u8; AES_KEY_BYTES]);
        scrypt::scrypt(password, &salt, &params, &mut derived_key[..])
            .map_err(|_| AegisImportError::InvalidEncryptionParameters)?;

        if let Ok(key) = decrypt_aes_gcm(&derived_key[..], &wrapped_key, &slot.key_params) {
            if key.len() == AES_KEY_BYTES {
                master_key = Some(key);
                break;
            }
        }
    }

    let master_key = master_key.ok_or(AegisImportError::WrongPassword)?;
    decrypt_aes_gcm(&master_key, &encrypted_database, parameters)
        .map_err(|_| AegisImportError::InvalidFile)
}

fn decrypt_aes_gcm(
    key: &[u8],
    ciphertext_without_separate_tag: &[u8],
    parameters: &AegisCipherParameters,
) -> Result<Zeroizing<Vec<u8>>, AegisImportError> {
    validate_nonce_and_tag(parameters)?;
    let nonce = decode_hex(&parameters.nonce)?;
    let tag = decode_hex(&parameters.tag)?;

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| AegisImportError::InvalidEncryptionParameters)?;
    let nonce = Nonce::from_slice(&nonce);
    let mut authenticated_ciphertext = Zeroizing::new(ciphertext_without_separate_tag.to_vec());
    authenticated_ciphertext.extend_from_slice(&tag);

    cipher
        .decrypt(nonce, authenticated_ciphertext.as_slice())
        .map(Zeroizing::new)
        .map_err(|_| AegisImportError::WrongPassword)
}

fn validate_nonce_and_tag(parameters: &AegisCipherParameters) -> Result<(), AegisImportError> {
    let nonce = decode_hex(&parameters.nonce)?;
    let tag = decode_hex(&parameters.tag)?;
    if nonce.len() != AES_NONCE_BYTES || tag.len() != AES_TAG_BYTES {
        return Err(AegisImportError::InvalidEncryptionParameters);
    }
    Ok(())
}

fn decode_hex(value: &str) -> Result<Zeroizing<Vec<u8>>, AegisImportError> {
    if value.is_empty() || value.len() % 2 != 0 || value.len() > 256 {
        return Err(AegisImportError::InvalidEncryptionParameters);
    }
    let mut output = Zeroizing::new(Vec::with_capacity(value.len() / 2));
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0]).ok_or(AegisImportError::InvalidEncryptionParameters)?;
        let low = hex_nibble(pair[1]).ok_or(AegisImportError::InvalidEncryptionParameters)?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn convert_aegis_database(database: AegisDatabase) -> Result<AegisImportResult, AegisImportError> {
    if !(1..=3).contains(&database.version) {
        return Err(AegisImportError::UnsupportedVersion);
    }
    if database.entries.len() > MAX_ACCOUNTS || database.groups.len() > MAX_GROUPS {
        return Err(AegisImportError::TooManyAccounts);
    }

    let mut groups = HashMap::with_capacity(database.groups.len());
    for group in database.groups {
        if group.uuid.len() <= 64 && group.name.len() <= 128 {
            groups.insert(group.uuid, group.name);
        }
    }

    let mut accounts = Vec::with_capacity(database.entries.len());
    let mut skipped_unsupported = 0;
    for entry in database.entries {
        if !matches!(entry.kind.as_str(), "totp" | "hotp") {
            skipped_unsupported += 1;
            continue;
        }
        let algorithm = match entry.info.algo.as_deref() {
            Some("SHA1") => OtpAlgorithm::Sha1,
            Some("SHA256") => OtpAlgorithm::Sha256,
            Some("SHA512") => OtpAlgorithm::Sha512,
            _ => {
                skipped_unsupported += 1;
                continue;
            }
        };
        let digits = match entry.info.digits {
            Some(value @ 6..=8) => value,
            _ => {
                skipped_unsupported += 1;
                continue;
            }
        };

        let secret = decode_base32(entry.info.secret.0.as_str())
            .map_err(|_| AegisImportError::InvalidSecret)?;
        let mut account = match entry.kind.as_str() {
            "totp" => {
                let Some(period_seconds) = entry.info.period else {
                    return Err(AegisImportError::InvalidAccount);
                };
                Account::new_totp(
                    entry.issuer,
                    nonempty_label(entry.name),
                    secret,
                    algorithm,
                    digits,
                    period_seconds,
                )
                .map_err(|_| AegisImportError::InvalidAccount)?
            }
            "hotp" => {
                let Some(counter) = entry.info.counter else {
                    return Err(AegisImportError::InvalidAccount);
                };
                Account::new_hotp(
                    entry.issuer,
                    nonempty_label(entry.name),
                    secret,
                    algorithm,
                    digits,
                    counter,
                )
                .map_err(|_| AegisImportError::InvalidAccount)?
            }
            _ => {
                skipped_unsupported += 1;
                continue;
            }
        };

        account.set_favorite(entry.favorite);
        let group_name = entry
            .groups
            .iter()
            .find_map(|uuid| groups.get(uuid).cloned())
            .or_else(|| {
                entry.group.as_ref().map(|legacy_group| {
                    groups
                        .get(legacy_group)
                        .cloned()
                        .unwrap_or_else(|| legacy_group.clone())
                })
            });
        if let Some(group) = group_name {
            if group.len() <= 128 && !group.is_empty() {
                account
                    .set_group(Some(group))
                    .map_err(|_| AegisImportError::InvalidAccount)?;
            }
        }
        accounts.push(account);
    }

    Ok(AegisImportResult {
        accounts,
        skipped_unsupported,
    })
}

fn nonempty_label(value: String) -> String {
    if value.trim().is_empty() {
        "Imported account".to_owned()
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    const SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    const GROUP_ID: &str = "d7bf5f65-8f8b-45a0-8f9f-fc88793e9bc1";

    fn database_json() -> Zeroizing<Vec<u8>> {
        Zeroizing::new(
            format!(
                r#"{{"version":3,"entries":[
                    {{"type":"totp","name":"alice@example.com","issuer":"Example","favorite":true,"groups":["{GROUP_ID}"],"info":{{"secret":"{SECRET}","algo":"SHA256","digits":8,"period":60}}}},
                    {{"type":"hotp","name":"backup","issuer":"Example","group":"{GROUP_ID}","info":{{"secret":"{SECRET}","algo":"SHA512","digits":7,"counter":9}}}},
                    {{"type":"steam","name":"unsupported","issuer":"Example","info":{{"secret":"{SECRET}","algo":"SHA1","digits":5,"period":30}}}}
                ],"groups":[{{"uuid":"{GROUP_ID}","name":"Personal"}}]}}"#
            )
            .into_bytes(),
        )
    }

    fn encrypt_part(
        key: &[u8],
        nonce_bytes: [u8; AES_NONCE_BYTES],
        plaintext: &[u8],
    ) -> (String, String) {
        let cipher = Aes256Gcm::new_from_slice(key).expect("AES key size should be valid");
        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted = cipher
            .encrypt(nonce, plaintext)
            .expect("test AES-GCM encryption should succeed");
        let split = encrypted.len() - AES_TAG_BYTES;
        (
            hex_encode(&encrypted[..split]),
            hex_encode(&encrypted[split..]),
        )
    }

    fn hex_encode(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(DIGITS[usize::from(byte >> 4)] as char);
            output.push(DIGITS[usize::from(byte & 0x0f)] as char);
        }
        output
    }

    fn encrypted_export() -> Zeroizing<Vec<u8>> {
        let password = b"correct horse battery staple";
        let salt = [0x42_u8; 32];
        let mut derived_key = Zeroizing::new([0_u8; AES_KEY_BYTES]);
        let params = scrypt::Params::new(15, 8, 1).expect("Aegis scrypt params should be valid");
        scrypt::scrypt(password, &salt, &params, &mut derived_key[..])
            .expect("test scrypt should succeed");

        let master_key = Zeroizing::new([0x29_u8; AES_KEY_BYTES]);
        let (wrapped_key, wrapped_key_tag) =
            encrypt_part(&derived_key[..], [0x11; AES_NONCE_BYTES], &master_key[..]);
        let database = database_json();
        let database_cipher =
            Aes256Gcm::new_from_slice(&master_key[..]).expect("AES master key should be valid");
        let database_nonce = Nonce::from_slice(&[0x22_u8; AES_NONCE_BYTES]);
        let encrypted_database = database_cipher
            .encrypt(database_nonce, database.as_slice())
            .expect("test database encryption should succeed");
        let split = encrypted_database.len() - AES_TAG_BYTES;
        let database_ciphertext = BASE64.encode(&encrypted_database[..split]);
        let database_tag = hex_encode(&encrypted_database[split..]);
        let export = format!(
            r#"{{"version":1,"header":{{"slots":[{{"type":1,"key":"{wrapped_key}","key_params":{{"nonce":"{}","tag":"{wrapped_key_tag}"}},"n":32768,"r":8,"p":1,"salt":"{}","repaired":true}}],"params":{{"nonce":"{}","tag":"{database_tag}"}}}},"db":"{database_ciphertext}"}}"#,
            hex_encode(&[0x11; AES_NONCE_BYTES]),
            hex_encode(&salt),
            hex_encode(&[0x22; AES_NONCE_BYTES]),
        );
        Zeroizing::new(export.into_bytes())
    }

    #[test]
    fn imports_plaintext_totp_and_hotp_and_preserves_supported_metadata() {
        let database = database_json();
        let database_text = std::str::from_utf8(&database).expect("test database is UTF-8");
        let export = Zeroizing::new(
            format!(
                r#"{{"version":1,"header":{{"slots":null,"params":null}},"db":{}}}"#,
                database_text,
            )
            .into_bytes(),
        );
        let imported =
            import_aegis_export(&export, None).expect("plaintext Aegis export should import");
        assert_eq!(imported.accounts.len(), 2);
        assert_eq!(imported.skipped_unsupported, 1);
        assert_eq!(imported.accounts[0].issuer(), "Example");
        assert_eq!(imported.accounts[0].label(), "alice@example.com");
        assert_eq!(imported.accounts[0].algorithm(), OtpAlgorithm::Sha256);
        assert_eq!(imported.accounts[0].digits(), 8);
        assert_eq!(
            imported.accounts[0].mode(),
            crate::accounts::AccountMode::Totp { period_seconds: 60 }
        );
        assert_eq!(imported.accounts[0].group(), Some("Personal"));
        assert!(imported.accounts[0].is_favorite());
        assert_eq!(
            imported.accounts[1].mode(),
            crate::accounts::AccountMode::Hotp { counter: 9 }
        );
        assert_eq!(imported.accounts[1].group(), Some("Personal"));
    }

    #[test]
    fn imports_official_aegis_plaintext_fixture() {
        let imported =
            import_aegis_export(include_bytes!("../tests/fixtures/aegis_plain.json"), None)
                .expect("official plaintext Aegis fixture should import");
        assert_eq!(imported.accounts.len(), 6);
        assert_eq!(imported.skipped_unsupported, 1);

        let first = &imported.accounts[0];
        assert_eq!(first.issuer(), "Deno");
        assert_eq!(first.label(), "Mason");
        assert_eq!(first.algorithm(), OtpAlgorithm::Sha1);
        assert_eq!(first.digits(), 6);
        assert_eq!(
            first.mode(),
            crate::accounts::AccountMode::Totp { period_seconds: 30 }
        );

        let last = &imported.accounts[5];
        assert_eq!(last.issuer(), "WWE");
        assert_eq!(last.label(), "Mason");
        assert_eq!(last.algorithm(), OtpAlgorithm::Sha512);
        assert_eq!(last.digits(), 8);
        assert_eq!(
            last.mode(),
            crate::accounts::AccountMode::Hotp { counter: 10_300 }
        );
    }

    #[test]
    fn imports_official_aegis_encrypted_fixture_with_export_password() {
        let imported = import_aegis_export(
            include_bytes!("../tests/fixtures/aegis_encrypted.json"),
            Some(b"test"),
        )
        .expect("official encrypted Aegis fixture should decrypt and import");
        assert_eq!(imported.accounts.len(), 6);
        assert_eq!(imported.skipped_unsupported, 1);
    }

    #[test]
    fn imports_password_encrypted_aegis_export() {
        let export = encrypted_export();
        let imported = import_aegis_export(&export, Some(b"correct horse battery staple"))
            .expect("encrypted Aegis export should import");
        assert_eq!(imported.accounts.len(), 2);
        assert_eq!(imported.accounts[0].label(), "alice@example.com");
    }

    #[test]
    fn encrypted_export_requires_password_and_rejects_wrong_password() {
        let export = encrypted_export();
        assert_eq!(
            import_aegis_export(&export, None).err(),
            Some(AegisImportError::PasswordRequired)
        );
        assert_eq!(
            import_aegis_export(&export, Some(b"wrong password")).err(),
            Some(AegisImportError::WrongPassword)
        );
    }

    #[test]
    fn rejects_passwords_over_the_import_limit() {
        let export = include_bytes!("../tests/fixtures/aegis_encrypted.json");
        let password = vec![b'x'; MAX_PASSWORD_BYTES + 1];
        assert_eq!(
            import_aegis_export(export, Some(&password)).err(),
            Some(AegisImportError::PasswordTooLong)
        );
    }

    #[test]
    fn rejects_inconsistent_plaintext_header_and_database_shapes() {
        let export = br#"{
            "version": 1,
            "header": { "slots": [], "params": null },
            "db": { "version": 3, "entries": [] }
        }"#;
        assert_eq!(
            import_aegis_export(export, None).err(),
            Some(AegisImportError::InvalidFile)
        );
    }

    #[test]
    fn rejects_missing_encrypted_header_parameters_before_scrypt() {
        let malformed = br#"{
            "version": 1,
            "header": { "slots": [], "params": null },
            "db": "AAAA"
        }"#;
        assert_eq!(
            import_aegis_export(malformed, Some(b"test")).err(),
            Some(AegisImportError::InvalidFile)
        );
    }

    #[test]
    fn rejects_excessive_scrypt_cost_before_running_the_kdf() {
        let export = encrypted_export();
        let export_text =
            String::from_utf8(export.to_vec()).expect("test Aegis export should be valid UTF-8");
        let modified = Zeroizing::new(export_text.replace(r#""n":32768"#, r#""n":1048576"#));
        assert_eq!(
            import_aegis_export(modified.as_bytes(), Some(b"correct horse battery staple")).err(),
            Some(AegisImportError::InvalidEncryptionParameters)
        );
    }

    #[test]
    fn rejects_invalid_version_parameters_and_oversized_inputs() {
        assert_eq!(
            import_aegis_export(b"{}", None).err(),
            Some(AegisImportError::InvalidFile)
        );
        assert_eq!(
            import_aegis_export(&vec![0_u8; MAX_EXPORT_BYTES + 1], None).err(),
            Some(AegisImportError::InputTooLarge)
        );
    }
}
