//! Compact, versioned account database encoding.
//!
//! The database bytes are plaintext input to the encrypted vault. Callers must
//! keep encoded buffers in Zeroizing memory and must never write them directly
//! to disk.

use std::collections::HashSet;

use zeroize::Zeroizing;

use crate::otp::{OtpAlgorithm, OtpError, generate_hotp, generate_totp};

const DATABASE_MAGIC: &[u8; 8] = b"SUIKADB\0";
const DATABASE_VERSION: u16 = 1;
const RECORD_VERSION: u16 = 1;
const HEADER_BYTES: usize = 16;
const RECORD_FIXED_BYTES: usize = 38;
const MAX_ACCOUNTS: usize = 10_000;
const MAX_DATABASE_BYTES: usize = 8 * 1024 * 1024;
const MAX_ISSUER_BYTES: usize = 256;
const MAX_LABEL_BYTES: usize = 256;
const MAX_GROUP_BYTES: usize = 128;
const MAX_SECRET_BYTES: usize = 128;
const MAX_PERIOD_SECONDS: u64 = 86_400;

/// Account-level errors. Messages never include account secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountError {
    /// Account metadata or OTP parameters are invalid.
    InvalidAccount,
    /// The account database is malformed, truncated, or contains trailing bytes.
    InvalidDatabase,
    /// The database or a record uses an unsupported version.
    UnsupportedVersion,
    /// The database exceeds an application safety limit.
    DatabaseTooLarge,
    /// The database contains more accounts than supported.
    TooManyAccounts,
    /// Two records have the same account identifier.
    DuplicateAccountId,
    /// The operating system could not provide random identifier bytes.
    RandomnessUnavailable,
    /// An HOTP counter cannot be incremented further.
    CounterExhausted,
    /// OTP generation rejected its inputs.
    Otp(OtpError),
}

impl core::fmt::Display for AccountError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidAccount => f.write_str("account metadata or OTP parameters are invalid"),
            Self::InvalidDatabase => f.write_str("account database is malformed or truncated"),
            Self::UnsupportedVersion => f.write_str("account database version is not supported"),
            Self::DatabaseTooLarge => f.write_str("account database exceeds the supported size"),
            Self::TooManyAccounts => f.write_str("account count exceeds the supported limit"),
            Self::DuplicateAccountId => {
                f.write_str("account database contains a duplicate identifier")
            }
            Self::RandomnessUnavailable => {
                f.write_str("operating-system randomness is unavailable")
            }
            Self::CounterExhausted => f.write_str("HOTP counter cannot be incremented"),
            Self::Otp(error) => write!(f, "OTP generation failed: {error}"),
        }
    }
}

impl std::error::Error for AccountError {}

impl From<OtpError> for AccountError {
    fn from(error: OtpError) -> Self {
        Self::Otp(error)
    }
}

/// The OTP mode and its mode-specific parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountMode {
    /// Time-based OTP with an interval measured in seconds.
    Totp { period_seconds: u64 },
    /// Counter-based OTP with its current counter.
    Hotp { counter: u64 },
}

/// One authenticator account.
///
/// The secret is held in a zeroizing buffer. Account does not implement Clone
/// or Debug, avoiding accidental secret duplication or formatting.
pub struct Account {
    id: [u8; 16],
    issuer: String,
    label: String,
    group: Option<String>,
    favorite: bool,
    algorithm: OtpAlgorithm,
    digits: u8,
    mode: AccountMode,
    secret: Zeroizing<Vec<u8>>,
}

impl Account {
    /// Create a TOTP account with a randomly generated 128-bit identifier.
    pub fn new_totp(
        issuer: impl Into<String>,
        label: impl Into<String>,
        secret: Zeroizing<Vec<u8>>,
        algorithm: OtpAlgorithm,
        digits: u8,
        period_seconds: u64,
    ) -> Result<Self, AccountError> {
        let account = Self {
            id: generate_account_id()?,
            issuer: issuer.into(),
            label: label.into(),
            group: None,
            favorite: false,
            algorithm,
            digits,
            mode: AccountMode::Totp { period_seconds },
            secret,
        };
        account.validate()?;
        Ok(account)
    }

    /// Create an HOTP account with a randomly generated 128-bit identifier.
    pub fn new_hotp(
        issuer: impl Into<String>,
        label: impl Into<String>,
        secret: Zeroizing<Vec<u8>>,
        algorithm: OtpAlgorithm,
        digits: u8,
        counter: u64,
    ) -> Result<Self, AccountError> {
        let account = Self {
            id: generate_account_id()?,
            issuer: issuer.into(),
            label: label.into(),
            group: None,
            favorite: false,
            algorithm,
            digits,
            mode: AccountMode::Hotp { counter },
            secret,
        };
        account.validate()?;
        Ok(account)
    }

    /// Return the stable random account identifier.
    #[must_use]
    pub const fn id(&self) -> &[u8; 16] {
        &self.id
    }

    /// Return the issuer label.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Return the account label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Return the optional group name.
    #[must_use]
    pub fn group(&self) -> Option<&str> {
        self.group.as_deref()
    }

    /// Set or clear the account group.
    pub fn set_group(&mut self, group: Option<String>) -> Result<(), AccountError> {
        if group
            .as_ref()
            .is_some_and(|value| value.len() > MAX_GROUP_BYTES)
        {
            return Err(AccountError::InvalidAccount);
        }
        self.group = group.filter(|value| !value.is_empty());
        Ok(())
    }

    /// Return whether the account is marked as a favorite.
    #[must_use]
    pub const fn is_favorite(&self) -> bool {
        self.favorite
    }

    /// Set the favorite marker.
    pub fn set_favorite(&mut self, favorite: bool) {
        self.favorite = favorite;
    }

    /// Return the configured HMAC digest.
    #[must_use]
    pub const fn algorithm(&self) -> OtpAlgorithm {
        self.algorithm
    }

    /// Return the configured OTP digit count.
    #[must_use]
    pub const fn digits(&self) -> u8 {
        self.digits
    }

    /// Return the OTP mode.
    #[must_use]
    pub const fn mode(&self) -> AccountMode {
        self.mode
    }

    /// Generate the current TOTP or HOTP value.
    ///
    /// For HOTP, timestamp_seconds is ignored and the current counter is used.
    pub fn generate_code(&self, timestamp_seconds: u64) -> Result<String, AccountError> {
        match self.mode {
            AccountMode::Totp { period_seconds } => Ok(generate_totp(
                &self.secret,
                timestamp_seconds,
                period_seconds,
                self.digits,
                self.algorithm,
            )?),
            AccountMode::Hotp { counter } => Ok(generate_hotp(
                &self.secret,
                counter,
                self.digits,
                self.algorithm,
            )?),
        }
    }

    /// Advance an HOTP account after its code has been consumed.
    pub fn advance_hotp_counter(&mut self) -> Result<u64, AccountError> {
        match &mut self.mode {
            AccountMode::Hotp { counter } => {
                *counter = counter
                    .checked_add(1)
                    .ok_or(AccountError::CounterExhausted)?;
                Ok(*counter)
            }
            AccountMode::Totp { .. } => Err(AccountError::InvalidAccount),
        }
    }

    fn validate(&self) -> Result<(), AccountError> {
        if self.label.is_empty()
            || self.label.len() > MAX_LABEL_BYTES
            || self.issuer.len() > MAX_ISSUER_BYTES
            || self
                .group
                .as_ref()
                .is_some_and(|value| value.is_empty() || value.len() > MAX_GROUP_BYTES)
            || self.secret.is_empty()
            || self.secret.len() > MAX_SECRET_BYTES
            || !(6..=8).contains(&self.digits)
        {
            return Err(AccountError::InvalidAccount);
        }

        if let AccountMode::Totp { period_seconds } = self.mode
            && !(1..=MAX_PERIOD_SECONDS).contains(&period_seconds)
        {
            return Err(AccountError::InvalidAccount);
        }

        Ok(())
    }
}

/// In-memory collection of accounts with a compact versioned binary format.
pub struct AccountDatabase {
    accounts: Vec<Account>,
}

impl AccountDatabase {
    /// Create an empty account database.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            accounts: Vec::new(),
        }
    }

    /// Return the number of accounts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    /// Return whether the database contains no accounts.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    /// Borrow the ordered account list.
    #[must_use]
    pub fn accounts(&self) -> &[Account] {
        &self.accounts
    }

    /// Insert an account, rejecting duplicate identifiers.
    pub fn insert(&mut self, account: Account) -> Result<(), AccountError> {
        account.validate()?;
        if self.accounts.len() >= MAX_ACCOUNTS {
            return Err(AccountError::TooManyAccounts);
        }
        if self
            .accounts
            .iter()
            .any(|existing| existing.id == account.id)
        {
            return Err(AccountError::DuplicateAccountId);
        }
        self.accounts.push(account);
        Ok(())
    }

    /// Remove an account by identifier. Its secret is zeroized when dropped.
    pub fn remove(&mut self, id: &[u8; 16]) -> bool {
        if let Some(index) = self.accounts.iter().position(|account| &account.id == id) {
            self.accounts.remove(index);
            true
        } else {
            false
        }
    }

    /// Encode the database into a zeroizing plaintext buffer for vault storage.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, AccountError> {
        if self.accounts.len() > MAX_ACCOUNTS {
            return Err(AccountError::TooManyAccounts);
        }

        let mut seen = HashSet::with_capacity(self.accounts.len());
        let mut total_len = HEADER_BYTES;

        for account in &self.accounts {
            account.validate()?;
            if !seen.insert(account.id) {
                return Err(AccountError::DuplicateAccountId);
            }

            let record_len = record_length(account)?;
            total_len = total_len
                .checked_add(4 + record_len)
                .ok_or(AccountError::DatabaseTooLarge)?;
        }

        if total_len > MAX_DATABASE_BYTES {
            return Err(AccountError::DatabaseTooLarge);
        }

        let count =
            u32::try_from(self.accounts.len()).map_err(|_| AccountError::TooManyAccounts)?;
        let mut output = Zeroizing::new(Vec::with_capacity(total_len));
        output.extend_from_slice(DATABASE_MAGIC);
        output.extend_from_slice(&DATABASE_VERSION.to_be_bytes());
        output.extend_from_slice(&0_u16.to_be_bytes());
        output.extend_from_slice(&count.to_be_bytes());

        for account in &self.accounts {
            encode_record(account, &mut output)?;
        }

        Ok(output)
    }

    /// Decode a database from decrypted vault bytes.
    pub fn decode(encoded: &[u8]) -> Result<Self, AccountError> {
        if encoded.len() < HEADER_BYTES || encoded.len() > MAX_DATABASE_BYTES {
            return Err(AccountError::InvalidDatabase);
        }

        let mut cursor = Cursor::new(encoded);
        if cursor.take(8)? != DATABASE_MAGIC {
            return Err(AccountError::InvalidDatabase);
        }

        let version = cursor.u16()?;
        if version != DATABASE_VERSION {
            return Err(AccountError::UnsupportedVersion);
        }
        if cursor.u16()? != 0 {
            return Err(AccountError::InvalidDatabase);
        }

        let count = usize::try_from(cursor.u32()?).map_err(|_| AccountError::InvalidDatabase)?;
        if count > MAX_ACCOUNTS {
            return Err(AccountError::TooManyAccounts);
        }

        let mut accounts = Vec::with_capacity(count);
        let mut seen = HashSet::with_capacity(count);

        for _ in 0..count {
            let record_length =
                usize::try_from(cursor.u32()?).map_err(|_| AccountError::InvalidDatabase)?;
            if !(RECORD_FIXED_BYTES..=MAX_DATABASE_BYTES).contains(&record_length) {
                return Err(AccountError::InvalidDatabase);
            }

            let record_bytes = cursor.take(record_length)?;
            let account = decode_record(record_bytes)?;
            if !seen.insert(account.id) {
                return Err(AccountError::DuplicateAccountId);
            }
            accounts.push(account);
        }

        if !cursor.is_empty() {
            return Err(AccountError::InvalidDatabase);
        }

        Ok(Self { accounts })
    }
}

impl Default for AccountDatabase {
    fn default() -> Self {
        Self::new()
    }
}

fn generate_account_id() -> Result<[u8; 16], AccountError> {
    let mut id = [0_u8; 16];
    getrandom::fill(&mut id).map_err(|_| AccountError::RandomnessUnavailable)?;
    Ok(id)
}

fn record_length(account: &Account) -> Result<usize, AccountError> {
    RECORD_FIXED_BYTES
        .checked_add(account.issuer.len())
        .and_then(|length| length.checked_add(account.label.len()))
        .and_then(|length| length.checked_add(account.group.as_ref().map_or(0, String::len)))
        .and_then(|length| length.checked_add(account.secret.len()))
        .ok_or(AccountError::DatabaseTooLarge)
}

fn encode_record(account: &Account, output: &mut Zeroizing<Vec<u8>>) -> Result<(), AccountError> {
    let record_len = record_length(account)?;
    let record_len_u32 = u32::try_from(record_len).map_err(|_| AccountError::DatabaseTooLarge)?;
    let issuer_len =
        u16::try_from(account.issuer.len()).map_err(|_| AccountError::InvalidAccount)?;
    let label_len = u16::try_from(account.label.len()).map_err(|_| AccountError::InvalidAccount)?;
    let group_bytes = account.group.as_deref().unwrap_or("").as_bytes();
    let group_len = u16::try_from(group_bytes.len()).map_err(|_| AccountError::InvalidAccount)?;
    let secret_len =
        u16::try_from(account.secret.len()).map_err(|_| AccountError::InvalidAccount)?;

    let (mode, parameter) = match account.mode {
        AccountMode::Totp { period_seconds } => (1_u8, period_seconds),
        AccountMode::Hotp { counter } => (2_u8, counter),
    };
    let algorithm = match account.algorithm {
        OtpAlgorithm::Sha1 => 1_u8,
        OtpAlgorithm::Sha256 => 2_u8,
        OtpAlgorithm::Sha512 => 3_u8,
    };
    let flags = u8::from(account.favorite);

    output.extend_from_slice(&record_len_u32.to_be_bytes());
    output.extend_from_slice(&account.id);
    output.extend_from_slice(&RECORD_VERSION.to_be_bytes());
    output.push(mode);
    output.push(algorithm);
    output.push(account.digits);
    output.push(flags);
    output.extend_from_slice(&parameter.to_be_bytes());
    output.extend_from_slice(&issuer_len.to_be_bytes());
    output.extend_from_slice(&label_len.to_be_bytes());
    output.extend_from_slice(&group_len.to_be_bytes());
    output.extend_from_slice(&secret_len.to_be_bytes());
    output.extend_from_slice(account.issuer.as_bytes());
    output.extend_from_slice(account.label.as_bytes());
    output.extend_from_slice(group_bytes);
    output.extend_from_slice(&account.secret);

    Ok(())
}

fn decode_record(encoded: &[u8]) -> Result<Account, AccountError> {
    let mut cursor = Cursor::new(encoded);
    let id: [u8; 16] = cursor.array()?;

    let record_version = cursor.u16()?;
    if record_version != RECORD_VERSION {
        return Err(AccountError::UnsupportedVersion);
    }

    let mode = cursor.u8()?;
    let algorithm = match cursor.u8()? {
        1 => OtpAlgorithm::Sha1,
        2 => OtpAlgorithm::Sha256,
        3 => OtpAlgorithm::Sha512,
        _ => return Err(AccountError::InvalidDatabase),
    };
    let digits = cursor.u8()?;
    let flags = cursor.u8()?;
    if flags & !1 != 0 {
        return Err(AccountError::InvalidDatabase);
    }
    let parameter = cursor.u64()?;

    let issuer_len = usize::from(cursor.u16()?);
    let label_len = usize::from(cursor.u16()?);
    let group_len = usize::from(cursor.u16()?);
    let secret_len = usize::from(cursor.u16()?);

    if issuer_len > MAX_ISSUER_BYTES
        || !(1..=MAX_LABEL_BYTES).contains(&label_len)
        || group_len > MAX_GROUP_BYTES
        || !(1..=MAX_SECRET_BYTES).contains(&secret_len)
    {
        return Err(AccountError::InvalidDatabase);
    }

    let issuer = cursor.utf8(issuer_len)?;
    let label = cursor.utf8(label_len)?;
    let group_string = cursor.utf8(group_len)?;
    let secret = Zeroizing::new(cursor.take(secret_len)?.to_vec());

    if !cursor.is_empty() {
        return Err(AccountError::InvalidDatabase);
    }

    let account_mode = match mode {
        1 => AccountMode::Totp {
            period_seconds: parameter,
        },
        2 => AccountMode::Hotp { counter: parameter },
        _ => return Err(AccountError::InvalidDatabase),
    };

    let account = Account {
        id,
        issuer,
        label,
        group: if group_string.is_empty() {
            None
        } else {
            Some(group_string)
        },
        favorite: flags & 1 != 0,
        algorithm,
        digits,
        mode: account_mode,
        secret,
    };
    account.validate()?;
    Ok(account)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], AccountError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(AccountError::InvalidDatabase)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(AccountError::InvalidDatabase)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], AccountError> {
        self.take(N)?
            .try_into()
            .map_err(|_| AccountError::InvalidDatabase)
    }

    fn u8(&mut self) -> Result<u8, AccountError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, AccountError> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, AccountError> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, AccountError> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    fn utf8(&mut self, length: usize) -> Result<String, AccountError> {
        String::from_utf8(self.take(length)?.to_vec()).map_err(|_| AccountError::InvalidDatabase)
    }

    const fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_totp_and_hotp_accounts() {
        let mut database = AccountDatabase::new();

        let mut totp = Account::new_totp(
            "Example",
            "alice@example.com",
            Zeroizing::new(b"12345678901234567890".to_vec()),
            OtpAlgorithm::Sha1,
            6,
            30,
        )
        .expect("TOTP account should be valid");
        totp.set_group(Some("Personal".to_owned()))
            .expect("group should be valid");
        totp.set_favorite(true);

        let hotp = Account::new_hotp(
            "Counter Service",
            "work account",
            Zeroizing::new(b"12345678901234567890".to_vec()),
            OtpAlgorithm::Sha1,
            6,
            1,
        )
        .expect("HOTP account should be valid");

        database.insert(totp).expect("insert TOTP");
        database.insert(hotp).expect("insert HOTP");

        let encoded = database.encode().expect("database should encode");
        let decoded = AccountDatabase::decode(&encoded).expect("database should decode");

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded.accounts()[0].issuer(), "Example");
        assert_eq!(decoded.accounts()[0].label(), "alice@example.com");
        assert_eq!(decoded.accounts()[0].group(), Some("Personal"));
        assert!(decoded.accounts()[0].is_favorite());
        assert_eq!(
            decoded.accounts()[0]
                .generate_code(59)
                .expect("TOTP should generate"),
            "287082"
        );
        assert_eq!(
            decoded.accounts()[1]
                .generate_code(0)
                .expect("HOTP should generate"),
            "287082"
        );
    }

    #[test]
    fn hotp_counter_is_explicitly_advanced() {
        let mut account = Account::new_hotp(
            "Issuer",
            "label",
            Zeroizing::new(b"12345678901234567890".to_vec()),
            OtpAlgorithm::Sha1,
            6,
            0,
        )
        .expect("HOTP account should be valid");

        assert_eq!(account.generate_code(0).expect("code"), "755224");
        assert_eq!(account.advance_hotp_counter().expect("advance"), 1);
        assert_eq!(account.generate_code(0).expect("next code"), "287082");
    }

    #[test]
    fn rejects_trailing_data_and_invalid_header() {
        let database = AccountDatabase::new();
        let encoded = database.encode().expect("empty database should encode");

        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert_eq!(
            AccountDatabase::decode(&trailing).err(),
            Some(AccountError::InvalidDatabase)
        );

        let mut bad_magic = encoded.to_vec();
        bad_magic[0] ^= 1;
        assert_eq!(
            AccountDatabase::decode(&bad_magic).err(),
            Some(AccountError::InvalidDatabase)
        );
    }

    #[test]
    fn rejects_unsupported_database_version() {
        let encoded = AccountDatabase::new().encode().expect("encode");
        let mut unsupported = encoded.to_vec();
        unsupported[8..10].copy_from_slice(&2_u16.to_be_bytes());

        assert_eq!(
            AccountDatabase::decode(&unsupported).err(),
            Some(AccountError::UnsupportedVersion)
        );
    }

    #[test]
    fn rejects_invalid_utf8_and_invalid_otp_parameters() {
        let mut database = AccountDatabase::new();
        let account = Account::new_totp(
            "Issuer",
            "label",
            Zeroizing::new(b"secret".to_vec()),
            OtpAlgorithm::Sha256,
            6,
            30,
        )
        .expect("account should be valid");
        database.insert(account).expect("insert");

        let encoded = database.encode().expect("encode");
        let mut invalid_utf8 = encoded.to_vec();
        // Header(16) + record length(4) + fixed record fields(38) + issuer(6):
        // the first byte of the account label begins at offset 64.
        invalid_utf8[64] = 0xFF;

        assert_eq!(
            AccountDatabase::decode(&invalid_utf8).err(),
            Some(AccountError::InvalidDatabase)
        );
    }
}
