//! Android-only JNI bridge for the shared SuikaAuthenticator Rust core.
//!
//! Keep this crate in its own Cargo workspace. The core remains platform-
//! neutral and continues to forbid unsafe code; JNI FFI is isolated here.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use jni::errors::ThrowRuntimeExAndDefault;
use jni::objects::{JByteArray, JClass, JObjectArray, JString};
use jni::strings::JNIString;
use jni::sys::{jboolean, jint, jlong, jobjectArray};
use jni::{Env, EnvUnowned};
use suika_core::accounts::{Account, AccountDatabase, AccountMode};
use suika_core::base32::decode_base32;
use suika_core::crypto::KdfParams;
use suika_core::otp::OtpAlgorithm;
use suika_core::storage::{StorageError, VaultStore};
use suika_core::vault::{Vault, VaultSession};
use zeroize::Zeroizing;

const APP_DIRECTORY: &str = "SuikaAuthenticator";
const MAX_SESSION_HANDLE_ATTEMPTS: usize = 8;

struct NativeSession {
    store: VaultStore,
    vault: VaultSession,
    accounts: AccountDatabase,
}

static SESSIONS: OnceLock<Mutex<HashMap<u64, NativeSession>>> = OnceLock::new();

fn sessions() -> &'static Mutex<HashMap<u64, NativeSession>> {
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn app_directory(app_private_root: &str) -> Result<PathBuf, String> {
    let root = PathBuf::from(app_private_root);
    if !root.is_absolute() {
        return Err("Android private storage root must be an absolute path.".to_owned());
    }
    Ok(root.join(APP_DIRECTORY))
}

fn open_store(app_private_root: &str) -> Result<VaultStore, String> {
    VaultStore::open(app_directory(app_private_root)?).map_err(|error| error.to_string())
}

fn insert_session(session: NativeSession) -> Result<u64, String> {
    let mut registry = sessions().lock()
        .map_err(|_| "Native session registry is unavailable.".to_owned())?;
    for _ in 0..MAX_SESSION_HANDLE_ATTEMPTS {
        let mut bytes = [0_u8; 8];
        getrandom::fill(&mut bytes)
            .map_err(|_| "The operating system random source is unavailable.".to_owned())?;
        let handle = u64::from_ne_bytes(bytes) & (i64::MAX as u64);
        if handle == 0 || registry.contains_key(&handle) { continue; }
        registry.insert(handle, session);
        return Ok(handle);
    }
    Err("A unique native session handle could not be allocated.".to_owned())
}

fn create_vault(app_private_root: &str, password: &[u8]) -> Result<u64, String> {
    let store = open_store(app_private_root)?;
    match store.load() {
        Ok(_) => return Err("An encrypted vault already exists.".to_owned()),
        Err(StorageError::VaultNotFound) => {}
        Err(error) => return Err(error.to_string()),
    }
    let accounts = AccountDatabase::new();
    let plaintext = accounts.encode().map_err(|error| error.to_string())?;
    let (serialized, vault) = Vault::create_session(&plaintext, password, KdfParams::PRODUCTION)
        .map_err(|error| error.to_string())?;
    store.save_new(&serialized).map_err(|error| error.to_string())?;
    insert_session(NativeSession { store, vault, accounts })
}

fn unlock_vault(app_private_root: &str, password: &[u8]) -> Result<u64, String> {
    let store = open_store(app_private_root)?;
    let serialized = store.load().map_err(|error| error.to_string())?;
    let vault = Vault::unlock(&serialized, password).map_err(|error| error.to_string())?;
    let accounts = AccountDatabase::decode(vault.plaintext()).map_err(|error| error.to_string())?;
    insert_session(NativeSession { store, vault, accounts })
}

fn vault_exists(app_private_root: &str) -> Result<bool, String> {
    let store = open_store(app_private_root)?;
    match store.load() {
        Ok(_) => Ok(true),
        Err(StorageError::VaultNotFound) => Ok(false),
        Err(error) => Err(error.to_string()),
    }
}

fn persist_candidate(session: &mut NativeSession, candidate: AccountDatabase) -> Result<(), String> {
    let new_plaintext = candidate.encode().map_err(|error| error.to_string())?;
    let previous_plaintext = Zeroizing::new(session.vault.plaintext().to_vec());
    session.vault.replace_plaintext(new_plaintext).map_err(|error| error.to_string())?;
    let encrypted = match session.vault.seal_current() {
        Ok(serialized) => serialized,
        Err(error) => {
            let _ = session.vault.replace_plaintext(previous_plaintext);
            return Err(error.to_string());
        }
    };
    if let Err(error) = session.store.save(&encrypted) {
        let _ = session.vault.replace_plaintext(previous_plaintext);
        return Err(error.to_string());
    }
    session.accounts = candidate;
    Ok(())
}

fn add_totp(
    handle: jlong,
    issuer: String,
    label: String,
    encoded_secret: &[u8],
    algorithm: jint,
    digits: jint,
    period_seconds: jlong,
) -> Result<(), String> {
    let handle = u64::try_from(handle).map_err(|_| "Native session handle is invalid.".to_owned())?;
    let algorithm = match algorithm {
        1 => OtpAlgorithm::Sha1,
        2 => OtpAlgorithm::Sha256,
        3 => OtpAlgorithm::Sha512,
        _ => return Err("The selected OTP algorithm is not supported.".to_owned()),
    };
    let digits = u8::try_from(digits).map_err(|_| "The OTP digit count is invalid.".to_owned())?;
    let period_seconds = u64::try_from(period_seconds)
        .map_err(|_| "The TOTP period is invalid.".to_owned())?;
    let encoded = Zeroizing::new(
        std::str::from_utf8(encoded_secret)
            .map_err(|_| "The Base32 secret is not valid UTF-8.".to_owned())?.to_owned()
    );
    let secret = decode_base32(&encoded).map_err(|error| error.to_string())?;
    let account = Account::new_totp(issuer, label, secret, algorithm, digits, period_seconds)
        .map_err(|error| error.to_string())?;

    let mut registry = sessions().lock()
        .map_err(|_| "Native session registry is unavailable.".to_owned())?;
    let session = registry.get_mut(&handle)
        .ok_or_else(|| "The native vault session is no longer active.".to_owned())?;
    let candidate_bytes = session.accounts.encode().map_err(|error| error.to_string())?;
    let mut candidate = AccountDatabase::decode(&candidate_bytes).map_err(|error| error.to_string())?;
    candidate.insert(account).map_err(|error| error.to_string())?;
    persist_candidate(session, candidate)
}

fn parse_account_id(encoded: &str) -> Result<[u8; 16], String> {
    let bytes = encoded.as_bytes();
    if bytes.len() != 32 {
        return Err("The account identifier is invalid.".to_owned());
    }

    let mut id = [0_u8; 16];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or_else(|| "The account identifier is invalid.".to_owned())?;
        let low = hex_nibble(pair[1]).ok_or_else(|| "The account identifier is invalid.".to_owned())?;
        id[index] = (high << 4) | low;
    }
    Ok(id)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

/// Consume an HOTP code only after its incremented counter is encrypted and committed.
fn consume_hotp(handle: jlong, encoded_id: &str) -> Result<String, String> {
    let handle = u64::try_from(handle).map_err(|_| "Native session handle is invalid.".to_owned())?;
    let account_id = parse_account_id(encoded_id)?;
    let mut registry = sessions().lock()
        .map_err(|_| "Native session registry is unavailable.".to_owned())?;
    let session = registry.get_mut(&handle)
        .ok_or_else(|| "The native vault session is no longer active.".to_owned())?;

    let candidate_bytes = session.accounts.encode().map_err(|error| error.to_string())?;
    let mut candidate = AccountDatabase::decode(&candidate_bytes).map_err(|error| error.to_string())?;

    let code = {
        let account = candidate.get_mut(&account_id)
            .ok_or_else(|| "The authenticator account no longer exists.".to_owned())?;
        if !matches!(account.mode(), AccountMode::Hotp { .. }) {
            return Err("This account does not use HOTP.".to_owned());
        }
        let code = account.generate_code(0).map_err(|error| error.to_string())?;
        account.advance_hotp_counter().map_err(|error| error.to_string())?;
        code
    };

    // Do not expose the one-time value until the next counter is safely saved.
    persist_candidate(session, candidate)?;
    Ok(code)
}

fn list_account_fields(handle: jlong) -> Result<Vec<String>, String> {
    let handle = u64::try_from(handle).map_err(|_| "Native session handle is invalid.".to_owned())?;
    let registry = sessions().lock()
        .map_err(|_| "Native session registry is unavailable.".to_owned())?;
    let session = registry.get(&handle)
        .ok_or_else(|| "The native vault session is no longer active.".to_owned())?;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "The system clock is before the Unix epoch.".to_owned())?.as_secs();
    let mut fields = Vec::with_capacity(session.accounts.len().saturating_mul(5));
    for account in session.accounts.accounts() {
        let id = account.id().iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let (code, kind) = match account.mode() {
            AccountMode::Totp { period_seconds } => (
                account.generate_code(timestamp).map_err(|error| error.to_string())?,
                format!("TOTP · {period_seconds}s"),
            ),
            AccountMode::Hotp { counter } => (
                String::new(),
                format!("HOTP · tap to generate · counter {counter}"),
            ),
        };
        fields.push(id);
        fields.push(account.issuer().to_owned());
        fields.push(account.label().to_owned());
        fields.push(code);
        fields.push(kind);
    }
    Ok(fields)
}

fn throw_state_error<T: Default>(env: &mut Env<'_>, message: &str) -> jni::errors::Result<T> {
    let class = jni::jni_str!("java/lang/IllegalStateException");
    let message = JNIString::new(message);
    env.throw_new(class, &message)?;
    Ok(T::default())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_suika_suikaauthenticator_NativeBridge_nativeHasVault<'local>(
    mut unowned_env: EnvUnowned<'local>, _class: JClass<'local>, root: JString<'local>
) -> jboolean {
    unowned_env.with_env(|env| -> jni::errors::Result<jboolean> {
        let root = root.try_to_string(env)?;
        match vault_exists(&root) {
            Ok(true) => Ok(true),
            Ok(false) => Ok(false),
            Err(message) => throw_state_error(env, &message),
        }
    }).resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_suika_suikaauthenticator_NativeBridge_nativeCreateVault<'local>(
    mut unowned_env: EnvUnowned<'local>, _class: JClass<'local>,
    root: JString<'local>, password: JByteArray<'local>
) -> jlong {
    unowned_env.with_env(|env| -> jni::errors::Result<jlong> {
        let root = root.try_to_string(env)?;
        let password = Zeroizing::new(env.convert_byte_array(&password)?);
        match create_vault(&root, &password) {
            Ok(handle) => Ok(handle as jlong),
            Err(message) => throw_state_error(env, &message),
        }
    }).resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_suika_suikaauthenticator_NativeBridge_nativeUnlockVault<'local>(
    mut unowned_env: EnvUnowned<'local>, _class: JClass<'local>,
    root: JString<'local>, password: JByteArray<'local>
) -> jlong {
    unowned_env.with_env(|env| -> jni::errors::Result<jlong> {
        let root = root.try_to_string(env)?;
        let password = Zeroizing::new(env.convert_byte_array(&password)?);
        match unlock_vault(&root, &password) {
            Ok(handle) => Ok(handle as jlong),
            Err(message) => throw_state_error(env, &message),
        }
    }).resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_suika_suikaauthenticator_NativeBridge_nativeLockVault<'local>(
    mut unowned_env: EnvUnowned<'local>, _class: JClass<'local>, handle: jlong
) {
    unowned_env.with_env(|env| -> jni::errors::Result<()> {
        let handle = match u64::try_from(handle) {
            Ok(handle) => handle,
            Err(_) => return throw_state_error(env, "Native session handle is invalid."),
        };
        let mut registry = match sessions().lock() {
            Ok(registry) => registry,
            Err(_) => return throw_state_error(env, "Native session registry is unavailable."),
        };
        if registry.remove(&handle).is_none() {
            return throw_state_error(env, "The native vault session is no longer active.");
        }
        Ok(())
    }).resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_suika_suikaauthenticator_NativeBridge_nativeListAccounts<'local>(
    mut unowned_env: EnvUnowned<'local>, _class: JClass<'local>, handle: jlong
) -> jobjectArray {
    unowned_env.with_env(|env| -> jni::errors::Result<jobjectArray> {
        let fields = match list_account_fields(handle) {
            Ok(fields) => fields,
            Err(message) => return throw_state_error(env, &message),
        };
        let empty = JString::from_str(env, "")?;
        let array = JObjectArray::<JString>::new(env, fields.len(), &empty)?;
        for (index, field) in fields.iter().enumerate() {
            let value = JString::from_str(env, field)?;
            array.set_element(env, index, &value)?;
        }
        Ok(array.into_raw())
    }).resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_suika_suikaauthenticator_NativeBridge_nativeAddTotp<'local>(
    mut unowned_env: EnvUnowned<'local>, _class: JClass<'local>,
    handle: jlong, issuer: JString<'local>, label: JString<'local>,
    encoded_secret: JByteArray<'local>, algorithm: jint, digits: jint, period_seconds: jlong
) {
    unowned_env.with_env(|env| -> jni::errors::Result<()> {
        let issuer = issuer.try_to_string(env)?;
        let label = label.try_to_string(env)?;
        let encoded_secret = Zeroizing::new(env.convert_byte_array(&encoded_secret)?);
        match add_totp(handle, issuer, label, &encoded_secret, algorithm, digits, period_seconds) {
            Ok(()) => Ok(()),
            Err(message) => throw_state_error(env, &message),
        }
    }).resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_suika_suikaauthenticator_NativeBridge_nativeConsumeHotp<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    account_id: JString<'local>,
) -> jni::sys::jstring {
    unowned_env.with_env(|env| -> jni::errors::Result<jni::sys::jstring> {
        let account_id = account_id.try_to_string(env)?;
        match consume_hotp(handle, &account_id) {
            Ok(code) => Ok(JString::from_str(env, &code)?.into_raw()),
            Err(message) => throw_state_error(env, &message),
        }
    }).resolve::<ThrowRuntimeExAndDefault>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let mut random = [0_u8; 12];
            getrandom::fill(&mut random).expect("system CSPRNG should be available");
            let suffix = random.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
            let path = std::env::temp_dir().join(format!("suika-android-native-test-{suffix}"));
            fs::create_dir(&path).expect("test directory should be created");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn hotp_is_returned_only_after_the_next_counter_is_persisted() {
        let temporary = TestDirectory::new();
        let store = VaultStore::open(temporary.0.join(APP_DIRECTORY))
            .expect("vault store should open");
        let mut accounts = AccountDatabase::new();
        let account = Account::new_hotp(
            "RFC 4226",
            "test account",
            Zeroizing::new(b"12345678901234567890".to_vec()),
            OtpAlgorithm::Sha1,
            6,
            0,
        ).expect("HOTP account should be valid");
        let account_id = account.id().iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        accounts.insert(account).expect("HOTP account should insert");

        let plaintext = accounts.encode().expect("account database should encode");
        let params = KdfParams::new(64 * 1024, 1, 1).expect("test KDF profile");
        let (serialized, vault) = Vault::create_session(&plaintext, b"test password", params)
            .expect("encrypted vault and unlocked session should be created");
        store.save_new(&serialized).expect("initial vault should be saved");

        let handle = insert_session(NativeSession { store, vault, accounts })
            .expect("native session handle should be allocated");
        let first = consume_hotp(handle as jlong, &account_id).expect("first HOTP should persist");
        let second = consume_hotp(handle as jlong, &account_id).expect("second HOTP should persist");
        assert_eq!(first, "755224");
        assert_eq!(second, "287082");

        let mut registry = sessions().lock().expect("session registry should remain available");
        let session = registry.remove(&handle).expect("test session should still exist");
        let persisted = Vault::unlock(
            &session.store.load().expect("updated encrypted vault should load"),
            b"test password",
        ).expect("updated vault should unlock");
        let persisted_accounts = AccountDatabase::decode(persisted.plaintext())
            .expect("persisted account database should decode");
        assert_eq!(
            persisted_accounts.accounts()[0].generate_code(0).expect("next HOTP code"),
            "359152"
        );
    }
}

