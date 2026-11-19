//! Android-only JNI bridge for the shared SuikaAuthenticator Rust core.
//!
//! Keep this crate in its own Cargo workspace. The core remains platform-
//! neutral and continues to forbid unsafe code; JNI FFI is isolated here.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, Once, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use jni::errors::ThrowRuntimeExAndDefault;
use jni::objects::{JByteArray, JClass, JObjectArray, JString};
use jni::strings::JNIString;
use jni::sys::{jboolean, jbyteArray, jint, jlong, jobjectArray};
use jni::{Env, EnvUnowned};
use suika_core::accounts::{Account, AccountDatabase, AccountMode};
use suika_core::aegis::import_aegis_export;
use suika_core::backup::Backup;
use suika_core::base32::decode_base32;
use suika_core::crypto::KdfParams;
use suika_core::otp::OtpAlgorithm;
use suika_core::otpauth::parse_otpauth_uri;
use suika_core::storage::{StorageError, VaultStore};
use suika_core::vault::{Vault, VaultSession};
use zeroize::Zeroizing;

#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(
    _vm: *mut std::ffi::c_void,
    _reserved: *mut std::ffi::c_void,
) -> jint {
    static PANIC_HOOK: Once = Once::new();
    PANIC_HOOK.call_once(|| std::panic::set_hook(Box::new(|_| {})));
    jni::sys::JNI_VERSION_1_6
}

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
    let mut registry = sessions()
        .lock()
        .map_err(|_| "Native session registry is unavailable.".to_owned())?;
    for _ in 0..MAX_SESSION_HANDLE_ATTEMPTS {
        let mut bytes = [0_u8; 8];
        getrandom::fill(&mut bytes)
            .map_err(|_| "The operating system random source is unavailable.".to_owned())?;
        let handle = u64::from_ne_bytes(bytes) & (i64::MAX as u64);
        if handle == 0 || registry.contains_key(&handle) {
            continue;
        }
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
    store
        .save_new(&serialized)
        .map_err(|error| error.to_string())?;
    insert_session(NativeSession {
        store,
        vault,
        accounts,
    })
}

fn unlock_vault(app_private_root: &str, password: &[u8]) -> Result<u64, String> {
    let store = open_store(app_private_root)?;
    let serialized = store.load().map_err(|error| error.to_string())?;
    let vault = Vault::unlock(&serialized, password).map_err(|error| error.to_string())?;
    let accounts = AccountDatabase::decode(vault.plaintext()).map_err(|error| error.to_string())?;
    insert_session(NativeSession {
        store,
        vault,
        accounts,
    })
}

fn unlock_vault_with_device_key(
    app_private_root: &str,
    wrapping_key: &[u8],
) -> Result<u64, String> {
    let store = open_store(app_private_root)?;
    let serialized = store.load().map_err(|error| error.to_string())?;
    let vault = Vault::unlock_with_device_wrapping_key(&serialized, wrapping_key)
        .map_err(|error| error.to_string())?;
    let accounts = AccountDatabase::decode(vault.plaintext()).map_err(|error| error.to_string())?;
    insert_session(NativeSession {
        store,
        vault,
        accounts,
    })
}

fn export_device_unlock_key(handle: jlong) -> Result<Zeroizing<[u8; 32]>, String> {
    let handle =
        u64::try_from(handle).map_err(|_| "Native session handle is invalid.".to_owned())?;
    let registry = sessions()
        .lock()
        .map_err(|_| "Native session registry is unavailable.".to_owned())?;
    let session = registry
        .get(&handle)
        .ok_or_else(|| "The native vault session is no longer active.".to_owned())?;
    Ok(session.vault.device_unlock_wrapping_key())
}

fn vault_exists(app_private_root: &str) -> Result<bool, String> {
    let store = open_store(app_private_root)?;
    match store.load() {
        Ok(_) => Ok(true),
        Err(StorageError::VaultNotFound) => Ok(false),
        Err(error) => Err(error.to_string()),
    }
}

fn persist_candidate(
    session: &mut NativeSession,
    candidate: AccountDatabase,
) -> Result<(), String> {
    let new_plaintext = candidate.encode().map_err(|error| error.to_string())?;
    let previous_plaintext = Zeroizing::new(session.vault.plaintext().to_vec());
    session
        .vault
        .replace_plaintext(new_plaintext)
        .map_err(|error| error.to_string())?;
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
    let handle =
        u64::try_from(handle).map_err(|_| "Native session handle is invalid.".to_owned())?;
    let algorithm = match algorithm {
        1 => OtpAlgorithm::Sha1,
        2 => OtpAlgorithm::Sha256,
        3 => OtpAlgorithm::Sha512,
        _ => return Err("The selected OTP algorithm is not supported.".to_owned()),
    };
    let digits = u8::try_from(digits).map_err(|_| "The OTP digit count is invalid.".to_owned())?;
    let period_seconds =
        u64::try_from(period_seconds).map_err(|_| "The TOTP period is invalid.".to_owned())?;
    let encoded = Zeroizing::new(
        std::str::from_utf8(encoded_secret)
            .map_err(|_| "The Base32 secret is not valid UTF-8.".to_owned())?
            .to_owned(),
    );
    let secret = decode_base32(&encoded).map_err(|error| error.to_string())?;
    let account = Account::new_totp(issuer, label, secret, algorithm, digits, period_seconds)
        .map_err(|error| error.to_string())?;

    let mut registry = sessions()
        .lock()
        .map_err(|_| "Native session registry is unavailable.".to_owned())?;
    let session = registry
        .get_mut(&handle)
        .ok_or_else(|| "The native vault session is no longer active.".to_owned())?;
    let candidate_bytes = session
        .accounts
        .encode()
        .map_err(|error| error.to_string())?;
    let mut candidate =
        AccountDatabase::decode(&candidate_bytes).map_err(|error| error.to_string())?;
    candidate
        .insert(account)
        .map_err(|error| error.to_string())?;
    persist_candidate(session, candidate)
}

fn import_otpauth_uri(handle: jlong, encoded_uri: &[u8]) -> Result<(), String> {
    if encoded_uri.len() > 4096 {
        return Err("The provisioning URI exceeds the supported 4096-byte limit.".to_owned());
    }
    let uri = std::str::from_utf8(encoded_uri)
        .map_err(|_| "The provisioning URI is not valid UTF-8.".to_owned())?;
    let account = parse_otpauth_uri(uri).map_err(|error| error.to_string())?;
    let handle =
        u64::try_from(handle).map_err(|_| "Native session handle is invalid.".to_owned())?;
    let mut registry = sessions()
        .lock()
        .map_err(|_| "Native session registry is unavailable.".to_owned())?;
    let session = registry
        .get_mut(&handle)
        .ok_or_else(|| "The native vault session is no longer active.".to_owned())?;
    let candidate_bytes = session
        .accounts
        .encode()
        .map_err(|error| error.to_string())?;
    let mut candidate =
        AccountDatabase::decode(&candidate_bytes).map_err(|error| error.to_string())?;
    candidate
        .insert(account)
        .map_err(|error| error.to_string())?;
    persist_candidate(session, candidate)
}

fn import_aegis_file(
    handle: jlong,
    encoded_export: &[u8],
    password: &[u8],
) -> Result<(usize, usize), String> {
    let handle =
        u64::try_from(handle).map_err(|_| "Native session handle is invalid.".to_owned())?;
    {
        let registry = sessions()
            .lock()
            .map_err(|_| "Native session registry is unavailable.".to_owned())?;
        if !registry.contains_key(&handle) {
            return Err("The native vault session is no longer active.".to_owned());
        }
    }

    let imported = import_aegis_export(
        encoded_export,
        if password.is_empty() {
            None
        } else {
            Some(password)
        },
    )
    .map_err(|error| error.to_string())?;
    let imported_count = imported.accounts.len();
    let skipped_unsupported = imported.skipped_unsupported;
    if imported_count == 0 {
        return Err(if skipped_unsupported == 0 {
            "The Aegis export contains no accounts.".to_owned()
        } else {
            format!(
                "No supported TOTP/HOTP accounts were found; {skipped_unsupported} unsupported entries were skipped."
            )
        });
    }

    let mut registry = sessions()
        .lock()
        .map_err(|_| "Native session registry is unavailable.".to_owned())?;
    let session = registry
        .get_mut(&handle)
        .ok_or_else(|| "The native vault session is no longer active.".to_owned())?;
    let candidate_bytes = session
        .accounts
        .encode()
        .map_err(|error| error.to_string())?;
    let mut candidate =
        AccountDatabase::decode(&candidate_bytes).map_err(|error| error.to_string())?;
    for account in imported.accounts {
        candidate
            .insert(account)
            .map_err(|error| error.to_string())?;
    }
    persist_candidate(session, candidate)?;
    Ok((imported_count, skipped_unsupported))
}

fn export_backup(handle: jlong, password: &[u8]) -> Result<Vec<u8>, String> {
    let handle =
        u64::try_from(handle).map_err(|_| "Native session handle is invalid.".to_owned())?;
    let plaintext = {
        let registry = sessions()
            .lock()
            .map_err(|_| "Native session registry is unavailable.".to_owned())?;
        let session = registry
            .get(&handle)
            .ok_or_else(|| "The native vault session is no longer active.".to_owned())?;
        Zeroizing::new(session.vault.plaintext().to_vec())
    };

    Backup::create(&plaintext, password, KdfParams::PRODUCTION)
        .map_err(|error| error.to_string())
}

fn restore_backup(
    handle: jlong,
    encoded_backup: &[u8],
    password: &[u8],
) -> Result<usize, String> {
    let handle =
        u64::try_from(handle).map_err(|_| "Native session handle is invalid.".to_owned())?;
    {
        let registry = sessions()
            .lock()
            .map_err(|_| "Native session registry is unavailable.".to_owned())?;
        if !registry.contains_key(&handle) {
            return Err("The native vault session is no longer active.".to_owned());
        }
    }

    let plaintext = Backup::restore(encoded_backup, password)
        .map_err(|error| error.to_string())?;
    let candidate =
        AccountDatabase::decode(&plaintext).map_err(|error| error.to_string())?;
    let restored_count = candidate.len();

    let mut registry = sessions()
        .lock()
        .map_err(|_| "Native session registry is unavailable.".to_owned())?;
    let session = registry
        .get_mut(&handle)
        .ok_or_else(|| "The native vault session is no longer active.".to_owned())?;
    persist_candidate(session, candidate)?;
    Ok(restored_count)
}

fn update_account(
    handle: jlong,
    encoded_id: &str,
    issuer: String,
    label: String,
    encoded_secret: &[u8],
) -> Result<(), String> {
    let handle =
        u64::try_from(handle).map_err(|_| "Native session handle is invalid.".to_owned())?;
    let account_id = parse_account_id(encoded_id)?;
    let replacement_secret = if encoded_secret.is_empty() {
        None
    } else {
        let encoded = Zeroizing::new(
            std::str::from_utf8(encoded_secret)
                .map_err(|_| "The Base32 secret is not valid UTF-8.".to_owned())?
                .to_owned(),
        );
        Some(decode_base32(&encoded).map_err(|error| error.to_string())?)
    };

    let mut registry = sessions()
        .lock()
        .map_err(|_| "Native session registry is unavailable.".to_owned())?;
    let session = registry
        .get_mut(&handle)
        .ok_or_else(|| "The native vault session is no longer active.".to_owned())?;

    let candidate_bytes = session
        .accounts
        .encode()
        .map_err(|error| error.to_string())?;
    let mut candidate =
        AccountDatabase::decode(&candidate_bytes).map_err(|error| error.to_string())?;

    let account = candidate
        .get_mut(&account_id)
        .ok_or_else(|| "The authenticator account no longer exists.".to_owned())?;
    let algorithm = account.algorithm();
    let digits = account.digits();
    let mode = account.mode();
    account
        .update(issuer, label, replacement_secret, algorithm, digits, mode)
        .map_err(|error| error.to_string())?;

    persist_candidate(session, candidate)
}

fn remove_account(handle: jlong, encoded_id: &str) -> Result<(), String> {
    let handle =
        u64::try_from(handle).map_err(|_| "Native session handle is invalid.".to_owned())?;
    let account_id = parse_account_id(encoded_id)?;

    let mut registry = sessions()
        .lock()
        .map_err(|_| "Native session registry is unavailable.".to_owned())?;
    let session = registry
        .get_mut(&handle)
        .ok_or_else(|| "The native vault session is no longer active.".to_owned())?;

    let candidate_bytes = session
        .accounts
        .encode()
        .map_err(|error| error.to_string())?;
    let mut candidate =
        AccountDatabase::decode(&candidate_bytes).map_err(|error| error.to_string())?;
    if !candidate.remove(&account_id) {
        return Err("The authenticator account no longer exists.".to_owned());
    }

    persist_candidate(session, candidate)
}

fn parse_account_id(encoded: &str) -> Result<[u8; 16], String> {
    let bytes = encoded.as_bytes();
    if bytes.len() != 32 {
        return Err("The account identifier is invalid.".to_owned());
    }

    let mut id = [0_u8; 16];
    for (index, byte) in id.iter_mut().enumerate() {
        let offset = index * 2;
        let high = hex_nibble(bytes[offset])
            .ok_or_else(|| "The account identifier is invalid.".to_owned())?;
        let low = hex_nibble(bytes[offset + 1])
            .ok_or_else(|| "The account identifier is invalid.".to_owned())?;
        *byte = (high << 4) | low;
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
    let handle =
        u64::try_from(handle).map_err(|_| "Native session handle is invalid.".to_owned())?;
    let account_id = parse_account_id(encoded_id)?;
    let mut registry = sessions()
        .lock()
        .map_err(|_| "Native session registry is unavailable.".to_owned())?;
    let session = registry
        .get_mut(&handle)
        .ok_or_else(|| "The native vault session is no longer active.".to_owned())?;

    let candidate_bytes = session
        .accounts
        .encode()
        .map_err(|error| error.to_string())?;
    let mut candidate =
        AccountDatabase::decode(&candidate_bytes).map_err(|error| error.to_string())?;

    let code = {
        let account = candidate
            .get_mut(&account_id)
            .ok_or_else(|| "The authenticator account no longer exists.".to_owned())?;
        if !matches!(account.mode(), AccountMode::Hotp { .. }) {
            return Err("This account does not use HOTP.".to_owned());
        }
        let code = account
            .generate_code(0)
            .map_err(|error| error.to_string())?;
        account
            .advance_hotp_counter()
            .map_err(|error| error.to_string())?;
        code
    };

    // Do not expose the one-time value until the next counter is safely saved.
    persist_candidate(session, candidate)?;
    Ok(code)
}

fn list_account_fields(handle: jlong) -> Result<Vec<String>, String> {
    let handle =
        u64::try_from(handle).map_err(|_| "Native session handle is invalid.".to_owned())?;
    let registry = sessions()
        .lock()
        .map_err(|_| "Native session registry is unavailable.".to_owned())?;
    let session = registry
        .get(&handle)
        .ok_or_else(|| "The native vault session is no longer active.".to_owned())?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "The system clock is before the Unix epoch.".to_owned())?
        .as_secs();
    let mut fields = Vec::with_capacity(session.accounts.len().saturating_mul(5));
    for account in session.accounts.accounts() {
        let id = account
            .id()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let (code, kind) = match account.mode() {
            AccountMode::Totp { period_seconds } => (
                account
                    .generate_code(timestamp)
                    .map_err(|error| error.to_string())?,
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
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
    root: JString<'local>,
) -> jboolean {
    unowned_env
        .with_env(|env| -> jni::errors::Result<jboolean> {
            let root = root.try_to_string(env)?;
            match vault_exists(&root) {
                Ok(true) => Ok(true),
                Ok(false) => Ok(false),
                Err(message) => throw_state_error(env, &message),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_suika_suikaauthenticator_NativeBridge_nativeCreateVault<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
    root: JString<'local>,
    password: JByteArray<'local>,
) -> jlong {
    unowned_env
        .with_env(|env| -> jni::errors::Result<jlong> {
            let root = root.try_to_string(env)?;
            let password = Zeroizing::new(env.convert_byte_array(&password)?);
            match create_vault(&root, &password) {
                Ok(handle) => Ok(handle as jlong),
                Err(message) => throw_state_error(env, &message),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_suika_suikaauthenticator_NativeBridge_nativeUnlockVault<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
    root: JString<'local>,
    password: JByteArray<'local>,
) -> jlong {
    unowned_env
        .with_env(|env| -> jni::errors::Result<jlong> {
            let root = root.try_to_string(env)?;
            let password = Zeroizing::new(env.convert_byte_array(&password)?);
            match unlock_vault(&root, &password) {
                Ok(handle) => Ok(handle as jlong),
                Err(message) => throw_state_error(env, &message),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_suika_suikaauthenticator_NativeBridge_nativeUnlockVaultWithDeviceKey<
    'local,
>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
    root: JString<'local>,
    wrapping_key: JByteArray<'local>,
) -> jlong {
    unowned_env
        .with_env(|env| -> jni::errors::Result<jlong> {
            let root = root.try_to_string(env)?;
            let wrapping_key = Zeroizing::new(env.convert_byte_array(&wrapping_key)?);
            match unlock_vault_with_device_key(&root, &wrapping_key) {
                Ok(handle) => Ok(handle as jlong),
                Err(message) => throw_state_error(env, &message),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_suika_suikaauthenticator_NativeBridge_nativeExportDeviceUnlockKey<
    'local,
>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jbyteArray {
    unowned_env
        .with_env(|env| -> jni::errors::Result<jbyteArray> {
            let key = match export_device_unlock_key(handle) {
                Ok(key) => key,
                Err(message) => return throw_state_error(env, &message),
            };
            Ok(env.byte_array_from_slice(&key[..])?.into_raw())
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_suika_suikaauthenticator_NativeBridge_nativeLockVault<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    unowned_env
        .with_env(|env| -> jni::errors::Result<()> {
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
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_suika_suikaauthenticator_NativeBridge_nativeListAccounts<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jobjectArray {
    unowned_env
        .with_env(|env| -> jni::errors::Result<jobjectArray> {
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
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_suika_suikaauthenticator_NativeBridge_nativeAddTotp<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    issuer: JString<'local>,
    label: JString<'local>,
    encoded_secret: JByteArray<'local>,
    algorithm: jint,
    digits: jint,
    period_seconds: jlong,
) {
    unowned_env
        .with_env(|env| -> jni::errors::Result<()> {
            let issuer = issuer.try_to_string(env)?;
            let label = label.try_to_string(env)?;
            let encoded_secret = Zeroizing::new(env.convert_byte_array(&encoded_secret)?);
            match add_totp(
                handle,
                issuer,
                label,
                &encoded_secret,
                algorithm,
                digits,
                period_seconds,
            ) {
                Ok(()) => Ok(()),
                Err(message) => throw_state_error(env, &message),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_suika_suikaauthenticator_NativeBridge_nativeImportOtpAuthUri<
    'local,
>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    encoded_uri: JByteArray<'local>,
) {
    unowned_env
        .with_env(|env| -> jni::errors::Result<()> {
            let encoded_uri = Zeroizing::new(env.convert_byte_array(&encoded_uri)?);
            match import_otpauth_uri(handle, &encoded_uri) {
                Ok(()) => Ok(()),
                Err(message) => throw_state_error(env, &message),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_suika_suikaauthenticator_NativeBridge_nativeImportAegisExport<
    'local,
>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    encoded_export: JByteArray<'local>,
    encoded_password: JByteArray<'local>,
) -> jni::sys::jstring {
    unowned_env
        .with_env(|env| -> jni::errors::Result<jni::sys::jstring> {
            let encoded_export = Zeroizing::new(env.convert_byte_array(&encoded_export)?);
            let encoded_password = Zeroizing::new(env.convert_byte_array(&encoded_password)?);
            match import_aegis_file(handle, &encoded_export, &encoded_password) {
                Ok((imported, skipped)) => {
                    let summary = format!("{imported}:{skipped}");
                    Ok(JString::from_str(env, &summary)?.into_raw())
                }
                Err(message) => throw_state_error(env, &message),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_suika_suikaauthenticator_NativeBridge_nativeExportBackup<
    'local,
>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    encoded_password: JByteArray<'local>,
) -> jbyteArray {
    unowned_env
        .with_env(|env| -> jni::errors::Result<jbyteArray> {
            let password = Zeroizing::new(env.convert_byte_array(&encoded_password)?);
            let backup = match export_backup(handle, &password) {
                Ok(backup) => backup,
                Err(message) => return throw_state_error(env, &message),
            };
            Ok(env.byte_array_from_slice(&backup)?.into_raw())
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_suika_suikaauthenticator_NativeBridge_nativeRestoreBackup<
    'local,
>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    encoded_backup: JByteArray<'local>,
    encoded_password: JByteArray<'local>,
) -> jint {
    unowned_env
        .with_env(|env| -> jni::errors::Result<jint> {
            let backup = Zeroizing::new(env.convert_byte_array(&encoded_backup)?);
            let password = Zeroizing::new(env.convert_byte_array(&encoded_password)?);
            match restore_backup(handle, &backup, &password) {
                Ok(count) => match jint::try_from(count) {
                    Ok(count) => Ok(count),
                    Err(_) => throw_state_error(env, "The restored account count is invalid."),
                },
                Err(message) => throw_state_error(env, &message),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_suika_suikaauthenticator_NativeBridge_nativeUpdateAccount<
    'local,
>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    account_id: JString<'local>,
    issuer: JString<'local>,
    label: JString<'local>,
    encoded_secret: JByteArray<'local>,
) {
    unowned_env
        .with_env(|env| -> jni::errors::Result<()> {
            let account_id = account_id.try_to_string(env)?;
            let issuer = issuer.try_to_string(env)?;
            let label = label.try_to_string(env)?;
            let encoded_secret = Zeroizing::new(env.convert_byte_array(&encoded_secret)?);
            match update_account(handle, &account_id, issuer, label, &encoded_secret) {
                Ok(()) => Ok(()),
                Err(message) => throw_state_error(env, &message),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_suika_suikaauthenticator_NativeBridge_nativeRemoveAccount<
    'local,
>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    account_id: JString<'local>,
) {
    unowned_env
        .with_env(|env| -> jni::errors::Result<()> {
            let account_id = account_id.try_to_string(env)?;
            match remove_account(handle, &account_id) {
                Ok(()) => Ok(()),
                Err(message) => throw_state_error(env, &message),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_suika_suikaauthenticator_NativeBridge_nativeConsumeHotp<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    account_id: JString<'local>,
) -> jni::sys::jstring {
    unowned_env
        .with_env(|env| -> jni::errors::Result<jni::sys::jstring> {
            let account_id = account_id.try_to_string(env)?;
            match consume_hotp(handle, &account_id) {
                Ok(code) => Ok(JString::from_str(env, &code)?.into_raw()),
                Err(message) => throw_state_error(env, &message),
            }
        })
        .resolve::<ThrowRuntimeExAndDefault>()
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
            let suffix = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
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
    fn provisioning_uri_import_persists_totp_and_hotp_accounts() {
        let temporary = TestDirectory::new();
        let store =
            VaultStore::open(temporary.0.join(APP_DIRECTORY)).expect("vault store should open");
        let accounts = AccountDatabase::new();
        let plaintext = accounts.encode().expect("account database should encode");
        let params = KdfParams::new(64 * 1024, 1, 1).expect("test KDF profile");
        let (serialized, vault) = Vault::create_session(&plaintext, b"test password", params)
            .expect("encrypted vault and unlocked session should be created");
        store
            .save_new(&serialized)
            .expect("initial vault should be saved");
        let handle = insert_session(NativeSession {
            store,
            vault,
            accounts,
        })
        .expect("native session handle should be allocated");

        let secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        import_otpauth_uri(
            handle as jlong,
            format!(
                "otpauth://totp/Example%20Issuer:alice%40example.com?secret={secret}&algorithm=SHA256&digits=8&period=60"
            ).as_bytes(),
        )
        .expect("TOTP provisioning URI should import");
        import_otpauth_uri(
            handle as jlong,
            format!(
                "otpauth://hotp/Example:backup?secret={secret}&counter=9&algorithm=SHA512&digits=7"
            )
            .as_bytes(),
        )
        .expect("HOTP provisioning URI should import");

        let mut registry = sessions()
            .lock()
            .expect("session registry should remain available");
        let session = registry
            .remove(&(handle))
            .expect("native session should remain active");
        assert_eq!(session.accounts.len(), 2);
        let persisted = Vault::unlock(
            &session.store.load().expect("persisted vault should load"),
            b"test password",
        )
        .expect("persisted vault should unlock");
        let restored = AccountDatabase::decode(persisted.plaintext())
            .expect("persisted accounts should decode");
        assert_eq!(restored.len(), 2);
        assert_eq!(restored.accounts()[0].issuer(), "Example Issuer");
        assert_eq!(restored.accounts()[0].label(), "alice@example.com");
        assert_eq!(restored.accounts()[0].algorithm(), OtpAlgorithm::Sha256);
        assert_eq!(
            restored.accounts()[0].mode(),
            AccountMode::Totp { period_seconds: 60 }
        );
        assert_eq!(restored.accounts()[1].issuer(), "Example");
        assert_eq!(restored.accounts()[1].label(), "backup");
        assert_eq!(restored.accounts()[1].algorithm(), OtpAlgorithm::Sha512);
        assert_eq!(
            restored.accounts()[1].mode(),
            AccountMode::Hotp { counter: 9 }
        );
    }

    #[test]
    fn aegis_json_import_is_committed_to_the_encrypted_vault() {
        let temporary = TestDirectory::new();
        let store =
            VaultStore::open(temporary.0.join(APP_DIRECTORY)).expect("vault store should open");
        let accounts = AccountDatabase::new();
        let plaintext = accounts.encode().expect("account database should encode");
        let params = KdfParams::new(64 * 1024, 1, 1).expect("test KDF profile");
        let (serialized, vault) = Vault::create_session(&plaintext, b"test password", params)
            .expect("encrypted vault and unlocked session should be created");
        store
            .save_new(&serialized)
            .expect("initial vault should be saved");
        let handle = insert_session(NativeSession {
            store,
            vault,
            accounts,
        })
        .expect("native session handle should be allocated");

        let export = br#"{
            "version": 1,
            "header": { "slots": null, "params": null },
            "db": {
                "version": 3,
                "entries": [
                    {
                        "type": "totp",
                        "name": "alice@example.com",
                        "issuer": "Example",
                        "favorite": true,
                        "info": {
                            "secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
                            "algo": "SHA256",
                            "digits": 8,
                            "period": 60
                        }
                    },
                    {
                        "type": "steam",
                        "name": "unsupported",
                        "issuer": "Example",
                        "info": {
                            "secret": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
                            "algo": "SHA1",
                            "digits": 5,
                            "period": 30
                        }
                    }
                ]
            }
        }"#;
        assert_eq!(
            import_aegis_file(handle as jlong, export, b"")
                .expect("plaintext Aegis export should import"),
            (1, 1)
        );

        let mut registry = sessions()
            .lock()
            .expect("session registry should remain available");
        let session = registry
            .remove(&handle)
            .expect("native session should remain active");
        assert_eq!(session.accounts.len(), 1);
        let persisted = Vault::unlock(
            &session.store.load().expect("persisted vault should load"),
            b"test password",
        )
        .expect("persisted imported vault should unlock");
        let restored = AccountDatabase::decode(persisted.plaintext())
            .expect("persisted imported accounts should decode");
        assert_eq!(restored.len(), 1);
        assert_eq!(restored.accounts()[0].issuer(), "Example");
        assert_eq!(restored.accounts()[0].label(), "alice@example.com");
        assert_eq!(restored.accounts()[0].algorithm(), OtpAlgorithm::Sha256);
        assert_eq!(restored.accounts()[0].digits(), 8);
        assert_eq!(
            restored.accounts()[0].mode(),
            AccountMode::Totp { period_seconds: 60 }
        );
        assert!(restored.accounts()[0].is_favorite());
    }

    #[test]
    fn invalid_provisioning_uri_does_not_modify_vault() {
        let temporary = TestDirectory::new();
        let store =
            VaultStore::open(temporary.0.join(APP_DIRECTORY)).expect("vault store should open");
        let accounts = AccountDatabase::new();
        let plaintext = accounts.encode().expect("account database should encode");
        let params = KdfParams::new(64 * 1024, 1, 1).expect("test KDF profile");
        let (serialized, vault) = Vault::create_session(&plaintext, b"test password", params)
            .expect("encrypted vault and unlocked session should be created");
        store
            .save_new(&serialized)
            .expect("initial vault should be saved");
        let handle = insert_session(NativeSession {
            store,
            vault,
            accounts,
        })
        .expect("native session should be allocated");

        assert!(
            import_otpauth_uri(handle as jlong, b"otpauth://totp/alice?secret=invalid!").is_err()
        );
        let mut registry = sessions()
            .lock()
            .expect("session registry should remain available");
        let session = registry
            .get(&handle)
            .expect("native session should remain active");
        assert!(session.accounts.is_empty());
        assert!(registry.remove(&handle).is_some());
    }

    #[test]
    fn account_edit_and_removal_are_encrypted_and_preserve_private_state() {
        let temporary = TestDirectory::new();
        let store =
            VaultStore::open(temporary.0.join(APP_DIRECTORY)).expect("vault store should open");
        let mut accounts = AccountDatabase::new();
        let mut account = Account::new_totp(
            "Original issuer",
            "original account",
            Zeroizing::new(b"12345678901234567890".to_vec()),
            OtpAlgorithm::Sha1,
            6,
            30,
        )
        .expect("TOTP account should be valid");
        account
            .set_group(Some("Personal".to_owned()))
            .expect("account group should be set");
        account.set_favorite(true);
        let original_id = *account.id();
        let encoded_id = account
            .id()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let original_code = account
            .generate_code(59)
            .expect("original code should generate");
        accounts.insert(account).expect("account should insert");

        let plaintext = accounts.encode().expect("account database should encode");
        let params = KdfParams::new(64 * 1024, 1, 1).expect("test KDF profile");
        let (serialized, vault) = Vault::create_session(&plaintext, b"test password", params)
            .expect("encrypted vault and unlocked session should be created");
        store
            .save_new(&serialized)
            .expect("initial vault should be saved");
        let handle = insert_session(NativeSession {
            store,
            vault,
            accounts,
        })
        .expect("native session handle should be allocated");

        update_account(
            handle as jlong,
            &encoded_id,
            "Renamed issuer".to_owned(),
            "renamed account".to_owned(),
            b"",
        )
        .expect("metadata-only edit should retain the existing secret");
        {
            let registry = sessions()
                .lock()
                .expect("session registry should remain available");
            let account = &registry
                .get(&handle)
                .expect("native session should remain active")
                .accounts
                .accounts()[0];
            assert_eq!(account.id(), &original_id);
            assert_eq!(account.issuer(), "Renamed issuer");
            assert_eq!(account.label(), "renamed account");
            assert_eq!(account.group(), Some("Personal"));
            assert!(account.is_favorite());
            assert_eq!(
                account
                    .generate_code(59)
                    .expect("existing secret should remain"),
                original_code
            );
        }

        update_account(
            handle as jlong,
            &encoded_id,
            "Replacement issuer".to_owned(),
            "replacement account".to_owned(),
            b"JBSWY3DPEHPK3PXP",
        )
        .expect("a replacement Base32 secret should be accepted");
        {
            let registry = sessions()
                .lock()
                .expect("session registry should remain available");
            let account = &registry
                .get(&handle)
                .expect("native session should remain active")
                .accounts
                .accounts()[0];
            assert_eq!(account.id(), &original_id);
            assert_eq!(account.algorithm(), OtpAlgorithm::Sha1);
            assert_eq!(account.digits(), 6);
            assert_eq!(account.mode(), AccountMode::Totp { period_seconds: 30 });
            assert_ne!(
                account
                    .generate_code(59)
                    .expect("replacement secret should generate"),
                original_code
            );
        }

        remove_account(handle as jlong, &encoded_id).expect("account removal should persist");
        let mut registry = sessions()
            .lock()
            .expect("session registry should remain available");
        let session = registry
            .remove(&handle)
            .expect("test session should still exist");
        assert!(session.accounts.is_empty());
        let persisted = Vault::unlock(
            &session
                .store
                .load()
                .expect("updated encrypted vault should load"),
            b"test password",
        )
        .expect("updated vault should unlock");
        let persisted_accounts = AccountDatabase::decode(persisted.plaintext())
            .expect("persisted account database should decode");
        assert!(persisted_accounts.is_empty());
    }

    #[test]
    fn hotp_is_returned_only_after_the_next_counter_is_persisted() {
        let temporary = TestDirectory::new();
        let store =
            VaultStore::open(temporary.0.join(APP_DIRECTORY)).expect("vault store should open");
        let mut accounts = AccountDatabase::new();
        let account = Account::new_hotp(
            "RFC 4226",
            "test account",
            Zeroizing::new(b"12345678901234567890".to_vec()),
            OtpAlgorithm::Sha1,
            6,
            0,
        )
        .expect("HOTP account should be valid");
        let account_id = account
            .id()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        accounts
            .insert(account)
            .expect("HOTP account should insert");

        let plaintext = accounts.encode().expect("account database should encode");
        let params = KdfParams::new(64 * 1024, 1, 1).expect("test KDF profile");
        let (serialized, vault) = Vault::create_session(&plaintext, b"test password", params)
            .expect("encrypted vault and unlocked session should be created");
        store
            .save_new(&serialized)
            .expect("initial vault should be saved");

        let handle = insert_session(NativeSession {
            store,
            vault,
            accounts,
        })
        .expect("native session handle should be allocated");
        let first = consume_hotp(handle as jlong, &account_id).expect("first HOTP should persist");
        let second =
            consume_hotp(handle as jlong, &account_id).expect("second HOTP should persist");
        assert_eq!(first, "755224");
        assert_eq!(second, "287082");

        let mut registry = sessions()
            .lock()
            .expect("session registry should remain available");
        let session = registry
            .remove(&handle)
            .expect("test session should still exist");
        let persisted = Vault::unlock(
            &session
                .store
                .load()
                .expect("updated encrypted vault should load"),
            b"test password",
        )
        .expect("updated vault should unlock");
        let persisted_accounts = AccountDatabase::decode(persisted.plaintext())
            .expect("persisted account database should decode");
        assert_eq!(
            persisted_accounts.accounts()[0]
                .generate_code(0)
                .expect("next HOTP code"),
            "359152"
        );
    }
}
