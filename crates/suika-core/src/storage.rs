//! Small, dependency-free encrypted-vault file storage.
//!
//! The caller supplies the one application-owned directory. On Linux the
//! frontend must pass `$HOME/.SuikaAuthenticator`; Android must pass its
//! single app-private internal files directory. This module never chooses an
//! XDG path and never creates plaintext account-data files.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::vault::{MAX_VAULT_FILE_BYTES, MIN_VAULT_FILE_BYTES, VAULT_MAGIC};

const VAULT_FILENAME: &str = "vault.bin";
const TEMP_NAME_ATTEMPTS: usize = 8;
const TEMP_RANDOM_BYTES: usize = 16;

/// File-storage failures. Messages never contain vault contents.
#[derive(Debug)]
pub enum StorageError {
    /// The supplied application directory was not an absolute path.
    DirectoryMustBeAbsolute,
    /// The application directory or vault path is a symlink or unexpected file type.
    UnsafePath,
    /// The vault file does not exist.
    VaultNotFound,
    /// The vault file is structurally too small, too large, or has invalid magic.
    InvalidVaultFile,
    /// The file exceeds the configured maximum size.
    VaultTooLarge,
    /// The OS random source could not generate a temporary filename.
    RandomnessUnavailable,
    /// A storage operation failed.
    Io(std::io::Error),
}

impl core::fmt::Display for StorageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DirectoryMustBeAbsolute => {
                f.write_str("application storage directory must be an absolute path")
            }
            Self::UnsafePath => {
                f.write_str("application storage path is not a safe directory or regular file")
            }
            Self::VaultNotFound => f.write_str("encrypted vault file does not exist"),
            Self::InvalidVaultFile => f.write_str("encrypted vault file is malformed"),
            Self::VaultTooLarge => f.write_str("encrypted vault exceeds the supported size"),
            Self::RandomnessUnavailable => {
                f.write_str("operating-system randomness is unavailable")
            }
            Self::Io(error) => write!(f, "vault storage operation failed: {error}"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<std::io::Error> for StorageError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Storage rooted inside one application-owned directory.
///
/// This type stores only encrypted vault bytes. It does not serialize accounts,
/// derive keys, or expose plaintext files.
pub struct VaultStore {
    directory: PathBuf,
    vault_path: PathBuf,
}

impl VaultStore {
    /// Open or create the supplied application-owned directory.
    ///
    /// The directory must be absolute. It is created if missing and restricted
    /// to the current user on Unix (mode 0700). Existing symlinks and non-
    /// directory paths are rejected.
    ///
    /// The Linux frontend must pass the exact path
    /// `$HOME/.SuikaAuthenticator`. Android must pass one dedicated private
    /// internal app directory. Do not pass XDG config/data/cache directories.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, StorageError> {
        let directory = directory.as_ref();

        if !directory.is_absolute() {
            return Err(StorageError::DirectoryMustBeAbsolute);
        }

        match fs::symlink_metadata(directory) {
            Ok(metadata) => validate_directory_metadata(&metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(directory)?;
            }
            Err(error) => return Err(StorageError::Io(error)),
        }

        let metadata = fs::symlink_metadata(directory)?;
        validate_directory_metadata(&metadata)?;
        restrict_directory_permissions(directory)?;

        Ok(Self {
            directory: directory.to_path_buf(),
            vault_path: directory.join(VAULT_FILENAME),
        })
    }

    /// Return the application-owned storage directory.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Return the fixed encrypted vault path.
    #[must_use]
    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    /// Read the encrypted vault into memory.
    ///
    /// The file is never copied to a temporary plaintext location. The loaded
    /// bytes are ciphertext and must be passed to `Vault::unlock`.
    pub fn load(&self) -> Result<Vec<u8>, StorageError> {
        let path_metadata = match fs::symlink_metadata(&self.vault_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(StorageError::VaultNotFound);
            }
            Err(error) => return Err(StorageError::Io(error)),
        };
        validate_file_metadata(&path_metadata)?;

        let file = OpenOptions::new().read(true).open(&self.vault_path)?;
        let opened_metadata = file.metadata()?;
        validate_file_metadata(&opened_metadata)?;
        ensure_same_file(&path_metadata, &opened_metadata)?;

        restrict_open_file_permissions(&file)?;
        let file_len =
            usize::try_from(opened_metadata.len()).map_err(|_| StorageError::VaultTooLarge)?;
        validate_vault_size(file_len)?;

        let read_limit = u64::try_from(MAX_VAULT_FILE_BYTES)
            .map_err(|_| StorageError::VaultTooLarge)?
            .saturating_add(1);
        let mut bytes = Vec::with_capacity(file_len);
        file.take(read_limit).read_to_end(&mut bytes)?;

        if bytes.len() != file_len {
            return Err(StorageError::InvalidVaultFile);
        }
        validate_vault_bytes(&bytes)?;

        Ok(bytes)
    }

    /// Atomically replace the encrypted vault file.
    ///
    /// The new bytes are written to a unique temporary file in the same
    /// directory, flushed to storage, and then renamed over `vault.bin`.
    /// On Linux and Android (Unix filesystems), the rename is atomic. The old
    /// vault remains intact if writing or syncing the temporary file fails.
    ///
    /// The temporary file is mode 0600; the directory is mode 0700. After
    /// rename, the containing directory is synced to make the directory entry
    /// durable across a crash where the filesystem supports directory fsync.
    pub fn save(&self, encrypted_vault: &[u8]) -> Result<(), StorageError> {
        validate_vault_bytes(encrypted_vault)?;

        let (temporary_path, mut temporary_file) = self.create_temporary_file()?;
        let mut cleanup = PendingFile::new(temporary_path);

        temporary_file.write_all(encrypted_vault)?;
        temporary_file.sync_all()?;
        drop(temporary_file);

        fs::rename(cleanup.path(), &self.vault_path)?;
        cleanup.commit();

        // The rename has happened at this point. If directory sync fails,
        // report the durability uncertainty rather than claiming the write
        // was durably committed.
        File::open(&self.directory)?.sync_all()?;

        Ok(())
    }

    fn create_temporary_file(&self) -> Result<(PathBuf, File), StorageError> {
        for _ in 0..TEMP_NAME_ATTEMPTS {
            let mut random = [0_u8; TEMP_RANDOM_BYTES];
            getrandom::fill(&mut random).map_err(|_| StorageError::RandomnessUnavailable)?;

            let suffix = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let path = self.directory.join(format!(".vault.tmp-{suffix}"));

            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            restrict_new_file_permissions(&mut options);

            match options.open(&path) {
                Ok(file) => return Ok((path, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(StorageError::Io(error)),
            }
        }

        Err(StorageError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate a unique temporary vault filename",
        )))
    }
}

struct PendingFile {
    path: PathBuf,
    committed: bool,
}

impl PendingFile {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for PendingFile {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn validate_directory_metadata(metadata: &Metadata) -> Result<(), StorageError> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StorageError::UnsafePath);
    }
    Ok(())
}

fn validate_file_metadata(metadata: &Metadata) -> Result<(), StorageError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StorageError::UnsafePath);
    }
    Ok(())
}

fn ensure_same_file(before: &Metadata, after: &Metadata) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(StorageError::UnsafePath);
        }
    }

    #[cfg(not(unix))]
    {
        if before.len() != after.len() {
            return Err(StorageError::UnsafePath);
        }
    }

    Ok(())
}

fn validate_vault_size(length: usize) -> Result<(), StorageError> {
    if length < MIN_VAULT_FILE_BYTES {
        return Err(StorageError::InvalidVaultFile);
    }
    if length > MAX_VAULT_FILE_BYTES {
        return Err(StorageError::VaultTooLarge);
    }
    Ok(())
}

fn validate_vault_bytes(bytes: &[u8]) -> Result<(), StorageError> {
    validate_vault_size(bytes.len())?;
    if bytes.get(..VAULT_MAGIC.len()) != Some(VAULT_MAGIC.as_slice()) {
        return Err(StorageError::InvalidVaultFile);
    }

    crate::vault::Vault::validate_serialized(bytes).map_err(|_| StorageError::InvalidVaultFile)
}

#[cfg(unix)]
fn restrict_directory_permissions(path: &Path) -> Result<(), StorageError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_directory_permissions(_path: &Path) -> Result<(), StorageError> {
    Ok(())
}

#[cfg(unix)]
fn restrict_open_file_permissions(file: &File) -> Result<(), StorageError> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_open_file_permissions(_file: &File) -> Result<(), StorageError> {
    Ok(())
}

#[cfg(unix)]
fn restrict_new_file_permissions(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.mode(0o600);
}

#[cfg(not(unix))]
fn restrict_new_file_permissions(_options: &mut OpenOptions) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::vault::Vault;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let mut random = [0_u8; 12];
            getrandom::fill(&mut random).expect("system random source should be available");
            let suffix = random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let path = std::env::temp_dir().join(format!("suika-storage-test-{suffix}"));
            fs::create_dir(&path).expect("test directory should be created");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn test_vault(payload: &[u8], password: &[u8]) -> Vec<u8> {
        let params = KdfParams::new(64 * 1024, 1, 1).expect("test KDF profile");
        Vault::create(payload, password, params).expect("test vault should be created")
    }

    #[test]
    fn creates_restricts_and_reopens_the_application_directory() {
        let temporary = TestDirectory::new();
        let app_dir = temporary.0.join(".SuikaAuthenticator");
        let store = VaultStore::open(&app_dir).expect("app directory should be created");

        assert_eq!(store.directory(), app_dir);
        assert!(store.directory().is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&app_dir)
                    .expect("directory metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }

        VaultStore::open(&app_dir).expect("existing app directory should open");
    }

    #[test]
    fn saves_and_loads_only_encrypted_vault_bytes() {
        let temporary = TestDirectory::new();
        let store = VaultStore::open(temporary.0.join(".SuikaAuthenticator"))
            .expect("app directory should open");
        let serialized = test_vault(b"account database", b"test password");

        store.save(&serialized).expect("vault should save");
        let loaded = store.load().expect("vault should load");
        assert_eq!(loaded, serialized);

        let unlocked =
            Vault::unlock(&loaded, b"test password").expect("loaded vault should unlock");
        assert_eq!(unlocked.plaintext(), b"account database");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(store.vault_path())
                    .expect("vault metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn replacement_preserves_a_valid_vault() {
        let temporary = TestDirectory::new();
        let store = VaultStore::open(temporary.0.join(".SuikaAuthenticator"))
            .expect("app directory should open");
        let original = test_vault(b"original", b"password");
        let replacement = test_vault(b"replacement", b"password");

        store.save(&original).expect("original vault should save");
        store
            .save(&replacement)
            .expect("replacement vault should save");

        let loaded = store.load().expect("replacement should load");
        assert_eq!(
            Vault::unlock(&loaded, b"password")
                .expect("replacement should unlock")
                .plaintext(),
            b"replacement"
        );
    }

    #[test]
    fn invalid_or_oversized_input_never_replaces_existing_vault() {
        let temporary = TestDirectory::new();
        let store = VaultStore::open(temporary.0.join(".SuikaAuthenticator"))
            .expect("app directory should open");
        let original = test_vault(b"preserve me", b"password");
        store.save(&original).expect("original vault should save");

        assert!(matches!(
            store.save(b"not a vault"),
            Err(StorageError::InvalidVaultFile)
        ));

        let mut invalid_header = test_vault(b"invalid header", b"password");
        invalid_header[8..10].copy_from_slice(&99_u16.to_be_bytes());
        assert!(matches!(
            store.save(&invalid_header),
            Err(StorageError::InvalidVaultFile)
        ));

        let oversized = vec![0_u8; MAX_VAULT_FILE_BYTES + 1];
        assert!(matches!(
            store.save(&oversized),
            Err(StorageError::VaultTooLarge)
        ));

        assert_eq!(store.load().expect("original remains"), original);
    }

    #[test]
    fn refuses_symlinked_directories_and_vault_files() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let temporary = TestDirectory::new();
            let real_directory = temporary.0.join("real");
            fs::create_dir(&real_directory).expect("real directory");
            let linked_directory = temporary.0.join(".SuikaAuthenticator");
            symlink(&real_directory, &linked_directory).expect("directory symlink");

            assert!(matches!(
                VaultStore::open(&linked_directory),
                Err(StorageError::UnsafePath)
            ));

            let store = VaultStore::open(real_directory.clone()).expect("open real directory");
            let outside_file = temporary.0.join("outside.bin");
            fs::write(&outside_file, b"do not follow").expect("outside file");
            symlink(&outside_file, store.vault_path()).expect("vault file symlink");

            assert!(matches!(store.load(), Err(StorageError::UnsafePath)));
        }
    }

    #[test]
    fn rejects_relative_storage_directories() {
        assert!(matches!(
            VaultStore::open("relative-path"),
            Err(StorageError::DirectoryMustBeAbsolute)
        ));
    }
}
