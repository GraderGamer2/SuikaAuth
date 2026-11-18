# Vault file storage

SuikaAuthenticator stores its encrypted vault in one application-owned directory. The shared Rust storage module accepts that directory from the platform frontend; it does not choose XDG locations or create alternate data roots.

## Required platform roots

- Linux: $HOME/.SuikaAuthenticator/
- Android: one dedicated app-private internal files directory supplied by the Android frontend.

Every future persistent application file (preferences, backups, imports, recovery data) must remain below the same platform root. Do not split data across XDG config/data/cache folders or other per-user locations.

## Files

The initial storage layer uses:

- vault.bin: the encrypted vault only.
- .vault.tmp-<random>: a short-lived encrypted temporary file created in the same directory during atomic replacement.

No plaintext account database is ever written to disk. The account database exists as a zeroizing buffer in memory and is encrypted before storage.

## Permission policy

On Unix platforms, the application directory is set to mode 0700 and the vault/temporary file to mode 0600. Existing vault permissions are tightened when loaded. Android internal files are already app-private; the Rust implementation also applies Unix file modes where supported.

## Atomic save sequence

1. Validate the byte length and vault magic.
2. Generate a random temporary filename using the OS cryptographic random source.
3. Create the temporary file with exclusive creation and mode 0600.
4. Write all encrypted vault bytes.
5. Call sync_all on the file.
6. Rename the temporary file over vault.bin in the same directory.
7. Call sync_all on the containing directory.

Because the temporary file is in the same directory, the rename is atomic on the Linux and Android filesystems targeted by the first releases. If writing or syncing the temporary file fails before rename, the old vault remains untouched and the temporary file is removed. If directory sync fails after rename, the method reports the durability uncertainty even though the rename has already occurred.

## Path and file validation

- The supplied directory must be absolute.
- The final directory component may not be a symlink or non-directory.
- The vault path must be a regular file, not a symlink.
- On Unix, the opened file identity is compared with the prior symlink_metadata result to detect path substitution between checking and opening.
- Vault reads are bounded by the version 1 maximum container size.
- The storage layer checks the vault magic; cryptographic and complete format validation occurs when the core unlocks the vault.

The storage layer does not defend against a fully compromised process or a malicious actor running under the same user identity who can continuously race filesystem operations. Its scope is safe ordinary operation, accidental corruption resistance, and protection against common path/file mistakes.
