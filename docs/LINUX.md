# Linux frontend

The Linux application is a native GTK4 desktop program implemented in Rust. The executable target is:

    cargo run --release -p suika-authenticator-linux --bin suika-authenticator

The frontend depends on the shared suika-core crate for account parsing, OTP generation, encrypted vault creation, and unlocking. GTK is not a dependency of suika-core.

## First launch

If the vault file does not exist, the application offers first-run setup. It asks for a master password twice, creates an empty versioned account database in zeroizing memory, encrypts it with the production Argon2id profile, and stores the encrypted bytes as vault.bin.

The first-run screen uses a create-only storage operation. If another application instance creates a vault first, the second instance will not replace it.

## Subsequent launches

If vault.bin exists and its public container structure is valid, the application requests the master password. Key derivation and authenticated decryption run on a worker thread, so GTK remains responsive while Argon2id is running.

A successful unlock displays the account list. TOTP codes refresh once per second, HOTP counters are displayed without being advanced automatically, and the user must click Copy to put a code on the desktop clipboard. Lock explicitly drops the unlocked core session.

## Persistent data

The Linux frontend supplies exactly:

    $HOME/.SuikaAuthenticator/

The shared storage layer applies owner-only directory and file permissions on Unix. The frontend does not use XDG configuration, data, or cache paths for application-owned persistent state.

## Current scope

This is the initial functional shell. It supports first-run setup, unlock, a read-only account overview, OTP display, copy, and explicit locking. Manual TOTP/HOTP enrollment, account editing/removal, search, inactivity locking, and password-change UI are not yet implemented.

No password is stored in application settings or command-line arguments. The master password entry is cleared before the worker starts; the worker receives a zeroizing byte buffer. The application does not log passwords, OTP secrets, or generated codes.
