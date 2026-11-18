# SuikaAuthenticator

SuikaAuthenticator is a lightweight, offline-first authenticator for Linux and Android. It uses a shared Rust security core with native platform interfaces.

## Initial platforms

- **Linux:** native GTK4 application, initially x86-64.
- **Android:** native Kotlin application using the shared Rust backend through JNI.

Both applications share the same OTP implementation, cryptographic primitives, vault format, and backup logic.

## Security baseline

- TOTP and HOTP with HMAC-SHA-1, SHA-256, and SHA-512.
- Self-contained encrypted vault; no cloud account, remote service, or mandatory OS keyring.
- Argon2id password-derived wrapping key: 128 MiB, 3 iterations, 4 lanes.
- XChaCha20-Poly1305 authenticated encryption with a random 256-bit data-encryption key.
- Optional Android biometric unlock; the master password remains the recovery method.
- Encrypted portable backups.
- No plaintext vault files or application telemetry.

Read the threat model (docs/THREAT_MODEL.md) and cryptographic design (docs/CRYPTOGRAPHY.md). The current core is an initial implementation and is not yet a production security audit.

## Application data directory

All application-owned persistent user data must stay in one application-specific directory:

- **Linux:** ~/.SuikaAuthenticator/
- **Android:** one dedicated application-private internal directory.

Do not scatter application data across XDG configuration, data, or cache directories, or other per-user locations.

## Development status

See ROADMAP.md for the authoritative implementation sequence and current milestone. The shared Rust core includes RFC-tested TOTP/HOTP generation, an Argon2id/XChaCha20 encrypted vault, a compact versioned account database, and an app-directory vault file store. CI checks formatting, tests, Clippy, and the enabled dependency feature tree. Linux and Android interfaces follow the vault/storage work.

## CI downloads

The Build binaries workflow is configured to build the Linux executable and Android debug APK once the platform projects exist.

Successful build artifacts are available under the workflow run's Artifacts section and expire after **one day**. They are temporary CI downloads, not permanent GitHub Releases.

See docs/BUILDING.md for build details.

## Dependency policy

See docs/DEPENDENCIES.md. Keep the shared core small; platform UI dependencies must not enter it.
