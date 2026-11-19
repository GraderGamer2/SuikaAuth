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
- Optional Android device-bound biometric unlock; the master password remains portable recovery.
- Encrypted portable backups.
- No plaintext vault files; no application logging, tracing, profiling, telemetry, or crash-reporting integration.

Read the threat model (docs/THREAT_MODEL.md) and cryptographic design (docs/CRYPTOGRAPHY.md). The current core is an initial implementation and is not yet a production security audit.

## Application data directory

All application-owned persistent user data must stay in one application-specific directory:

- **Linux:** ~/.SuikaAuthenticator/
- **Android:** one dedicated application-private internal directory.

Do not scatter application data across XDG configuration, data, or cache directories, or other per-user locations.

## Development status

See ROADMAP.md for the authoritative implementation sequence and current milestone. The shared Rust core includes RFC-tested TOTP/HOTP generation, bounded RFC 4648 Base32 decoding, an Argon2id/XChaCha20 encrypted vault, a compact versioned account database, and atomic app-directory vault storage. The GTK4 Linux frontend supports first-run vault creation and unlock, live OTP display, TOTP/HOTP enrollment, local QR-image import, plaintext/encrypted Aegis JSON migration, dropdown-based OTP configuration with custom period/counter values, click-to-copy, HOTP counter advancement, local search, account editing/removal, explicit locking, and an automatic five-minute inactivity lock. The Android View-based frontend uses the same vault and Rust core through an isolated JNI library, supports TOTP provisioning-URI import, camera-based QR enrollment, plaintext/encrypted Aegis JSON migration, configurable TOTP enrollment, account listing, safe HOTP consumption, account editing/removal without displaying stored secrets, local account search, optional device-bound biometric unlock, and background locking immediately or after a user-selected 1, 3, 5, or 10 minutes, in addition to its five-minute inactivity lock. Linux and Android Rust release artifacts use opt-level 3 and full LTO with portable target CPU baselines.

## CI downloads

The Build binaries workflow builds the optimized Linux executable and Android debug APK. The Android job cross-compiles the shared Rust core bridge for arm64-v8a and x86_64 before assembling the APK.

Successful build artifacts are available under the workflow run's Artifacts section and expire after **one day**. They are temporary CI downloads, not permanent GitHub Releases.

See docs/BUILDING.md for build details. For supported authenticator export formats, preserved fields, and migration limits, see docs/MIGRATION.md.

## Dependency policy

See docs/DEPENDENCIES.md. Keep the shared core small; platform UI dependencies must not enter it.
