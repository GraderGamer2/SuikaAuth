# SuikaAuthenticator development roadmap

This is the authoritative project roadmap. Update its checkboxes and the changelog as work is completed. Development follows this order unless a security or correctness issue requires reordering.

Status: **Milestone 7 — Encrypted backup and restore (Linux/Android implementation and CI validation complete; cross-platform file-transfer test pending)**

## 1. Repository and architecture foundation

- [x] Establish the public repository and main-branch documentation.
- [x] Record the Linux and Android first-release targets.
- [x] Establish the shared Rust core / native frontend architecture.
- [x] Establish the single application-owned data directory requirement: ~/.SuikaAuthenticator/ on Linux and one app-private directory on Android.
- [x] Add the one-day GitHub Actions artifact workflow.
- [x] Document the initial threat model and dependency policy.
- [x] Create the Rust workspace and initial core crate.

## 2. Cryptographic and OTP core

- [x] Implement bounded Argon2id parameter handling and 256-bit key derivation.
- [x] Implement XChaCha20-Poly1305 encryption/decryption with associated data.
- [x] Add operating-system CSPRNG use for salts, keys, and nonces.
- [x] Add key redaction and zeroization wrappers.
- [x] Implement HOTP and TOTP using HMAC-SHA-1, SHA-256, and SHA-512.
- [x] Add RFC 4226 and RFC 6238 test vectors.
- [x] Add bounded RFC 4648 Base32 decoding with zeroizing input and output buffers.
- [x] Run formatting, tests, and static analysis on CI and correct all findings.
- [ ] Benchmark the production 128 MiB Argon2id profile on Linux and Android hardware.
- [x] Review the core API and cryptographic dependency feature tree in CI.

## 3. Versioned encrypted vault container

- [x] Specify the binary vault header and version negotiation.
- [x] Authenticate version, KDF metadata, and wrapped-key metadata as AEAD associated data.
- [x] Implement random DEK wrapping and password change.
- [x] Implement bounded parsing and clear failure paths.
- [x] Implement versioned account serialization without plaintext disk files, returning zeroizing buffers.
- [x] Implement atomic saves, file permissions, and crash-safe replacement on Linux/Android filesystem semantics.
- [x] Add corruption, truncation, wrong-password, and KDF-bound tests.
- [x] Add interrupted-write failure-path and leftover-temporary-file recovery tests.
- [ ] Perform abrupt process-kill and power-loss durability tests on target Linux and Android filesystems.

## 4. Linux application

- [x] Add the initial native GTK4 Linux frontend.
- [x] Create and manage ~/.SuikaAuthenticator/ with restrictive permissions through the shared vault store.
- [x] Add first-run vault creation and password unlocking.
- [x] Add account list, code display, countdown, and click-to-copy.
- [x] Add manual TOTP account enrollment with Base32 validation and encrypted persistence.
- [x] Add HOTP enrollment and account search.
- [x] Add account editing and removal, preserving stable IDs and never displaying existing secrets.
- [x] Replace OTP mode, algorithm, digit-count, and period/counter free-text controls with dropdown selectors and custom-value support.
- [x] Lock the vault after five minutes without input and on explicit Lock.
- [x] Drop the unlocked session and clear account secret entry fields on window close/application shutdown.
- [x] Build an optimized x86-64 release executable and document system runtime dependencies.

## 5. Android application

- [x] Add the initial native Kotlin Android frontend using platform Views (no Compose/WebView).
- [x] Integrate vault creation, password unlock, TOTP listing/enrollment, HOTP consumption, and explicit session drop through an isolated JNI crate.
- [x] Persist HOTP counter advancement before returning a code for copying.
- [x] Store the Android vault under one noBackupFilesDir/SuikaAuthenticator/ root.
- [x] Add five-minute inactivity locking, foreground/background session cleanup, and local issuer/account search.
- [x] Add configurable background auto-lock (immediate, 1, 3, 5, or 10 minutes), persisted under the Android app-private data root.
- [x] Build and validate installable debug APKs for arm64-v8a and x86_64 in CI.
- [x] Add account editing and removal with stable IDs, retained secrets by default, and explicit removal confirmation.
- [x] Complete broader lifecycle hardening with ViewModel-owned native-session retention, serialized JNI work, foreground/background lock handling, and explicit cleanup.
- [x] Add Android Keystore / BiometricPrompt device-bound KEK unlock using a non-exportable AES-256-GCM key, per-use strong-biometric authorization, and invalidation recovery after biometric or device-security enrollment changes.

## 6. Enrollment and migration

- [x] Add manual TOTP enrollment.
- [x] Add manual HOTP enrollment.
- [x] Parse and validate bounded TOTP/HOTP otpauth URIs, including percent encoding, duplicate rejection, issuer consistency, and OTP parameter validation.
- [x] Add offline Android camera QR scanning using CameraX and a bundled ML Kit QR model; request camera permission only when scanning is started. CI builds the Android APK with the camera model dependency.
- [x] Add local Linux QR image import using GdkPixbuf and the pure-Rust quircs decoder, with image/pixel bounds and single-code validation; the Linux frontend builds in CI.
- [x] Add offline migration from plaintext and password-encrypted Aegis JSON exports on Linux and Android; preserve standard TOTP/HOTP settings, favorites, and one group mapping, and report unsupported Aegis token types. Tests use Aegis's published plaintext and encrypted examples.
- [ ] Add migration from other documented authenticator formats.
- [x] Validate issuer, account label, Base32 secret encoding and length, algorithm, digits, TOTP period, and HOTP counter during URI import.

## 7. Encrypted backup and restore

- [x] Define a portable encrypted backup format; see docs/BACKUP_FORMAT.md.
- [x] Derive backup encryption keys from a user-supplied backup password using the bounded Argon2id profile and a separate random DEK.
- [x] Add Linux and Android export/import UI, transactional restore, and clear error handling; Linux uses mode-0600 atomic file export and Android uses the system document picker. Both workflows are CI-validated.
- [ ] Test cross-platform restore between Linux and Android.
- [x] Ensure backups never contain plaintext OTP secrets; core tests verify encrypted output and authenticated round trips.

## 8. Security hardening and release

- [ ] Review threat model and cryptographic implementation.
- [ ] Audit direct and transitive dependencies.
- [x] Commit the root and Android JNI Cargo-generated Cargo.lock files and verify locked CI builds.
- [x] Test file replacement and recovery behavior under interruption.
- [ ] Perform abrupt process-kill and power-loss durability tests on target Linux and Android filesystems.
- [ ] Measure idle RAM, unlocked RAM, binary/APK size, and vault unlock latency.
- [ ] Review logs, crash output, permissions, clipboard behavior, and memory lifetime.
- [ ] Add production signing and release provenance only after the release process is designed.
- [ ] Keep temporary CI build artifacts at exactly one-day retention.

## 9. Future platform expansion

- [ ] Evaluate macOS and Windows frontends using the same vault and Rust core.
- [ ] Preserve vault format compatibility across all supported platforms.

## Definition of done

A milestone is complete only when its implementation, tests, documentation, and CI validation agree. A workflow that skips a missing project is not evidence that the missing application has been built. Android CI builds and static validation are performed during development; hands-on device validation is intentionally consolidated into the final feature-complete test pass.
