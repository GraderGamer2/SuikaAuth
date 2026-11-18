# SuikaAuthenticator development roadmap

This is the authoritative project roadmap. Update its checkboxes and the changelog as work is completed. Development follows this order unless a security or correctness issue requires reordering.

Status: **Milestone 3 — encrypted vault container and storage in progress**

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
- [x] Run formatting, tests, and static analysis on CI and correct all findings.
- [ ] Benchmark the production 128 MiB Argon2id profile on Linux and Android hardware.
- [x] Review the core API and cryptographic dependency feature tree in CI.

## 3. Versioned encrypted vault container

- [x] Specify the binary vault header and version negotiation.
- [x] Authenticate version, KDF metadata, and wrapped-key metadata as AEAD associated data.
- [x] Implement random DEK wrapping and password change.
- [x] Implement bounded parsing and clear failure paths.
- [x] Implement versioned account serialization without plaintext disk files, returning zeroizing buffers.
- [ ] Implement atomic saves, file permissions, and crash-safe replacement (implementation added; awaiting CI validation).
- [x] Add corruption, truncation, wrong-password, and KDF-bound tests.
- [ ] Add interrupted-write and crash-recovery tests.

## 4. Linux application

- [ ] Add the native GTK4 Linux frontend.
- [ ] Create and manage ~/.SuikaAuthenticator/ with restrictive permissions.
- [ ] Add first-run vault creation and password unlocking.
- [ ] Add account list, code display, countdown, copy, search, and account management.
- [ ] Add lock-on-inactivity and secure process shutdown.
- [ ] Build an optimized x86-64 release executable and document system runtime dependencies.

## 5. Android application

- [ ] Add the native Kotlin Android frontend.
- [ ] Integrate the same Rust core through JNI.
- [ ] Store all app-owned persistent data inside one private app directory.
- [ ] Add vault setup, unlock, account list, countdown, copy, search, and account management.
- [ ] Add Android Keystore / BiometricPrompt device-bound DEK unlock.
- [ ] Handle biometric enrollment changes and password fallback.
- [ ] Build an installable debug APK for CI.

## 6. Enrollment and migration

- [ ] Add manual TOTP/HOTP enrollment.
- [ ] Parse and validate otpauth URIs.
- [ ] Add camera QR scanning on Android.
- [ ] Add QR image import on Linux.
- [ ] Add migration from Aegis exports and other documented authenticator formats.
- [ ] Validate issuer, account label, secret encoding, algorithm, digits, period, and counter.

## 7. Encrypted backup and restore

- [ ] Define a portable encrypted backup format.
- [ ] Derive backup encryption keys from a user-supplied backup password.
- [ ] Add export, import, restore verification, and clear error handling.
- [ ] Test cross-platform restore between Linux and Android.
- [ ] Ensure backups never contain plaintext OTP secrets.

## 8. Security hardening and release

- [ ] Review threat model and cryptographic implementation.
- [ ] Audit direct and transitive dependencies.
- [ ] Commit and review Cargo.lock.
- [ ] Test file replacement and recovery behavior under interruption.
- [ ] Measure idle RAM, unlocked RAM, binary/APK size, and vault unlock latency.
- [ ] Review logs, crash output, permissions, clipboard behavior, and memory lifetime.
- [ ] Add production signing and release provenance only after the release process is designed.
- [ ] Keep temporary CI build artifacts at exactly one-day retention.

## 9. Future platform expansion

- [ ] Evaluate macOS and Windows frontends using the same vault and Rust core.
- [ ] Preserve vault format compatibility across all supported platforms.

## Definition of done

A milestone is complete only when its implementation, tests, documentation, and CI validation agree. A workflow that skips a missing project is not evidence that the missing application has been built.
