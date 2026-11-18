# Changelog

All notable project changes will be recorded here.

## Unreleased

- Added the dependency-free vault file store using caller-supplied application-owned directories, bounded reads, restrictive Unix permissions, temporary-file cleanup, and atomic replacement.
- Added storage tests for encrypted-vault round trips, replacement, invalid-input preservation, directory permissions, relative paths, and symlink rejection.
- Added failure-injection coverage for an interrupted save before rename and restart behavior with a leftover partial temporary file.
- Added a compact versioned account database with TOTP/HOTP parameters, issuer/label/group metadata, favorites, and random account IDs.
- Added zeroizing account-secret ownership and zeroizing encoded database buffers without adding a serialization framework dependency.
- Added account database round-trip, TOTP/HOTP generation, counter advancement, malformed header, version, and UTF-8 validation tests.
- Added the initial versioned encrypted vault container with Argon2id-wrapped DEK and XChaCha20-Poly1305 payload encryption.
- Added bounded vault parsing, authenticated header metadata, generic unlock failures, and password-change support.
- Added vault round-trip, tampering, wrong-password, truncation, KDF-bound, and payload-size tests.
- Capped vault-header Argon2id parameters at 128 MiB and three passes to limit pre-authentication resource consumption.
- Wrapped the temporary decrypted DEK copy in zeroizing memory.
- Verified the shared Rust core with formatting, all tests, and strict Clippy in GitHub Actions.

- Added the authoritative development roadmap.
- Added the initial Rust workspace and shared suika-core crate.
- Implemented bounded Argon2id key derivation using the selected 128 MiB / 3-iteration / 4-lane profile.
- Implemented XChaCha20-Poly1305 authenticated encryption and zeroizing decrypted buffers.
- Added CSPRNG-backed salt, key, and nonce generation.
- Added HOTP/TOTP generation with SHA-1, SHA-256, and SHA-512 HMAC.
- Added RFC 4226 and RFC 6238 test vectors.
- Documented the threat model, cryptographic design, and dependency policy.
- Updated CI to run Rust formatting and core tests before the platform frontends exist.
- Preserved the one-day GitHub Actions artifact retention policy.
