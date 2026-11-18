# Changelog

All notable project changes will be recorded here.

## Unreleased

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
