# Dependency policy

SuikaAuthenticator keeps the shared security core small and platform-independent. Dependencies are exact-pinned to reviewed direct versions and enabled features are kept narrow.

## Initial direct dependencies

| Crate | Pinned version | Purpose |
|---|---:|---|
| argon2 | 0.6.0 | Argon2id key derivation |
| chacha20poly1305 | 0.11.0 | XChaCha20-Poly1305 |
| getrandom | 0.4.3 | Operating-system cryptographic randomness |
| hmac | 0.13.0 | HMAC composition for OTP |
| sha1 | 0.11.0 | HMAC-SHA-1 compatibility |
| sha2 | 0.11.1 | HMAC-SHA-256 and HMAC-SHA-512 |
| zeroize | 1.9.0 | Clear sensitive buffers |

All listed cryptographic implementations are pure Rust. The direct versions are exact-pinned in the workspace manifest. A reviewed Cargo.lock must be committed before the first public application build so transitive dependency resolution is reproducible.

## Feature policy

- Disable default features when they are not required.
- Do not enable Argon2's optional parallel/Rayon feature in the initial core.
- Do not enable password-hash PHC string support when only raw key derivation is needed.
- Do not enable QR generation, URL parsing, image processing, HTTP, or serialization in the security core.
- CI runs cargo tree --workspace -e features so the complete enabled dependency feature tree is visible in each successful Rust-core build. Review this output whenever dependencies or features change.

## Rejected by default

No Electron runtime, database server, networking runtime, OpenSSL runtime dependency, analytics SDK, cloud SDK, or mandatory OS keyring integration.

A dependency may be added only when it provides concrete functionality that cannot reasonably be supplied by an existing dependency or a small amount of non-cryptographic application code. Cryptographic primitives must not be reimplemented merely to reduce the dependency count.

## Platform-only dependencies

GTK and its system libraries belong only to the Linux frontend. Kotlin/Android SDK dependencies belong only to the Android frontend. Neither platform UI stack may become a dependency of the shared Rust core.
