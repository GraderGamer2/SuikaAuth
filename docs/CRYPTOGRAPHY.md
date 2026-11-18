# Cryptographic design

Status: initial implementation baseline. This document is not a third-party security audit.

## Password-based key derivation

Use Argon2id (version 1.3 / 0x13) to derive a 256-bit key-encryption key from the user's master password.

Initial production parameters:

| Parameter | Value |
|---|---:|
| Memory | 131,072 KiB (128 MiB) |
| Iterations | 3 |
| Lanes | 4 |
| Output | 32 bytes |
| Salt | 32 random bytes |

The first implementation deliberately does not enable Argon2's optional Rayon parallel feature. The lane parameter remains four, but the core crate avoids adding a separate parallel runtime. Unlock latency must be measured on real Linux and Android hardware before release.

KDF parameters are validated and bounded before invoking Argon2. The current accepted range is 64–256 MiB, 1–10 iterations, and 1–4 lanes. The serialized vault format must store the parameters needed to reproduce the key derivation. Never trust unvalidated KDF values from a file.

Use the raw key-derivation API (hash_password_into), not password-hash string formatting, because the output is a wrapping key rather than a password-verifier string.

## Key hierarchy

- Generate a random 256-bit data-encryption key (DEK).
- Encrypt account records with the DEK.
- Derive a key-encryption key (KEK) from the master password and random salt.
- Encrypt/wrap the DEK with the KEK.
- Rewrapping the DEK allows password changes without re-encrypting account records.

The DEK is not derived from the password. This separates the password KDF from bulk vault encryption.

## Vault encryption

Use XChaCha20-Poly1305:

- 256-bit key.
- 192-bit nonce.
- 128-bit authentication tag.
- Associated data binds the encrypted payload to its format/version and relevant header fields.

Generate a fresh nonce from the operating-system CSPRNG for every encryption. Never reuse a nonce with the same key. Authentication failure must be treated as a hard decryption failure; never return partially decrypted content.

The RustCrypto implementation is pure Rust and exposes XChaCha20-Poly1305. The algorithm choice and implementation version must be recorded in the versioned vault format.

## Randomness

Use the operating system's cryptographically secure random source through getrandom for:

- Vault salts.
- DEKs.
- AEAD nonces.
- Future recovery material.

Randomness failure is fatal to the operation. Do not fall back to timestamps, process IDs, counters, or home-grown generators.

## OTP compatibility

HOTP/TOTP uses HMAC-SHA-1, HMAC-SHA-256, or HMAC-SHA-512 as selected by the account parameters. SHA-1 remains available for compatibility with common services; it is not used as the vault encryption primitive or password KDF.

The OTP implementation must pass RFC 4226 and RFC 6238 test vectors, including the SHA-1, SHA-256, and SHA-512 cases.

## Memory handling

- SecretKey does not implement Clone and redacts its Debug output.
- Key material is zeroized on drop.
- Decrypted AEAD output is returned in a zeroizing buffer.
- Argon2's internal working memory zeroization feature is enabled.
- These measures reduce exposure; they do not guarantee that every copy of sensitive material is erased from the entire system.

## Cryptographic dependencies

The implementation uses focused RustCrypto crates. Optional QR, URL parsing, serialization, GUI, and platform integration dependencies must not be pulled into the cryptographic core unless a concrete requirement justifies them.
