# Vault format version 1

This document specifies the portable encrypted file format implemented by the shared Rust core. The format is platform-independent and does not encode filesystem paths, operating-system keyring references, or device-specific biometric material.

## Binary layout

All integers are unsigned and big-endian. The file contains no optional padding, extension records, or trailing bytes in version 1.

| Offset | Length | Field | Description |
|---:|---:|---|---|
| 0 | 8 | Magic | ASCII bytes `SUIKAVLT` |
| 8 | 2 | Format version | `1` |
| 10 | 1 | KDF identifier | `1` = Argon2id v1.3 |
| 11 | 1 | AEAD identifier | `1` = XChaCha20-Poly1305 |
| 12 | 2 | Flags | Reserved; must be zero |
| 14 | 4 | Argon2 memory | KiB |
| 18 | 4 | Argon2 iterations | Pass count |
| 22 | 4 | Argon2 lanes | Parallelism parameter |
| 26 | 32 | Salt | Random password KDF salt |
| 58 | 24 | DEK-wrap nonce | Random XChaCha20 nonce |
| 82 | 48 | Wrapped DEK | 32-byte DEK plus 16-byte tag |
| 130 | 24 | Payload nonce | Random XChaCha20 nonce |
| 154 | 4 | Payload ciphertext length | Includes 16-byte authentication tag |
| 158 | Variable | Encrypted payload | Encrypted account database |

The fixed header length is 158 bytes. The maximum plaintext payload is 16 MiB; the ciphertext can be at most 16 MiB + 16 bytes.

## Key hierarchy

1. Generate a fresh random 256-bit DEK.
2. Generate a fresh 256-bit salt.
3. Derive a 256-bit KEK from the master password with Argon2id v1.3.
4. Encrypt the DEK with XChaCha20-Poly1305 under the KEK.
5. Encrypt the serialized account payload with XChaCha20-Poly1305 under the DEK.

The initial production profile is 128 MiB, three iterations, and four lanes. The parser accepts only bounded KDF parameter values (64–128 MiB, 1–3 iterations, and 1–4 lanes) and rejects out-of-range fields before invoking Argon2id. These upper bounds prevent an unauthenticated header from requesting more than the application's selected production cost.

## Associated data

DEK-wrap AAD consists of the domain string `SuikaAuthenticator/vault/v1/dek-wrap\0` followed by the complete 58-byte fixed prefix (magic, version, algorithm IDs, flags, Argon2 parameters, and salt).

Payload AAD consists of the domain string `SuikaAuthenticator/vault/v1/payload\0`, the complete 58-byte fixed prefix, the DEK-wrap nonce, the wrapped-DEK ciphertext (including its authentication tag), and the 4-byte payload ciphertext length.

The AEAD nonce for each ciphertext is supplied as the nonce input to XChaCha20-Poly1305. A fresh nonce is generated for every encryption operation.

## Parsing and failure rules

- Reject invalid magic, unsupported version, unsupported algorithm IDs, or nonzero reserved flags.
- Validate Argon2 memory, iteration, and lane values before derivation.
- Reject truncated data, a ciphertext shorter than its authentication tag, oversized payloads, and all trailing bytes.
- Never allocate based on an unchecked attacker-controlled length.
- Wrong passwords and authenticated-content failures return the same generic unlock error.
- Never return partially decrypted content.

## Password changes

A password change opens the existing vault, generates a fresh salt, derives a new KEK, wraps the same random DEK, and encrypts the payload again with fresh nonces. The old password must no longer unlock the newly sealed file.

The binary container API does not perform filesystem writes. Platform frontends must write a new temporary file inside the application-owned directory, flush it, and atomically replace the previous vault only after the new file is complete and validated.

## Compatibility

Version 1 has no migration fields. Future format changes must use a new version and retain explicit parsing rules. Do not silently reinterpret or downgrade unsupported vaults.
