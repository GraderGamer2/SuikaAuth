# Account database format version 1

The account database is the plaintext payload inside the encrypted vault. It is a compact, platform-independent binary format implemented directly in the Rust core; it is never a standalone on-disk file.

## Database header

All integers are unsigned and big-endian.

| Offset | Length | Field | Description |
|---:|---:|---|---|
| 0 | 8 | Magic | `SUIKADB\0` |
| 8 | 2 | Version | `1` |
| 10 | 2 | Flags | Reserved; must be zero |
| 12 | 4 | Account count | Maximum 10,000 |

The maximum serialized database size is 8 MiB.

## Account record

Each record starts with a 4-byte big-endian length that counts the bytes following that length field.

| Record offset | Length | Field |
|---:|---:|---|
| 0 | 16 | Random 128-bit account ID |
| 16 | 2 | Record version (1) |
| 18 | 1 | OTP mode: 1 = TOTP, 2 = HOTP |
| 19 | 1 | HMAC: 1 = SHA-1, 2 = SHA-256, 3 = SHA-512 |
| 20 | 1 | OTP digits: 6, 7, or 8 |
| 21 | 1 | Flags: bit 0 = favorite; all other bits reserved |
| 22 | 8 | TOTP period in seconds or HOTP counter |
| 30 | 2 | Issuer UTF-8 byte length |
| 32 | 2 | Account-label UTF-8 byte length |
| 34 | 2 | Group UTF-8 byte length; zero means no group |
| 36 | 2 | Secret byte length |
| 38 | Variable | Issuer, label, group, then raw secret bytes |

The fixed record header is 38 bytes, excluding the outer 4-byte record length.

## Validation limits

- Maximum 10,000 accounts.
- Maximum database size: 8 MiB.
- Issuer: 0–256 UTF-8 bytes.
- Account label: 1–256 UTF-8 bytes.
- Group: 0–128 UTF-8 bytes.
- Secret: 1–128 bytes.
- OTP digits: 6, 7, or 8.
- TOTP period: 1–86,400 seconds.
- Account IDs must be unique.
- Unknown modes, algorithms, versions, reserved flags, invalid UTF-8, truncated records, and trailing database bytes are rejected.

All record lengths are validated before slicing or allocating field buffers. The decoder does not trust account count or field lengths beyond the fixed limits above.

## Memory handling

Account secrets are owned in zeroizing buffers. Database encoding returns a zeroizing buffer so the serialized secret-bearing bytes are cleared when dropped. The encrypted vault is the only persistent representation; the account database must never be written to a plaintext file.

## Compatibility

Future incompatible database structures must increment the database version or record version. Version 1 rejects unknown record versions rather than guessing how to interpret them.
