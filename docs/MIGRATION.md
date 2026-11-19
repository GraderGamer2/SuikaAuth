# Authenticator migration

SuikaAuthenticator supports local migration from Aegis JSON exports and plaintext newline-delimited provisioning-URI text exports on Linux and Android. Both frontends validate entries through the shared Rust core and save imported accounts through the existing encrypted Suika vault. Source files are never changed or uploaded.

## Plaintext provisioning-URI text exports

The app imports text exports containing one standard `otpauth://` TOTP or HOTP URI per non-empty line. This supports the documented Ente Auth plaintext export format, as well as compatible URI-list text files from other authenticators.

- UTF-8 text is required. A leading UTF-8 BOM, CRLF/LF line endings, and blank lines are accepted.
- Every non-empty line must be a valid standard TOTP or HOTP provisioning URI. One invalid line rejects the entire import; the app does not silently skip entries or partially import the file.
- The existing shared URI parser enforces the 4,096-byte per-URI limit, supported HMAC algorithms, 6–8 digits, Base32 secret length, issuer consistency, and TOTP/HOTP mode parameters.
- The entire source file is limited to 16 MiB and 10,000 entries.
- Linux and Android read the selected file into a bounded zeroizing memory buffer. The source file is not modified or deleted.
- Imported accounts are merged into a candidate account database and persisted only after every line validates and the encrypted vault save succeeds.

**Important:** this is a plaintext export format. The text file contains the OTP provisioning URIs, including secret keys. Import only from a trusted location and securely delete the plaintext file after verifying the migration. SuikaAuthenticator does not currently import Ente's separately encrypted JSON export; that format requires its own documented container and key-derivation implementation and is not treated as a URI-list text file.

Upstream references: [Ente Auth migration/export documentation](https://github.com/ente-io/ente/blob/main/docs/docs/auth/migration/export.md) and [Ente CLI authentication export](https://ente.com/help/cli/auth).

## Supported Aegis exports

- Aegis vault file format version 1.
- Plaintext JSON exports.
- Password-encrypted JSON exports that contain at least one Aegis password slot.
- Inner Aegis account database versions 1, 2, and 3.
- Standard TOTP and HOTP entries using SHA1, SHA256, or SHA512 with 6–8 digits.
- TOTP periods and HOTP counters are preserved and validated by the shared account model.

Encrypted exports use the Aegis password slot format: scrypt derives a wrapping key from the export password, AES-256-GCM unwraps Aegis's random 256-bit database key, and AES-256-GCM decrypts the account database. The importer follows Aegis's published file format and decryption procedure. Passwords are interpreted as UTF-8, as in Aegis.

An encrypted export must have a password-based slot. Device-local biometric credentials are not portable and cannot be used by this importer. When exporting from Aegis, choose a password-protected export or make a plaintext JSON export.

## Imported and skipped data

Standard TOTP/HOTP entries are converted to new Suika account records with new Suika-generated IDs. The issuer, account label, HMAC algorithm, digits, TOTP period or HOTP counter, favorite flag, and one group assignment are retained. If an older Aegis record uses the legacy single group field, that group is retained. If a record belongs to multiple Aegis groups, the first group that can be resolved is retained because the current Suika account model has one group field.

Aegis-only token types such as Steam, MOTP, and Yandex are not standard TOTP/HOTP. They are skipped and included in the import summary rather than converted into incorrect codes. Entries with algorithms or digit settings outside Suika's supported range are also skipped. Unsupported token secrets are not decoded or retained. Aegis notes and custom icons are not imported because the current Suika account model does not yet have corresponding fields.

Importing the same file more than once creates additional accounts; the importer does not guess whether two entries with the same name are duplicates.

## Resource and security bounds

- Source export: maximum 16 MiB.
- Decrypted account database: maximum 8 MiB.
- Entries and groups: maximum 10,000 each.
- Vault slots: maximum 16 in total and four password slots.
- Export password: maximum 4,096 bytes of UTF-8 input.
- scrypt: at most 128 MiB memory, at most 2,097,152 units of (N \times r \times p) work, (r \leq 8), and (p \leq 4).
- Nonces, authentication tags, salts, wrapped keys, and Base64 payloads are length-checked before decryption.

The source JSON, decrypted database, export password, KDF output, decoded OTP secrets, and temporary binary buffers are held in zeroizing allocations where they contain plaintext secret material. On Android, file and password bytes cross JNI as byte arrays and are cleared after the native operation. On Linux, the file and password are processed on a worker thread. The importer does not initialize a logger, contact a network service, or write plaintext token data to disk.

All supported entries are first added to an in-memory candidate account database. The candidate is persisted only after the entire export has parsed, every supported record validates, and the normal encrypted Suika vault save succeeds. A malformed entry, wrong password, resource-limit failure, or save error does not commit a partial import.

## Upstream format references

- [Aegis vault file format](https://github.com/beemdevelopment/Aegis/blob/master/docs/vault.md)
- [Aegis reference decryption procedure](https://github.com/beemdevelopment/Aegis/blob/master/docs/decrypt.py)
- [Aegis vault JSON parser](https://github.com/beemdevelopment/Aegis/blob/master/app/src/main/java/com/beemdevelopment/aegis/vault/VaultFile.java)
- [Aegis password slot implementation](https://github.com/beemdevelopment/Aegis/blob/master/app/src/main/java/com/beemdevelopment/aegis/vault/slots/PasswordSlot.java)


The core test suite also imports Aegis's published plaintext and password-encrypted example fixtures. The encrypted upstream test fixture uses the sample password `test`; these fixtures are test data only and must never be used as production credentials.
