# Portable backup interoperability fixture

`portable_backup_v1.suikabak` is a deterministic, synthetic version-1 backup used by the shared Rust core, Linux frontend, and Android JNI integration tests.

- Test password: `portable-backup-fixture-password`
- KDF profile: Argon2id v1.3, 64 MiB, one iteration, one lane. This is intentionally the minimum accepted test profile, not the production profile.
- Contents: two synthetic accounts from issuer `CrossPlatform`: one TOTP account with SHA-256, eight digits, a 60-second period, favorite=true, and group `Portable`; one HOTP account with SHA-512, seven digits, and counter 9.
- OTP secret bytes, account IDs, DEK, salt, nonces, and backup password are fixed test material only. They do not belong to a real authenticator account.
- The fixture follows the public binary layout in [BACKUP_FORMAT.md](../../../docs/BACKUP_FORMAT.md). Its cryptographic container was generated independently from the Rust `Backup` implementation so restore tests exercise interoperability rather than only self-round-tripping.

The production export code always uses the production 128 MiB / 3-iteration / 4-lane Argon2id profile and fresh operating-system CSPRNG material. Never copy the fixture's password or deterministic key material into production code or real backups.
