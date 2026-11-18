# SuikaAuthenticator

SuikaAuthenticator is a lightweight, offline-first authenticator for Linux and Android, built around a shared Rust security core and native platform interfaces.

## Initial platform targets

- **Linux:** native GTK4 application, initially targeting x86-64.
- **Android:** native Kotlin application with the shared Rust backend integrated through JNI.

The Linux and Android applications share the same OTP implementation, encrypted vault format, key derivation, and backup logic. Platform-specific code is limited to user interface and operating-system integration.

## Security and architecture baseline

- TOTP and HOTP compatibility, including SHA-1, SHA-256, and SHA-512 HMAC algorithms.
- Self-contained encrypted vault; no remote service, cloud account, or OS keyring is required.
- Argon2id password-based key derivation, initially configured for 128 MiB, 3 iterations, and 4 lanes.
- XChaCha20-Poly1305 authenticated encryption with a random 256-bit data-encryption key.
- Optional biometric unlocking on supported Android devices; the master password remains the recovery mechanism.
- Encrypted, portable backups.
- No plaintext vault files or application telemetry.

Cryptographic parameters and the vault format must be reviewed and tested before being treated as production-ready.

## Application data location

All persistent, application-owned user data must stay inside one application-specific directory.

- **Linux:** `~/.SuikaAuthenticator/`
- **Android:** one dedicated application-private directory under the app's internal files area.

Do not scatter application data across XDG configuration, data, or cache directories, or other per-user locations. The Linux directory will contain the encrypted vault, preferences, backups, imports, and any future application-owned persistent files.

## Build downloads

GitHub Actions builds the Linux executable and Android debug APK when their respective projects are present. Build artifacts are uploaded to the workflow run and retained for **one day only**.

To download a build:

1. Open the [Build binaries workflow](https://github.com/GraderGamer2/SuikaAuth/actions/workflows/build.yml).
2. Open the latest successful run.
3. Download `suika-authenticator-linux-x86_64` or `suika-authenticator-android-debug` from the run's **Artifacts** section.

Artifacts require GitHub access to the repository and automatically expire after 1 day. These are temporary CI builds, not permanent GitHub Releases.

See [docs/BUILDING.md](docs/BUILDING.md) for build layout and download details.

## Project status

The repository is being initialized. The CI workflow is prepared for the planned project layout; platform binaries will appear once the Linux and Android application projects have been added.

## License

License selection is pending.
