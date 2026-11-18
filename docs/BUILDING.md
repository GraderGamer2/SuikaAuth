# Building and downloading SuikaAuthenticator

## Planned source layout

The build workflow is designed for this layout:

- `Cargo.toml`: root Rust workspace manifest.
- `apps/linux/Cargo.toml`: Linux GTK4 application package.
- `crates/`: shared Rust crates, including OTP and vault logic.
- `android/gradlew`: checked-in Gradle wrapper.
- `android/app/`: Android application module.

The Linux package is expected to produce the executable named `suika-authenticator`. The Android Gradle project is expected to produce `app/build/outputs/apk/debug/app-debug.apk`.

The workflow deliberately detects whether each platform project exists. Until a platform project and its build manifests are committed, its job reports that the target is not initialized rather than failing due to missing source files.

## GitHub Actions builds

Workflow: [Build binaries](../.github/workflows/build.yml)

Triggers:

- Pushes that change application source, manifests, or the workflow on `main`.
- Pull requests that change application source, manifests, or the workflow.
- Manual runs through **Actions → Build binaries → Run workflow**.

The Linux job builds the release executable on an Ubuntu x86-64 runner with GTK4 development headers installed. The resulting executable dynamically links to GTK4 and other system libraries; it is not currently packaged as a fully self-contained Linux image.

The Android job builds an installable **debug APK**. Debug APKs are suitable for development and testing. A production release APK will require a separate, deliberately managed signing process.

## Artifact names and retention

Each successful platform build uploads a separate artifact:

- `suika-authenticator-linux-x86_64`
- `suika-authenticator-android-debug`

Both upload steps set `retention-days: 1`. GitHub therefore deletes each uploaded build artifact after one day. This is an artifact-retention setting, not a permanent release asset.

## Downloading a build

1. Open the repository on GitHub.
2. Select **Actions**.
3. Select the latest **Build binaries** workflow run.
4. In the run summary, locate **Artifacts**.
5. Download the Linux or Android artifact ZIP.

GitHub requires the downloader to be signed in and have repository read access. The artifact download link remains valid only while the artifact exists.

## Reproducibility and integrity

The workflow will build from the checked-out commit and create a SHA-256 checksum file alongside each binary. Keep the artifact and checksum together when verifying a downloaded build.

The workflow is not a signed production release pipeline. Release signing, provenance attestations, and permanent release assets should be designed separately before public production distribution.
