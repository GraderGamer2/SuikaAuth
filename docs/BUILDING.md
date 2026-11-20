# Building and downloading SuikaAuthenticator

## Current Rust core and Linux frontend

The repository contains a Rust workspace with the shared suika-core library and GTK4 Linux frontend. It includes TOTP/HOTP primitives, zeroizing account records and serialization, Argon2id key derivation, XChaCha20-Poly1305, versioned encrypted vaults, and atomic app-directory vault file storage. Every successful Linux CI run performs the following validation before packaging the optimized executable:

    cargo fmt --all -- --check
    cargo test --locked --workspace --all-targets
    cargo clippy --locked --workspace --all-targets -- -D warnings

Rust 1.88 or newer is required by the current dependency baseline. The root rust-toolchain.toml selects the stable channel.

The root and Android JNI Cargo.lock files are committed and include the Aegis-import AES-GCM, scrypt, Base64, and JSON parser dependencies; the Android JNI lockfile was checked against the exact generated lockfile inside the successful debug APK artifact. CI uses --locked for both Rust workspaces' tests, Clippy, dependency inspection, and release builds, so resolved dependency graphs cannot drift without intentional lockfile updates. Direct cryptographic dependencies are exact-pinned.

## Planned application layout

- Cargo.toml: root Rust workspace manifest.
- crates/suika-core/: shared OTP, account database, vault cryptography, and encrypted-vault file storage.
- apps/linux/: native GTK4 Linux application.
- android/app/: native Kotlin application using platform Views.
- android/native/: isolated Rust JNI bridge crate, linked to suika-core without adding JNI dependencies to the shared core.
- android/gradle/: pinned Android Gradle build configuration. CI installs Gradle 9.6.0 with the Gradle Actions setup step.

The Linux package will produce the suika-authenticator executable. The Linux frontend also uses exact-pinned `gdk-pixbuf` 0.21.5 and `quircs` 0.10.3 for bounded local QR image import. The Android Gradle project cross-compiles the isolated Rust JNI bridge for arm64-v8a and x86_64, then produces a debug APK with CameraX 1.7.0 and the bundled ML Kit Barcode Scanning 17.3.0 QR model. Camera permission is requested only when the user starts scanning.

## GitHub Actions

Workflow: .github/workflows/build.yml

Triggers include relevant source pushes to main, pull requests, and manual runs. The Linux job runs Rust formatting, locked workspace tests, locked Clippy, locked dependency feature-tree inspection, and the optimized native executable build. The Linux and Android jobs are configured for real builds. The Android job checks the independent JNI crate's formatting, locked tests, and strict locked Clippy against its committed `android/native/Cargo.lock`; installs pinned SDK/NDK packages; cross-compiles both ABIs with cargo-ndk; and assembles the debug APK with Gradle 9.6.0. The successful debug artifact includes the Android JNI Cargo.lock.

## Artifact names and retention

- suika-authenticator-linux-x86_64 (includes the exact generated Cargo.lock used for that build)
- suika-authenticator-android-debug

Both artifacts use retention-days: 1. GitHub deletes them after one day. This is artifact retention, not a permanent release asset.

To download a build:

1. Open the repository's Build binaries workflow.
2. Open the latest successful run.
3. Download the desired platform artifact from its Artifacts section.

GitHub requires sign-in and repository read access. The artifact expires after one day.

## Measuring the production Argon2id profile

CI publishes standalone benchmark utilities separately from the application artifacts:

- `suika-authenticator-kdf-benchmark-linux-x86_64`
- `suika-authenticator-kdf-benchmark-android` (arm64-v8a and x86_64 binaries)

These are short-lived developer tools, not APKs and not application components. Each binary calls the shared core's `derive_wrapping_key` with `KdfParams::PRODUCTION` (128 MiB, 3 iterations, 4 lanes). It uses a fixed synthetic benchmark password and salt, performs one untimed warm-up, then measures five iterations by default. Pass a sample count from 1 through 20 to override the default. It does not read or modify a vault, access account secrets, or contact a network service.

On Linux, extract the benchmark artifact and run:

    ./suika-argon2-bench
    ./suika-argon2-bench 10

On a physical Android arm64 device, enable USB debugging, extract the Android benchmark artifact, and run the arm64 binary through ADB:

    adb push suika-argon2-bench-android-arm64-v8a /data/local/tmp/suika-argon2-bench
    adb shell chmod 0755 /data/local/tmp/suika-argon2-bench
    adb shell /data/local/tmp/suika-argon2-bench 5

The x86_64 binary is intended for x86_64 Android devices or emulators, not arm64 phones. No APK installation or root access is required.

Record the exact device model, OS version, sample output, and whether battery-saver/thermal throttling was active. Let the device return to a normal temperature between repeated benchmark sessions. Compare medians from the same number of samples and similar thermal/power conditions; CI compilation verifies the binary but does not substitute for measurements on the target hardware. The benchmark uses the production KDF cost and allocates its full working memory, so close memory-intensive applications before running it on devices with limited free RAM.

## Release distinction

Android debug APKs are development builds. A production APK requires deliberate signing configuration. The Linux executable is dynamically linked to GTK4 and required system libraries; it is not currently a fully self-contained Linux package.

Permanent GitHub Releases, signing, and provenance attestations will be designed separately from temporary CI artifacts.


## Android build baseline

- Android Gradle Plugin: 9.4.1 (current stable AGP 9; built-in Kotlin; no separate kotlin-android plugin).
- Gradle: 9.6.0.
- JDK: 17.
- Android platform: API 36 (stable package available in the runner SDK feed).
- SDK Build Tools: 36.0.0.
- NDK: 28.2.13676358.
- Rust JNI targets: aarch64-linux-android and x86_64-linux-android.
- cargo-ndk: 4.1.2.

Install the Android SDK/NDK packages listed above, install Rust stable and the two Android Rust targets, then run:

    cargo install cargo-ndk --version 4.1.2 --locked
    cargo test --locked --manifest-path android/native/Cargo.toml
    cargo clippy --locked --manifest-path android/native/Cargo.toml --all-targets -- -D warnings
    cargo ndk -t arm64-v8a -t x86_64 -o android/app/src/main/jniLibs build --locked --release --manifest-path android/native/Cargo.toml
    gradle --no-daemon -p android assembleDebug

CI uses the same commands and version pins. The generated JNI shared libraries are build outputs and are not committed.


## Optimized release profile and application diagnostics

Both independent Rust workspaces use the same production release settings:

```toml
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
strip = "symbols"
panic = "abort"
```

The root profile applies to Linux. The Android JNI workspace defines its own copy because Cargo profile settings are read from the workspace root. Full/fat LTO optimizes across the linked Rust crates and deliberately increases link time. No `target-cpu=native` or host-specific `target-feature` settings are used. The Linux x86-64 executable and Android arm64-v8a/x86_64 libraries retain the standard portable target baselines.

Application code does not initialize loggers, tracing subscribers, profilers, telemetry, or crash-reporting integrations. The Android JNI workspace compiles the transitive Rust `log` facade at `max_level_off`, and both Rust frontends install an empty panic hook so Rust panic details are not printed by the default hook. Platform frameworks and the operating system may still emit their own diagnostics; those are not application logging and are not globally suppressed.
