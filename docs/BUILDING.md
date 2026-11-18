# Building and downloading SuikaAuthenticator

## Current Rust core

The repository contains a Rust workspace with the shared suika-core library. It includes TOTP/HOTP primitives, zeroizing account records and serialization, Argon2id key derivation, XChaCha20-Poly1305, versioned encrypted vaults, and atomic app-directory vault file storage. The core CI validation currently passes 36 tests, formatting, strict Clippy, and dependency feature inspection:

    cargo fmt --all -- --check
    cargo test --workspace

Rust 1.88 or newer is required by the current dependency baseline. The root rust-toolchain.toml selects the stable channel.

A reviewed Cargo.lock is still required before the first public application build. Direct cryptographic dependencies are exact-pinned while the core is under active development.

## Planned application layout

- Cargo.toml: root Rust workspace manifest.
- crates/suika-core/: shared OTP, account database, vault cryptography, and encrypted-vault file storage.
- apps/linux/: future native GTK4 Linux application.
- android/: future native Kotlin application and checked-in Gradle wrapper.

The Linux package will produce the suika-authenticator executable. The Android Gradle project will produce a debug APK.

## GitHub Actions

Workflow: .github/workflows/build.yml

Triggers include relevant source pushes to main, pull requests, and manual runs. The Linux job now runs Rust formatting, workspace tests, Clippy, and dependency feature-tree inspection as soon as the Rust core exists. The Linux executable and Android APK build steps remain conditional until their respective application projects have been added.

## Artifact names and retention

- suika-authenticator-linux-x86_64
- suika-authenticator-android-debug

Both artifacts use retention-days: 1. GitHub deletes them after one day. This is artifact retention, not a permanent release asset.

To download a build:

1. Open the repository's Build binaries workflow.
2. Open the latest successful run.
3. Download the desired platform artifact from its Artifacts section.

GitHub requires sign-in and repository read access. The artifact expires after one day.

## Release distinction

Android debug APKs are development builds. A production APK requires deliberate signing configuration. The Linux executable is dynamically linked to GTK4 and required system libraries; it is not currently a fully self-contained Linux package.

Permanent GitHub Releases, signing, and provenance attestations will be designed separately from temporary CI artifacts.
