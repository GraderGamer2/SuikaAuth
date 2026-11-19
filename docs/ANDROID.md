# Android frontend and native integration

## Application shape

The Android application is a native Kotlin application using the platform View system. It will not use Compose, a WebView, an embedded browser, or a cross-platform UI runtime. The Android UI is presentation and lifecycle code; the Rust core remains the source of truth for the vault, account records, OTP generation, and persistence.

The Android package will contain:

- `android/app/`: Kotlin application and Android resources.
- `android/native/`: an Android-only Rust JNI bridge crate.
- `android/gradle/`: Gradle build configuration. CI installs the exact Gradle version through the pinned setup-gradle action; this initial scaffold does not check in a wrapper JAR.
- `android/app/src/main/jniLibs/`: generated Rust shared libraries arranged by Android ABI; do not check generated binaries into Git.

The JNI bridge is intentionally an independent Cargo workspace rooted at `android/native/`. It depends on `suika-core` by path, but its JNI dependency and Android ABI configuration do not enter the Linux workspace or the shared core dependency graph.

## Native library and ABI targets

The initial Android package will ship two 64-bit ABIs:

- `arm64-v8a` — physical ARM64 Android devices.
- `x86_64` — Android emulators and x86-64 devices.

Android expects native libraries inside the APK at `lib/<abi>/lib<name>.so`. Build the Rust shared library with `cargo-ndk`, placing the results under `android/app/src/main/jniLibs/`. Use explicit target/API-level inputs. CI pins the Rust stable toolchain, NDK 28.2.13676358, cargo-ndk 4.1.2, Gradle 9.6.0, and the current stable Android Gradle Plugin 9.4.1.

The initial Android build baseline uses the current stable Android Gradle Plugin 9.4.1, with Gradle 9.6.0, SDK Build Tools 36.0.0, NDK 28.2.13676358, and JDK 17. Android's AGP API reference lists 9.4.1 as the current stable release; the AGP 9.4 compatibility notes specify Gradle 9.6.0, Build Tools 36.0.0, NDK 28.2.13676358, JDK 17, and support through API level 37. The project currently targets API 36 because that stable SDK package is available from the runner's SDK feed. AGP 9 has built-in Kotlin support, so do not also apply `org.jetbrains.kotlin.android` to the application module. The CI workflow pins Gradle 9.6.0 and installs the SDK/NDK packages explicitly.

References: [Android Gradle Plugin API reference (current stable version)](https://developer.android.com/reference/tools/gradle-api), [AGP 9.4.0 compatibility notes](https://developer.android.com/build/releases/agp-9-4-0-release-notes), and [Migrate to built-in Kotlin](https://developer.android.com/build/migrate-to-built-in-kotlin).

## Rust/Kotlin boundary

- Native bridge returns a Java boolean for vault existence checks and uses JNI modified-UTF8 exception strings.

The initial Android vertical slice exposes a narrow JNI API for vault existence checks, vault creation, password unlock, account listing, TOTP enrollment, HOTP code consumption, and explicit session locking. HOTP codes are returned only after the counter increment has been encrypted and durably saved. The bridge exposes only display metadata and generated codes, never raw account secrets.

The remaining JNI work covers:

- creating and unlocking the encrypted vault;
- listing account display data and generating current codes;
- adding, updating, and removing TOTP/HOTP accounts;
- advancing an HOTP counter and persisting it before returning the consumed code;
- explicitly locking and dropping an unlocked session.

The bridge must not return raw OTP secrets or the decrypted account-database blob to Kotlin. It returns only display metadata and the code required by the current view. The Rust side retains the unlocked `VaultSession` and account database while the application is unlocked.

When the Android UI accepts an encoded Base32 secret, the JNI bridge should call `suika_core::base32::decode_base32` rather than reimplementing RFC 4648 decoding in Kotlin. Pass the returned zeroizing byte buffer directly into account creation or update; do not retain a second long-lived secret copy in the UI layer.

Use an opaque native session handle with validation on every operation. A lock operation invalidates the handle and drops the Rust session. Do not expose Rust object pointers directly as unvalidated Kotlin `Long` values.

Argon2id and other blocking cryptographic/file operations must run on a Kotlin worker executor, not the Android main thread. Surface results to the UI thread only after the native operation completes. Passwords and replacement secrets should cross JNI in byte arrays, be wrapped in Rust zeroizing buffers immediately, and have the Kotlin byte arrays cleared in a `finally` block.

## Android application data

All SuikaAuthenticator-owned persistent state must remain under one dedicated app-private internal directory:

```
context.noBackupFilesDir/SuikaAuthenticator/
```

Derive this root from `Context.noBackupFilesDir` at runtime rather than persisting an absolute path. Android documents this directory as app-private internal storage that is excluded from automatic backup to remote storage. This avoids silently copying the live vault into device/cloud backup; later backup and restore must use the application's explicit encrypted backup format. The encrypted vault, preferences, and app-owned backup files will live below this one directory. Do not use shared preferences, databases, external storage, separate cache directories, or other Android-owned locations for application state. Android system-managed files such as the installed APK and Keystore material are platform-managed and are not application data files.

Reference: [Android `Context.getNoBackupFilesDir()`](https://developer.android.com/reference/android/content/Context#getNoBackupFilesDir()).

The vault file uses the exact same versioned container and account-database format as Linux. No platform-specific plaintext export or alternate Android vault format is permitted.

## Lifecycle and biometric roadmap

The Android frontend will lock on explicit user request and after a five-minute inactivity timeout. The lifecycle must drop the native unlocked-session handle when the app is locked or the process is shutting down; process death is not a substitute for the explicit lock path.

Biometric unlock is a later milestone. It must use Android Keystore for a non-exportable, device-bound wrapping key and BiometricPrompt for authorization. A biometric match by itself must never be treated as cryptographic vault authentication. The master password remains the portable recovery method.

## CI responsibilities

The Android CI job must:

1. install the pinned Java 17 toolchain and Android SDK/NDK;
2. install the pinned Rust toolchain and Android compilation targets;
3. install the pinned `cargo-ndk` tool;
4. build the JNI bridge for both declared ABIs into `jniLibs`;
5. run Gradle tests/build checks and assemble a debug APK;
6. include the APK, build information, and SHA-256 checksum in the one-day Actions artifact.

Production signing and release provenance remain separate from the debug APK workflow.
