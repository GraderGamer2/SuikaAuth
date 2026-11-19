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

The native bridge returns a Java boolean for vault-existence checks and uses JNI exception strings.

The initial Android frontend exposes a narrow JNI API for vault existence checks, vault creation, password unlock, account listing, TOTP enrollment, account editing/removal, HOTP code consumption, and explicit session locking. Metadata-only edits never request or expose an existing secret; a blank replacement-secret field retains the current zeroizing core buffer. Removal persists the encrypted account database. HOTP codes are returned only after the incremented counter has been encrypted and saved. The bridge exposes only display metadata and generated codes, never raw account secrets.

The JNI bridge currently exposes vault creation and password unlock, device-wrapped KEK unlock, explicit session locking, account listing, manual TOTP enrollment, provisioning-URI import, account editing/removal, HOTP consumption, and an explicit export of the password-derived wrapping key for the one-time Android Keystore enrollment operation. The native session registry validates opaque handles on every call. The bridge never returns the DEK or decrypted account database to Kotlin. The wrapping-key export exists only to allow the platform Keystore to encrypt that existing KEK; callers must zero the returned byte array immediately after wrapping it.

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

The Android frontend locks on explicit user request, after five minutes of inactivity, and when the app becomes no longer visible according to a user-selected timeout: immediately (the default), or after 1, 3, 5, or 10 minutes. A pending background lock is canceled if the user returns before the selected delay expires. The timeout preference is stored in `noBackupFilesDir/SuikaAuthenticator/background-lock-timeout-ms`, alongside the encrypted vault and other app-owned state. The lifecycle drops the native session handle on explicit lock, five-minute inactivity, the selected background timeout, and final Activity destruction. A ViewModel owns the process-local native handle and a single-thread worker across configuration changes, preventing duplicate sessions and serializing vault file operations. A process restart loses the in-memory native registry and returns to authentication; neither the handle nor account data is placed in saved-instance state. Configuration changes during a biometric prompt cancel that prompt safely; an unfinished biometric enrollment is discarded and can be restarted. If the app backgrounds while a prompt is active, the selected background-lock policy is applied when the prompt finishes or is dismissed.

### Device-bound biometric unlock

Biometric unlock is optional and device-specific. It uses a non-exportable AES-256-GCM key in Android Keystore. The key requires authentication for every cryptographic operation using strong biometrics only, and is invalidated when biometric enrollment changes. AndroidX BiometricPrompt authorizes a `Cipher` operation; a successful biometric callback without the authorized CryptoObject cannot unlock the vault.

The encrypted vault format is unchanged. After the master password unlocks a vault, an explicit user action may export the existing password-derived 256-bit KEK from the native session to Kotlin. Kotlin immediately encrypts it with the device Keystore key and stores only a version byte, 12-byte GCM IV, and 48-byte AES-GCM ciphertext/tag under `noBackupFilesDir/SuikaAuthenticator/device-unlock.bin`. The DEK and decrypted account database never leave Rust. On biometric unlock, Keystore releases the KEK only through the authorized Cipher operation; JNI passes it back to Rust, which independently authenticates the existing vault's wrapped DEK and encrypted payload before creating a native session.

The master password remains available at all times as the portable recovery method. If Android reports permanent key invalidation after biometric or device-security changes, SuikaAuthenticator deletes the stale wrapped record and alias, then requests the master password so a new device-bound key can be enrolled. Disabling biometric unlock deletes both the wrapped record and Keystore alias. If a device has no strong biometric hardware or no biometric is enrolled, the master-password flow remains fully functional.

The app uses AndroidX Biometric 1.1.0, the stable dependency line, with API 26+ support. Only `BIOMETRIC_STRONG` is accepted; device-credential fallback is not used for this per-operation key. Keystore key material is system-managed, while the wrapped ciphertext remains below the single application data root.

### Camera-based QR enrollment

The Add authenticator screen offers an explicit **Scan QR code** action. The app declares camera hardware optional and requests `android.permission.CAMERA` at runtime only when the user starts scanning. CameraX 1.7.0 provides a lifecycle-bound rear-camera preview and `ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST`; ML Kit Barcode Scanning 17.3.0 is bundled in the APK and configured for QR format only. The bundled model is available immediately without a runtime model download. The scanner accepts only a bounded `otpauth://` text value, places it into the masked URI field for review, and then uses the native shared parser/import JNI path. It closes analysis, unbinds the camera, closes the ML Kit scanner after in-flight frames finish, and cancels when the dialog is dismissed, the Activity stops, or the vault locks.

Camera permission is not requested at startup, for ordinary account use, or merely because the app is installed. Devices without a camera can still use manual provisioning URI paste and Base32 enrollment.

### Aegis JSON migration

The Android account screen offers **Import Aegis export**, which opens the system document picker for a local JSON export. Plaintext exports can be imported with an empty password; password-encrypted exports prompt for the Aegis export password. A file URI remains in memory only and is not copied to a second persistent application directory. The file is read on the serialized worker thread, capped at 16 MiB, and passed with the password to the native Rust importer as byte arrays. Both arrays are cleared immediately after the JNI call; Rust wraps its copies in zeroizing buffers.

The native importer decrypts Aegis password slots using bounded scrypt parameters and AES-256-GCM, parses the inner database, and accepts only standard TOTP/HOTP accounts. It merges all supported entries into a candidate database and persists the candidate through the existing encrypted vault transaction. A failed password, malformed entry, or storage error does not commit a partial import. Importing the file does not change or delete the source export.

## CI responsibilities

The Android CI job must:

1. install the pinned Java 17 toolchain and Android SDK/NDK;
2. install the pinned Rust toolchain and Android compilation targets;
3. install the pinned `cargo-ndk` tool;
4. build the JNI bridge for both declared ABIs into `jniLibs`;
5. verify formatting, Rust tests, and strict Clippy; cross-compile the JNI library for both ABIs using the optimized release profile;
6. assemble a debug APK and include the APK, build information, and SHA-256 checksum in the one-day Actions artifact.

Both Rust workspaces use `opt-level = 3`, full/fat LTO, one codegen unit, symbol stripping, and aborting panic strategy. No build-host-specific CPU flags are forced: the Linux x86-64 binary and Android ABI libraries use their target triples' portable defaults. The app has no logging/tracing backend or telemetry; Android's transitive Rust `log` facade is compiled with `max_level_off`, and the JNI library installs an empty Rust panic hook.

Production signing and release provenance remain separate from the debug APK workflow.


## OTP clipboard handling

Copied TOTP and HOTP values are marked sensitive in the Android `ClipDescription` so Android 13 and later can redact the system clipboard preview. SuikaAuthenticator attaches non-secret owner, token, and monotonic-expiry metadata to the clip. After 30 seconds, it clears the clipboard only when Android still exposes that same SuikaAuthenticator clip; it never clears a newer clip from another application.

Android may return no clipboard description while the Activity is not eligible to inspect the clipboard. In that case expiry is deferred and checked again when SuikaAuthenticator returns to the foreground. This is best-effort cleanup, not a guarantee that a copied code is erased at exactly 30 seconds. The OS-level sensitive flag is a display hint, not a clipboard access-control mechanism.

Reference: [Android secure clipboard handling](https://developer.android.com/privacy-and-security/risks/secure-clipboard-handling) and [ClipDescription.EXTRA_IS_SENSITIVE](https://developer.android.com/reference/android/content/ClipDescription#EXTRA_IS_SENSITIVE).
