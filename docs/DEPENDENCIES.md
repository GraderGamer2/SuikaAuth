# Dependency policy

SuikaAuthenticator keeps the shared security core small and platform-independent. Dependencies are exact-pinned to reviewed direct versions and enabled features are kept narrow.

## Initial direct dependencies

| Crate | Pinned version | Purpose |
|---|---:|---|
| argon2 | 0.6.0 | Argon2id key derivation |
| chacha20poly1305 | 0.11.0 | XChaCha20-Poly1305 |
| getrandom | 0.4.3 | Operating-system cryptographic randomness |
| hmac | 0.13.0 | HMAC composition for OTP |
| sha1 | 0.11.0 | HMAC-SHA-1 compatibility |
| sha2 | 0.11.1 | HMAC-SHA-256 and HMAC-SHA-512 |
| zeroize | 1.9.0 | Clear sensitive buffers |
| gtk4 | 0.10.3 | Native GTK4 Linux interface (frontend only) |
| gdk-pixbuf | 0.21.5 | Local Linux image loading and QR image decoding (frontend only) |
| quircs | 0.10.3 | Pure-Rust Linux QR detection/decoding (frontend only) |
| gdk-pixbuf | 0.21.5 | Local Linux image loading and bounded QR image decoding (frontend only) |
| quircs | 0.10.3 | Pure-Rust Linux QR detection/decoding (frontend only) |

All listed cryptographic implementations are pure Rust. The direct versions are exact-pinned in the workspace manifest. Cargo.lock is committed. Every CI test, Clippy run, dependency-feature inspection, and release build uses --locked so the resolved graph cannot change implicitly.

## Feature policy

- Disable default features when they are not required.
- Do not enable Argon2's optional parallel/Rayon feature in the initial core.
- Do not enable password-hash PHC string support when only raw key derivation is needed.
- Do not enable QR generation, URL parsing, image processing, HTTP, or general-purpose serialization frameworks in the security core. Account records use a small, explicitly versioned binary codec.
- CI runs cargo tree --workspace -e features so the complete enabled dependency feature tree is visible in each successful Rust-core build. Review this output whenever dependencies or features change.

## Rejected by default

No Electron runtime, database server, networking runtime, OpenSSL runtime dependency, analytics SDK, cloud SDK, or mandatory OS keyring integration.

A dependency may be added only when it provides concrete functionality that cannot reasonably be supplied by an existing dependency or a small amount of non-cryptographic application code. Cryptographic primitives must not be reimplemented merely to reduce the dependency count.

## Platform-only dependencies

GTK4 0.10.3 is an exact-pinned Linux-only Rust binding and belongs only to the frontend; it is not linked into suika-core. JNI bindings belong in the isolated Android bridge crate, not in suika-core or the Linux application. The gtk-rs 0.10 line documents an MSRV of Rust 1.83 and uses the glib/gdk 0.21 dependency family, which keeps it compatible with this workspace's Rust 1.88 baseline. GTK and its system libraries belong only to the Linux frontend. Kotlin/Android SDK dependencies belong only to the Android frontend. Neither platform UI stack may become a dependency of the shared Rust core.


## Android-only dependencies

- `jni` 0.22.4 remains isolated in `android/native/`. Its transitive `log` facade is feature-unified with `max_level_off`; logging macros in that dependency graph are disabled at compile time. No logger or tracing subscriber is initialized.
- `androidx.biometric:biometric:1.1.0` supplies API 26+ BiometricPrompt and authenticated Cipher operations. It remains Android-only and does not enter the Rust core or Linux build.


## Camera and QR dependencies

- Linux pins `gdk-pixbuf` 0.21.5 and `quircs` 0.10.3 in `apps/linux`. They are frontend-only and do not enter `suika-core`.
- Android pins CameraX 1.7.0 (`camera-camera2`, `camera-lifecycle`, `camera-view`) for camera preview and frame analysis.
- Android pins `com.google.mlkit:barcode-scanning:17.3.0`, the bundled-model artifact. The QR model is packaged in the APK; scanning does not depend on a first-run network download. The dependency is configured for QR format only.
- Android camera permission is requested on demand from the QR scanner action, and camera hardware remains an optional device feature.
