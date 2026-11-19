# Changelog

All notable project changes will be recorded here.

## Unreleased
- Corrected the Android JNI lockfile's `walkdir 2.5.0` checksum to match Cargo's generated lockfile from the successful debug APK artifact; the next CI run verifies `--locked` resolution end to end.
- Committed the Android JNI workspace's Cargo-generated lockfile from the successful dual-ABI build and made Android JNI tests, strict Clippy, and release cross-compilation use `--locked`.
- Replaced the fixed-size Base32 account-ID `chunks_exact` decoder with indexed decoding after Rust 1.100 strict Clippy flagged the iterator pattern; the 32-character input check still guarantees all 16 byte pairs are in bounds.
- Removed the extra terminal blank line from the Android JNI source after the formatter reported the remaining EOF-only diff.
- Applied all rustfmt changes to the Android JNI workspace after the new native HOTP test exposed the formatting gate; Android tests and strict Clippy now run before ABI builds.
- Added safe Android HOTP consumption: the native bridge advances the counter, encrypts and commits the updated vault, and only then returns the code for clipboard use. HOTP accounts are no longer exposed as copyable stale codes in the account list.
- Added an RFC 4226 persistence test for sequential HOTP consumption, plus Android JNI formatting, unit-test, and strict Clippy gates. CI also packages the independent Android Cargo.lock with the debug APK artifact.
- Validated the first Android debug APK for arm64-v8a and x86_64 with stable AGP 9.4.1 / Gradle 9.6.0; run #56 passed both Android and Linux jobs.
- Replaced the unresolvable AGP 9.6.0 preview pin with current stable AGP 9.4.1 and its compatible Gradle 9.6.0 release; retained API 36, Build Tools 36.0.0, NDK 28.2.13676358, and JDK 17.
- Corrected `jni` 0.22.4 exception-string and `jboolean` API usage, and made both NDK environment variables point to the pinned 28.2.13676358 installation during Android cross-compilation.
- Switched the initial Android compile/target SDK to API 36 after CI confirmed the runner package feed does not yet publish platforms;android-37. the stable AGP baseline is 9.4.1.
- Added the first native Android application using platform Views and a separate Rust JNI Cargo workspace. The initial screen supports encrypted-vault creation/unlock, TOTP account listing/enrollment, explicit lock, background lock, and five-minute inactivity lock.
- Added Android JNI build steps for arm64-v8a and x86_64 using pinned stable AGP 9.4.1 / Gradle 9.6.0 / NDK 28.2.13676358 / cargo-ndk 4.1.2.
- Corrected the Android plugin pin to the actually published stable AGP 9.4.1 and its Gradle 9.6.0 compatibility pair after CI showed AGP 9.6.0 was not resolvable because it is a preview line.
- Collapsed the GTK secret-entry cleanup condition to satisfy strict Clippy on the stable Rust toolchain without changing traversal or cleanup behavior.
- Raised the bounded Base32 data-character ceiling to 208 so structurally complete over-sized inputs reach the decoded-byte limit check rather than being misclassified as malformed length.

- Corrected the Base32 separator test vector and refreshed Android platform guidance: AGP 9.4.0 tool versions, built-in Kotlin, and one `noBackupFilesDir` application-data root.

- Moved RFC 4648 Base32 decoding into the shared Rust core with bounded input/output, strict padding and trailing-bit checks, and zeroizing buffers; Linux add/edit enrollment now uses the shared decoder.
- Fixed shutdown cleanup's GTK widget upcast so the Linux workspace compiles before tests, Clippy, dependency inspection, and release linking.

- Added a five-minute inactivity lock driven by captured pointer, click, keyboard, and scroll activity across the GTK window.
- Centralized explicit and automatic locking so the unlocked vault session is dropped and add/edit/account pages are detached.
- Clear secret entry values on lock, window close, and application shutdown; drop the unlocked session on both window close and the application shutdown signal.
- Bound OTP refresh timers to their account page so they stop after that page is hidden or replaced.
- Store the normalized Base32 input in a zeroizing buffer in addition to the decoded secret bytes.

- Added account editing that preserves stable IDs, groups, and favorites while allowing optional secret replacement without displaying the existing secret.
- Added explicit AlertDialog confirmation before removing an account; removed account secrets are dropped through the core's zeroizing ownership.
- Added transactional account updates in suika-core and tests for metadata preservation, OTP changes, and invalid-update rollback.
- Switched confirmation/error prompts to GTK 4.10 AlertDialog APIs and enabled the matching gtk-rs feature rather than using deprecated MessageDialog.

- Added HOTP enrollment to the Linux account form, including Base32 secret validation, algorithm/digit configuration, and an initial counter.
- Added a HOTP “Copy & next” action that copies the current one-time code only after the incremented counter has been encrypted and persisted.
- Added live local search across account issuer and label without requiring an index or external service.
- Added mutable account lookup by stable ID in the shared account database for counter operations and subsequent account management.

- Committed the Cargo-generated lockfile and changed CI to use --locked for tests, Clippy, dependency inspection, and release builds.
- Verified the Linux frontend in CI with 42 passing tests, formatting, strict Clippy, dependency-feature inspection, and an optimized x86-64 release build.
- Removed the old account/enrollment GTK pages from the window hierarchy when locking the vault.

- Retained the password-derived wrapping key only inside the zeroizing unlocked vault session, enabling routine saves without retaining or re-requesting the master password.
- Added session re-sealing with fresh AEAD nonces and a test proving persisted changes still unlock with the original master password.
- Added manual TOTP enrollment to the GTK frontend, including Base32 decoding, input validation, algorithm/digits/period configuration, and encrypted vault persistence.
- Added Base32 RFC 4648 decoding tests covering valid vectors, lowercase/spacing, invalid symbols, bad padding, and unused trailing bits.

- Added the initial native GTK4 Linux frontend with first-run vault creation and password unlocking.
- Added an unlocked account overview with live TOTP refresh, HOTP counter display, click-to-copy OTP values, and explicit locking.
- Added create-only vault storage so a first-run race cannot replace an existing vault.
- Added Vault::create_session to reuse the first-run key derivation and enter the unlocked session without a second Argon2id pass.

- Added the dependency-free vault file store using caller-supplied application-owned directories, bounded reads, restrictive Unix permissions, temporary-file cleanup, and atomic replacement.
- Added storage tests for encrypted-vault round trips, replacement, invalid-input preservation, directory permissions, relative paths, and symlink rejection.
- Added failure-injection coverage for an interrupted save before rename and restart behavior with a leftover partial temporary file.
- Validated the shared core and storage layer in CI: 36 tests passed, formatting passed, strict Clippy passed, and dependency feature inspection passed.
- Added a compact versioned account database with TOTP/HOTP parameters, issuer/label/group metadata, favorites, and random account IDs.
- Added zeroizing account-secret ownership and zeroizing encoded database buffers without adding a serialization framework dependency.
- Added account database round-trip, TOTP/HOTP generation, counter advancement, malformed header, version, and UTF-8 validation tests.
- Added the initial versioned encrypted vault container with Argon2id-wrapped DEK and XChaCha20-Poly1305 payload encryption.
- Added bounded vault parsing, authenticated header metadata, generic unlock failures, and password-change support.
- Added vault round-trip, tampering, wrong-password, truncation, KDF-bound, and payload-size tests.
- Capped vault-header Argon2id parameters at 128 MiB and three passes to limit pre-authentication resource consumption.
- Wrapped the temporary decrypted DEK copy in zeroizing memory.
- Verified the shared Rust core with formatting, all tests, and strict Clippy in GitHub Actions.

- Added the authoritative development roadmap.
- Added the initial Rust workspace and shared suika-core crate.
- Implemented bounded Argon2id key derivation using the selected 128 MiB / 3-iteration / 4-lane profile.
- Implemented XChaCha20-Poly1305 authenticated encryption and zeroizing decrypted buffers.
- Added CSPRNG-backed salt, key, and nonce generation.
- Added HOTP/TOTP generation with SHA-1, SHA-256, and SHA-512 HMAC.
- Added RFC 4226 and RFC 6238 test vectors.
- Documented the threat model, cryptographic design, and dependency policy.
- Updated CI to run Rust formatting and core tests before the platform frontends exist.
- Preserved the one-day GitHub Actions artifact retention policy.
