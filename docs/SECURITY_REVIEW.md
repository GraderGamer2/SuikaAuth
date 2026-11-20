# Internal security review

Review date: 2026-11-20

Status: **source-level internal review completed; independent security audit not performed.**

This review covers the current shared Rust core and relevant Linux/Android key-handling paths. It is a maintenance review of implementation and documented controls, not a cryptographic proof, penetration test, dependency audit, certification, or independent security assessment.

## Scope examined

- Argon2id parameter validation, key derivation, salt generation, and zeroizing key ownership.
- XChaCha20-Poly1305 encryption/decryption, nonce generation, and associated-data construction.
- Versioned vault and portable-backup parsing, authentication, and key hierarchy.
- Account database secret ownership and Base32, otpauth, and Aegis import handling.
- HOTP/TOTP HMAC generation and temporary digest handling.
- Encrypted-vault file permissions and atomic replacement behavior.
- Android Keystore/BiometricPrompt wrapping-key handoff and JNI byte-array cleanup.
- Linux and Android password-entry and session cleanup paths at source level.

## Controls verified in source

### Key derivation and key hierarchy

The vault uses Argon2id v1.3 to derive a 256-bit key-encryption key (KEK) from the master password and a 32-byte random salt. The production profile is 128 MiB, three iterations, and four lanes. File-supplied parameters are checked before KDF allocation and constrained to 64–128 MiB, one to three iterations, and one to four lanes.

A fresh random 256-bit data-encryption key (DEK) encrypts the account database. The KEK wraps the DEK, so changing the password re-wraps the same DEK rather than deriving bulk encryption directly from the password. Secret keys are non-Clone, redacted in Debug output, and zeroized on drop.

### Authenticated encryption and container binding

The vault uses XChaCha20-Poly1305 with a 24-byte nonce and 16-byte authentication tag. Nonces are obtained from the operating-system CSPRNG for each encryption. The DEK wrapper and account payload use separate domain-specific associated-data strings. The wrapper AAD authenticates the versioned prefix, including algorithm identifiers, KDF parameters, and salt. The payload AAD additionally binds the wrapper nonce/ciphertext and payload length.

The parser validates the magic, format/algorithm identifiers, reserved bytes, bounded KDF parameters, ciphertext sizes, and exact total file length before key derivation or payload decryption. Wrong-password and authentication failures are returned through a generic unlock failure.

### Portable backup

Backups use a fresh independent DEK and a separate user-supplied backup password. Backup and vault AAD domains are distinct. Restore authenticates the wrapper and payload, validates the full account database, and returns zeroizing plaintext. Platform code constructs a candidate account database and commits it only through the encrypted vault save path.

### Secret and import handling

Account secrets are held in zeroizing allocations. Base32 normalized input and decoded output are bounded and zeroizing. otpauth query values are stored in zeroizing strings; Aegis input, decrypted database, password-derived keys, and imported secrets use zeroizing buffers where practical. Android JNI copies byte arrays into zeroizing Rust buffers, while Kotlin clears password/secret byte arrays after synchronous native operations. Linux password bytes are passed to the core in zeroizing buffers.

HOTP/TOTP remains covered by the RFC 4226 and RFC 6238 test vectors. During this review, the full HMAC digest was found to be returned in an ordinary Vec and dropped without explicit zeroization. It is now held in a zeroizing buffer until dynamic truncation finishes, and the HMAC crate's zeroize feature is explicitly enabled for dependency-managed digest state.

### Persistent storage and device unlock

The Linux/Android Rust vault store validates file type and size, rejects a vault symlink, restricts the application directory to mode 0700 and vault files to mode 0600 on Unix, writes through a same-directory mode-0600 temporary file, syncs it, atomically renames it, and syncs the directory. Actual process-kill and power-loss tests on target filesystems remain outstanding.

Android device unlock stores only the KEK encrypted by a non-exportable Android Keystore AES-256-GCM key. BiometricPrompt authenticates a per-use cipher operation with strong biometrics. The Rust core then independently verifies the portable vault's DEK wrapper and encrypted payload. The master password remains the recovery method.

## Findings and changes

- **HMAC digest lifetime:** fixed in this review. The full OTP HMAC digest is now zeroized after dynamic truncation; the HMAC crate's zeroize feature is explicitly enabled.
- No concrete flaw in the vault/backup key hierarchy, versioned header binding, or AEAD nonce/AAD construction was identified in this source pass.
- No vault format change, KDF parameter change, encryption algorithm change, or new runtime dependency was made.

## Residual risks and uncompleted validation

- This is not an independent review of cryptographic design, implementation, compiler output, or dependency internals. A qualified third-party security audit remains desirable before making a strong production-security claim.
- The manual direct/transitive dependency review remains open. Automated RustSec lockfile checks detect published advisories but do not establish exploitability or the absence of unknown vulnerabilities.
- UI frameworks can create password copies that are not under application zeroization control. Clearing GTK/Android entry widgets and zeroizing owned byte buffers reduces exposure but cannot erase every runtime-managed text copy.
- The operating system, kernel, swap, crash dumps, debuggers, keyloggers, privileged processes, and physical-memory access remain outside the protection boundary described in the threat model.
- Clipboard cleanup is best-effort; clipboard managers, previews, readers, shutdown, and races can expose or retain copied OTP values.
- Physical Linux Wayland/X11 and Android clipboard behavior, cross-platform document-picker transfer, and abrupt process-kill/power-loss storage tests remain pending.
- KDF and unlock performance measurements are deferred; no KDF profile adjustment is proposed based on unmeasured concerns.

## Roadmap disposition

The internal source-review item is complete. The manual dependency audit, physical-device validation, durability testing, broad memory/permissions review, and any independent third-party audit remain separate tasks.
