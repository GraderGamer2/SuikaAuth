# SuikaAuthenticator threat model

Status: initial design baseline; update this document whenever the security architecture changes.

## Assets

- TOTP/HOTP shared secrets.
- The random vault data-encryption key (DEK).
- The password-derived key-encryption key (KEK).
- Encrypted vaults and backups.
- Account metadata, including issuer and account labels.
- Temporary plaintext account data while the vault is unlocked.

## Security objectives

1. Protect account secrets at rest when the device is locked or the vault file is copied.
2. Detect modification, truncation, or substitution of encrypted vault data.
3. Make offline password guessing materially expensive through Argon2id.
4. Keep the same encrypted vault format portable between Linux and Android.
5. Avoid remote accounts, cloud services, telemetry, and mandatory operating-system keyrings.
6. Minimize the lifetime of plaintext secrets and derived keys in process memory.

## Assumptions and limits

- The device operating system and kernel are trusted while SuikaAuthenticator is running.
- The application cannot protect secrets from a compromised/rooted operating system, a malicious process with sufficient privileges, keyloggers, or an attacker who controls the device while the vault is unlocked.
- Memory zeroization reduces exposure but cannot guarantee removal of every compiler-generated copy, CPU register value, swap copy, crash dump, or physical-memory remnant.
- TOTP is a possession factor. It does not make a weak account password strong, prevent phishing, or protect an account whose server-side recovery process is compromised.
- An offline vault cannot enforce a server-side password-attempt limit. Password quality and Argon2id cost therefore matter.
- Biometrics are a platform convenience for local unlock. They are not a portable recovery factor and must never replace the master password for backup restoration.

## Attacker capabilities considered

- Obtaining a copy of the encrypted vault or backup while the application is closed.
- Modifying, truncating, or replacing encrypted file contents.
- Supplying malformed vault headers intended to trigger excessive memory or CPU allocation.
- Attempting offline password guesses against a copied vault.

## Required controls

- Argon2id with validated, bounded parameters before memory allocation.
- A fresh random salt for each vault password setup.
- A random 256-bit DEK, wrapped by a password-derived KEK.
- XChaCha20-Poly1305 authenticated encryption with a fresh random 192-bit nonce per encryption operation.
- Authentication of format metadata using associated data.
- Strict bounds on file sizes, ciphertext lengths, and KDF parameters.
- Atomic vault replacement and preservation of the previous valid file during writes.
- No plaintext temporary database or plaintext backup.
- Zeroization of key material and decrypted buffers where practical.
- No secrets in logs, crash messages, command-line arguments, or telemetry.

## Out of scope for the initial release

- Protection against a compromised host OS or rooted Android device.
- Remote account recovery or cloud synchronization.
- Protection against phishing or malicious OTP enrollment QR codes.
- Secure deletion guarantees on flash storage.
- Cross-device biometric migration.

## Directory ownership

On Linux, all application-owned persistent data must remain under the user's home directory in the dedicated .SuikaAuthenticator directory. Android must use one dedicated application-private internal directory. No application data may be scattered into other per-user configuration, data, or cache directories.
