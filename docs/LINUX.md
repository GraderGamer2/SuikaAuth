# Linux frontend

The Linux application is a native GTK4 desktop program implemented in Rust. The executable target is:

    cargo run --release -p suika-authenticator-linux --bin suika-authenticator

The frontend depends on the shared suika-core crate for account parsing, OTP generation, encrypted vault creation, and unlocking. GTK is not a dependency of suika-core.

## First launch

If the vault file does not exist, the application offers first-run setup. It asks for a master password twice, creates an empty versioned account database in zeroizing memory, encrypts it with the production Argon2id profile, and stores the encrypted bytes as vault.bin.

The first-run screen uses a create-only storage operation. If another application instance creates a vault first, the second instance will not replace it.

## Subsequent launches

If vault.bin exists and its public container structure is valid, the application requests the master password. Key derivation and authenticated decryption run on a worker thread, so GTK remains responsive while Argon2id is running.

A successful unlock displays the account list. TOTP codes refresh once per second; HOTP counters are displayed and are advanced only by the explicit “Copy & next” action, which persists the new counter before placing the consumed code on the desktop clipboard. The Lock button and five minutes without pointer, click, keyboard, or scroll activity drop the unlocked core session and return to the unlock screen.

## Persistent data

The Linux frontend supplies exactly:

    $HOME/.SuikaAuthenticator/

The shared storage layer applies owner-only directory and file permissions on Unix. The frontend does not use XDG configuration, data, or cache paths for application-owned persistent state.

## Current scope

The Linux frontend supports first-run setup, unlock, a live account overview, OTP display, TOTP/HOTP enrollment, copy, “Copy & next” for HOTP, local search by issuer/account, account editing/removal, explicit locking, and automatic locking after five minutes without input. Password-change UI and inactivity-timeout preferences are not yet implemented.

## Account persistence

Account records are encoded into a zeroizing buffer, installed into the unlocked vault session, encrypted using the session-held wrapping key, and written through the atomic vault store. The master password is not retained by the GTK frontend. The wrapping key remains only in the core's unlocked session and is zeroized when that session is dropped.

The manual enrollment form accepts TOTP or HOTP, SHA1/SHA256/SHA512, and 6/7/8 digits. TOTP periods range from 1 to 86400 seconds; HOTP accepts a user-supplied unsigned 64-bit initial counter. Base32 whitespace and hyphens are ignored, lowercase input is accepted, and the decoded secret must be at least 16 bytes and no more than 128 bytes.

No password is stored in application settings or command-line arguments. The master password entry is cleared before the worker starts; the worker receives a zeroizing byte buffer. The application does not log passwords, OTP secrets, or generated codes.

## Idle lock and shutdown

The inactivity timer is reset by pointer movement, pointer/touch clicks, keyboard input, and scrolling anywhere in the main GTK window. After five minutes without those events, the application drops the unlocked vault session, removes the account and enrollment pages, and returns to the password screen. The same session drop occurs when the main window closes or the GTK application shuts down. Secret-entry widgets are cleared on lock and shutdown. This is best-effort application-level memory cleanup; it is not a guarantee against memory acquisition by a process with sufficient privileges, swap capture, or abrupt power loss.


## OTP clipboard handling

The OTP display is not independently selectable; TOTP and HOTP values are copied through their explicit buttons so every application-mediated copy uses the guarded path. Copied values are cleared after 30 seconds only if GDK still reports that the clipboard is locally owned by SuikaAuthenticator and its text still matches the copied code. A later OTP copy supersedes the earlier expiry callback, and content copied by another application is never cleared. The comparison buffer is zeroized when the callback finishes. This is best-effort clipboard hygiene; it does not prevent another process from reading a code before it expires.

References: [GDK Clipboard ownership](https://docs.gtk.org/gdk4/method.Clipboard.is_local.html) and [GDK Clipboard text reads](https://docs.gtk.org/gdk4/method.Clipboard.read_text_async.html).
