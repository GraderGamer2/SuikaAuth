# Provisioning URI enrollment

SuikaAuthenticator accepts standard offline `otpauth://` provisioning URIs for TOTP and HOTP on Linux and Android. The URI is parsed in the shared Rust core; the two frontends do not maintain separate parsers.

## Accepted shape

- TOTP: `otpauth://totp/Issuer:account?secret=BASE32&issuer=Issuer&algorithm=SHA1&digits=6&period=30`
- HOTP: `otpauth://hotp/Issuer:account?secret=BASE32&issuer=Issuer&algorithm=SHA1&digits=6&counter=0`

The issuer prefix in the path is optional when the `issuer` query parameter is present. If both are present, they must match exactly. The label is percent-decoded as UTF-8. Query values accept percent encoding and form-style `+` spaces.

## Validation

- URI input is limited to 4,096 bytes and at most 32 query fields.
- A `secret` field is required, Base32-decoded by the shared RFC 4648 decoder, and must decode to 16–128 bytes.
- Algorithms are SHA1, SHA256, and SHA512. Digits are 6, 7, or 8.
- TOTP `period` defaults to 30 seconds and must be 1–86,400 seconds. A TOTP URI must not contain `counter`.
- HOTP `counter` is required and must fit in an unsigned 64-bit integer. An HOTP URI must not contain `period`.
- Duplicate query parameters, malformed escapes, invalid UTF-8, control characters, URI fragments, mismatched issuers, and unknown OTP algorithms are rejected.
- Unknown unique query parameters (including the optional `image` field) are ignored for forward compatibility. No image is fetched and no network access is performed.

The parser removes the encoded secret from its temporary query map into a zeroizing string before decoding; decoded bytes are held in a zeroizing buffer and passed directly to account creation. Linux clears the URI entry after submission. Android passes the URI through JNI as a bounded byte array that is cleared immediately after the native import operation. Account records are encrypted before they are persisted.

## QR enrollment

The Android app has a **Scan QR code** action on the Add authenticator form. It requests the `CAMERA` permission only after the user starts scanning. CameraX provides a lifecycle-bound rear-camera preview and latest-frame image analysis; the bundled ML Kit barcode model is restricted to QR formats. The model ships in the APK, so QR decoding does not require a first-run model download or a network connection. Only a QR payload beginning with `otpauth://` and no longer than 4,096 UTF-8 bytes is accepted. The URI is placed in the masked URI field for review; Add account then invokes the same native parser and encrypted persistence path as manual paste. The camera is unbound and the scanner is closed when the dialog is dismissed, the activity stops, or the vault locks.

Linux offers **Import QR image** on the Add account form. It opens a local image through GTK's file dialog, decodes it with GdkPixbuf, scales the result to at most 2,048 × 2,048 pixels, converts it to grayscale, and identifies QR symbols using the pure-Rust `quircs` decoder. The source image is limited to 32 MiB. Exactly one valid `otpauth://` payload may be imported at a time; unsupported images, multiple authenticator codes, malformed payloads, and oversized URIs are rejected. No image or URI is uploaded, and no network request is made.

Both QR paths are transport mechanisms only. They do not maintain independent OTP parsers and never bypass the shared parser's Base32 secret, issuer, algorithm, digit, period, or counter checks. QR decoding libraries belong to the platform frontends, not the cryptographic core.


Aegis JSON exports are handled by the separate offline migration path described in [MIGRATION.md](MIGRATION.md). Provisioning URI and QR enrollment remain the shared parser path for individual authenticator tokens.
