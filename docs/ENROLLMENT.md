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

This parser supports manual URI paste/import. Camera-based Android QR scanning and Linux QR image import remain separate roadmap items.
