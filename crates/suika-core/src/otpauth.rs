//! Strict, bounded parser for standard otpauth provisioning URIs.

use std::collections::HashMap;

use zeroize::{Zeroize, Zeroizing};

use crate::accounts::{Account, AccountError, AccountMode};
use crate::base32::decode_base32;
use crate::otp::OtpAlgorithm;

const MAX_URI_BYTES: usize = 4096;
const MAX_QUERY_FIELDS: usize = 32;
const MAX_QUERY_COMPONENT_BYTES: usize = 2048;
const MIN_SECRET_BYTES: usize = 16;
const MAX_SECRET_BYTES: usize = 128;
const MAX_PERIOD_SECONDS: u64 = 86_400;

/// Errors returned when an otpauth URI cannot be safely converted to an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpAuthError {
    InvalidUri,
    InvalidParameter,
    InvalidSecret,
    Account(AccountError),
}

impl core::fmt::Display for OtpAuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidUri => f.write_str("The provisioning URI is malformed or unsupported."),
            Self::InvalidParameter => f.write_str("The provisioning URI contains invalid OTP parameters."),
            Self::InvalidSecret => f.write_str("The provisioning URI does not contain a valid Base32 secret."),
            Self::Account(error) => write!(f, "The provisioning account is invalid: {error}"),
        }
    }
}

impl std::error::Error for OtpAuthError {}

impl From<AccountError> for OtpAuthError {
    fn from(error: AccountError) -> Self {
        Self::Account(error)
    }
}

/// Parse a standard `otpauth://totp` or `otpauth://hotp` URI into an account.
///
/// Parsing is deliberately bounded and rejects duplicate parameters, malformed
/// percent escapes, ambiguous issuer labels, unsupported algorithms, and
/// mode-incompatible fields. Unknown query parameters are ignored for
/// forward compatibility; the standard optional `image` parameter is unused.
pub fn parse_otpauth_uri(uri: &str) -> Result<Account, OtpAuthError> {
    if uri.len() > MAX_URI_BYTES {
        return Err(OtpAuthError::InvalidUri);
    }
    let uri = uri.trim();
    if uri.is_empty() || uri.contains('#') {
        return Err(OtpAuthError::InvalidUri);
    }

    let (scheme, remainder) = uri.split_once("://").ok_or(OtpAuthError::InvalidUri)?;
    if !scheme.eq_ignore_ascii_case("otpauth") {
        return Err(OtpAuthError::InvalidUri);
    }

    let (kind, path_and_query) = remainder.split_once('/').ok_or(OtpAuthError::InvalidUri)?;
    let mode = if kind.eq_ignore_ascii_case("totp") {
        0
    } else if kind.eq_ignore_ascii_case("hotp") {
        1
    } else {
        return Err(OtpAuthError::InvalidUri);
    };

    let (encoded_label, query) = path_and_query.split_once('?').ok_or(OtpAuthError::InvalidUri)?;
    if encoded_label.is_empty()
        || encoded_label.contains('/')
        || query.is_empty()
        || query.contains('?')
    {
        return Err(OtpAuthError::InvalidUri);
    }

    let label = percent_decode(encoded_label, false)?;
    if label.is_empty() || label.len() > MAX_QUERY_COMPONENT_BYTES {
        return Err(OtpAuthError::InvalidParameter);
    }

    let mut fields: HashMap<String, Zeroizing<String>> = HashMap::new();
    if query.len() > MAX_URI_BYTES - encoded_label.len() {
        return Err(OtpAuthError::InvalidUri);
    }
    for pair in query.split('&') {
        if fields.len() >= MAX_QUERY_FIELDS {
            return Err(OtpAuthError::InvalidUri);
        }
        let (encoded_key, encoded_value) =
            pair.split_once('=').ok_or(OtpAuthError::InvalidUri)?;
        if encoded_key.is_empty() || encoded_value.len() > MAX_QUERY_COMPONENT_BYTES {
            return Err(OtpAuthError::InvalidUri);
        }
        let key = percent_decode(encoded_key, true)?.to_ascii_lowercase();
        let value = Zeroizing::new(percent_decode(encoded_value, true)?);
        if key.is_empty() || fields.insert(key, value).is_some() {
            return Err(OtpAuthError::InvalidParameter);
        }
    }

    let secret_text = fields
        .remove("secret")
        .ok_or(OtpAuthError::InvalidSecret)?;
    if secret_text.is_empty() {
        return Err(OtpAuthError::InvalidSecret);
    }
    let secret = Zeroizing::new(
        decode_base32(secret_text.as_str()).map_err(|_| OtpAuthError::InvalidSecret)?,
    );
    if !(MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&secret.len()) {
        return Err(OtpAuthError::InvalidSecret);
    }

    let (label_issuer, account_label) = match label.split_once(':') {
        Some((issuer, account)) if !issuer.is_empty() && !account.is_empty() => {
            (Some(issuer), account)
        }
        Some(_) => return Err(OtpAuthError::InvalidParameter),
        None => (None, label.as_str()),
    };
    if account_label.is_empty() {
        return Err(OtpAuthError::InvalidParameter);
    }

    let query_issuer = fields.get("issuer").map(|value| value.as_str()).filter(|v| !v.is_empty());
    if let (Some(label_value), Some(query_value)) = (label_issuer, query_issuer)
        && label_value != query_value
    {
        return Err(OtpAuthError::InvalidParameter);
    }
    let issuer = query_issuer.or(label_issuer).unwrap_or("");

    let algorithm = match fields.get("algorithm").map(|value| value.as_str()).unwrap_or("SHA1") {
        value if value.eq_ignore_ascii_case("SHA1") => OtpAlgorithm::Sha1,
        value if value.eq_ignore_ascii_case("SHA256") => OtpAlgorithm::Sha256,
        value if value.eq_ignore_ascii_case("SHA512") => OtpAlgorithm::Sha512,
        _ => return Err(OtpAuthError::InvalidParameter),
    };

    let digits = parse_u64(&fields, "digits", Some(6))?;
    let digits = u8::try_from(digits).map_err(|_| OtpAuthError::InvalidParameter)?;
    if !(6..=8).contains(&digits) {
        return Err(OtpAuthError::InvalidParameter);
    }

    match mode {
        0 => {
            if fields.contains_key("counter") {
                return Err(OtpAuthError::InvalidParameter);
            }
            let period = parse_u64(&fields, "period", Some(30))?;
            if !(1..=MAX_PERIOD_SECONDS).contains(&period) {
                return Err(OtpAuthError::InvalidParameter);
            }
            Account::new_totp(issuer, account_label, secret, algorithm, digits, period)
                .map_err(OtpAuthError::from)
        }
        1 => {
            if fields.contains_key("period") {
                return Err(OtpAuthError::InvalidParameter);
            }
            let counter = parse_u64(&fields, "counter", None)?;
            Account::new_hotp(issuer, account_label, secret, algorithm, digits, counter)
                .map_err(OtpAuthError::from)
        }
        _ => Err(OtpAuthError::InvalidUri),
    }
}

fn parse_u64(
    fields: &HashMap<String, Zeroizing<String>>,
    name: &str,
    default: Option<u64>,
) -> Result<u64, OtpAuthError> {
    let Some(value) = fields.get(name) else {
        return default.ok_or(OtpAuthError::InvalidParameter);
    };
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(OtpAuthError::InvalidParameter);
    }
    value.parse().map_err(|_| OtpAuthError::InvalidParameter)
}

fn percent_decode(value: &str, plus_as_space: bool) -> Result<Zeroizing<String>, OtpAuthError> {
    let bytes = value.as_bytes();
    let mut decoded = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut offset = 0;
    while offset < bytes.len() {
        match bytes[offset] {
            b'%' => {
                let high = bytes.get(offset + 1).and_then(|v| hex(*v));
                let low = bytes.get(offset + 2).and_then(|v| hex(*v));
                let (Some(high), Some(low)) = (high, low) else {
                    return Err(OtpAuthError::InvalidUri);
                };
                decoded.push((high << 4) | low);
                offset += 3;
            }
            b'+' if plus_as_space => {
                decoded.push(b' ');
                offset += 1;
            }
            value => {
                decoded.push(value);
                offset += 1;
            }
        }
    }

    let bytes = core::mem::take(&mut *decoded);
    let decoded = match String::from_utf8(bytes) {
        Ok(value) => Zeroizing::new(value),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            return Err(OtpAuthError::InvalidUri);
        }
    };
    if decoded.chars().any(char::is_control) {
        return Err(OtpAuthError::InvalidParameter);
    }
    Ok(decoded)
}

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_totp_with_defaults_and_issuer_in_label() {
        let account = parse_otpauth_uri(
            "otpauth://totp/Example%20Issuer:alice%40example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
        )
        .expect("valid TOTP URI should parse");

        assert_eq!(account.issuer(), "Example Issuer");
        assert_eq!(account.label(), "alice@example.com");
        assert_eq!(account.algorithm(), OtpAlgorithm::Sha1);
        assert_eq!(account.digits(), 6);
        assert_eq!(account.mode(), AccountMode::Totp { period_seconds: 30 });
    }

    #[test]
    fn parses_explicit_totp_parameters_and_percent_encoded_query() {
        let account = parse_otpauth_uri(
            "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Example%20Issuer&algorithm=SHA256&digits=8&period=60",
        )
        .expect("valid configured TOTP URI should parse");

        assert_eq!(account.issuer(), "Example Issuer");
        assert_eq!(account.label(), "alice");
        assert_eq!(account.algorithm(), OtpAlgorithm::Sha256);
        assert_eq!(account.digits(), 8);
        assert_eq!(account.mode(), AccountMode::Totp { period_seconds: 60 });
    }

    #[test]
    fn parses_hotp_with_required_counter_and_sha512() {
        let account = parse_otpauth_uri(
            "otpauth://hotp/Example:token?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&counter=0&algorithm=SHA512&digits=7",
        )
        .expect("valid HOTP URI should parse");

        assert_eq!(account.issuer(), "Example");
        assert_eq!(account.label(), "token");
        assert_eq!(account.algorithm(), OtpAlgorithm::Sha512);
        assert_eq!(account.digits(), 7);
        assert_eq!(account.mode(), AccountMode::Hotp { counter: 0 });
    }

    #[test]
    fn accepts_matching_issuer_parameters_and_ignores_unknown_fields() {
        let account = parse_otpauth_uri(
            "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Example&image=https%3A%2F%2Fexample.test%2Ficon.png&future=ignored",
        )
        .expect("matching issuer and unknown extension should parse");
        assert_eq!(account.issuer(), "Example");
        assert_eq!(account.label(), "alice");
    }

    #[test]
    fn rejects_issuer_mismatch_and_duplicate_fields() {
        assert_eq!(
            parse_otpauth_uri(
                "otpauth://totp/First:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Second"
            ).err(),
            Some(OtpAuthError::InvalidParameter)
        );
        assert_eq!(
            parse_otpauth_uri(
                "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
            ).err(),
            Some(OtpAuthError::InvalidParameter)
        );
    }

    #[test]
    fn rejects_malformed_schemes_escapes_and_labels() {
        for uri in [
            "https://totp/alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            "otpauth://steam/alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            "otpauth://totp/?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            "otpauth://totp/alice%ZZ?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP#fragment",
        ] {
            assert!(parse_otpauth_uri(uri).is_err(), "unexpectedly parsed {uri}");
        }
    }

    #[test]
    fn rejects_invalid_or_unsafe_otp_parameters() {
        for uri in [
            "otpauth://totp/alice?secret=bad!",
            "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&digits=9",
            "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&period=0",
            "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&counter=0",
            "otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            "otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&period=30&counter=0",
            "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&algorithm=MD5",
            "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&digits=6x",
            "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&period=18446744073709551616",
        ] {
            assert!(parse_otpauth_uri(uri).is_err(), "unexpectedly parsed {uri}");
        }
    }

    #[test]
    fn rejects_undersized_base32_secrets() {
        assert_eq!(
            parse_otpauth_uri("otpauth://totp/alice?secret=GEZDGNBV").err(),
            Some(OtpAuthError::InvalidSecret)
        );
    }
}
