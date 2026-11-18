//! RFC 4226 HOTP and RFC 6238 TOTP generation.

use core::fmt;

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

/// HMAC digest supported by HOTP and TOTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpAlgorithm {
    /// HMAC-SHA-1, retained for broad service compatibility.
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

/// Errors returned while generating one-time passwords.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpError {
    /// HOTP/TOTP secrets must not be empty.
    EmptySecret,
    /// Only six-, seven-, and eight-digit codes are supported.
    InvalidDigits,
    /// A TOTP time period must be greater than zero.
    InvalidPeriod,
    /// An HMAC digest could not be initialized or had an invalid length.
    InvalidDigest,
}

impl fmt::Display for OtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptySecret => "OTP secret must not be empty",
            Self::InvalidDigits => "OTP digit count must be 6, 7, or 8",
            Self::InvalidPeriod => "TOTP period must be greater than zero",
            Self::InvalidDigest => "HMAC digest could not be processed",
        };

        f.write_str(message)
    }
}

impl std::error::Error for OtpError {}

fn compute_hmac(secret: &[u8], counter: u64, algorithm: OtpAlgorithm) -> Result<Vec<u8>, OtpError> {
    let message = counter.to_be_bytes();

    let digest = match algorithm {
        OtpAlgorithm::Sha1 => {
            let mut mac =
                Hmac::<Sha1>::new_from_slice(secret).map_err(|_| OtpError::InvalidDigest)?;
            mac.update(&message);
            mac.finalize().into_bytes().to_vec()
        }
        OtpAlgorithm::Sha256 => {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(secret).map_err(|_| OtpError::InvalidDigest)?;
            mac.update(&message);
            mac.finalize().into_bytes().to_vec()
        }
        OtpAlgorithm::Sha512 => {
            let mut mac =
                Hmac::<Sha512>::new_from_slice(secret).map_err(|_| OtpError::InvalidDigest)?;
            mac.update(&message);
            mac.finalize().into_bytes().to_vec()
        }
    };

    Ok(digest)
}

fn dynamic_truncate(digest: &[u8], digits: u8) -> Result<String, OtpError> {
    let last = digest.last().ok_or(OtpError::InvalidDigest)?;
    let offset = usize::from(last & 0x0F);
    let selected = digest
        .get(offset..offset + 4)
        .ok_or(OtpError::InvalidDigest)?;
    let bytes: [u8; 4] = selected.try_into().map_err(|_| OtpError::InvalidDigest)?;
    let binary = u32::from_be_bytes(bytes) & 0x7FFF_FFFF;
    let modulus = 10_u32.pow(u32::from(digits));
    let value = binary % modulus;

    Ok(format!("{value:0width$}", width = usize::from(digits)))
}

/// Generate an HOTP value as specified by RFC 4226.
///
/// The returned string preserves leading zeroes. Supported output lengths are
/// six, seven, and eight digits.
pub fn generate_hotp(
    secret: &[u8],
    counter: u64,
    digits: u8,
    algorithm: OtpAlgorithm,
) -> Result<String, OtpError> {
    if secret.is_empty() {
        return Err(OtpError::EmptySecret);
    }
    if !(6..=8).contains(&digits) {
        return Err(OtpError::InvalidDigits);
    }

    let digest = compute_hmac(secret, counter, algorithm)?;
    dynamic_truncate(&digest, digits)
}

/// Generate a TOTP value as specified by RFC 6238.
///
/// timestamp_seconds is a Unix timestamp in UTC. The counter is calculated as
/// timestamp_seconds divided by period_seconds.
pub fn generate_totp(
    secret: &[u8],
    timestamp_seconds: u64,
    period_seconds: u64,
    digits: u8,
    algorithm: OtpAlgorithm,
) -> Result<String, OtpError> {
    if period_seconds == 0 {
        return Err(OtpError::InvalidPeriod);
    }

    generate_hotp(
        secret,
        timestamp_seconds / period_seconds,
        digits,
        algorithm,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_rfc_4226_hotp_sha1_vectors() {
        let secret = b"12345678901234567890";
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];

        for (counter, expected_code) in expected.iter().enumerate() {
            let actual = generate_hotp(
                secret,
                u64::try_from(counter).expect("counter fits u64"),
                6,
                OtpAlgorithm::Sha1,
            )
            .expect("HOTP generation should succeed");

            assert_eq!(&actual, expected_code, "counter {counter}");
        }
    }

    #[test]
    fn passes_rfc_6238_sha1_vector() {
        assert_eq!(
            generate_totp(b"12345678901234567890", 59, 30, 8, OtpAlgorithm::Sha1)
                .expect("TOTP generation should succeed"),
            "94287082"
        );
    }

    #[test]
    fn passes_rfc_6238_sha256_vector() {
        assert_eq!(
            generate_totp(
                b"12345678901234567890123456789012",
                59,
                30,
                8,
                OtpAlgorithm::Sha256
            )
            .expect("TOTP generation should succeed"),
            "46119246"
        );
    }

    #[test]
    fn passes_rfc_6238_sha512_vector() {
        assert_eq!(
            generate_totp(
                b"1234567890123456789012345678901234567890123456789012345678901234",
                59,
                30,
                8,
                OtpAlgorithm::Sha512
            )
            .expect("TOTP generation should succeed"),
            "90693936"
        );
    }

    #[test]
    fn rejects_invalid_inputs() {
        assert_eq!(
            generate_hotp(b"", 0, 6, OtpAlgorithm::Sha1).err(),
            Some(OtpError::EmptySecret)
        );
        assert_eq!(
            generate_hotp(b"secret", 0, 5, OtpAlgorithm::Sha1).err(),
            Some(OtpError::InvalidDigits)
        );
        assert_eq!(
            generate_totp(b"secret", 59, 0, 6, OtpAlgorithm::Sha1).err(),
            Some(OtpError::InvalidPeriod)
        );
    }
}
