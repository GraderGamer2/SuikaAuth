//! Bounded RFC 4648 Base32 decoding for authenticator enrollment.
//!
//! Separators commonly used when displaying recovery or OTP secrets (ASCII
//! whitespace and hyphens) are ignored. The encoded input and decoded bytes
//! are held in zeroizing buffers. This module does not impose an OTP-specific
//! minimum secret size; account enrollment applies that policy separately.

use core::fmt;

use zeroize::Zeroizing;

const MAX_INPUT_BYTES: usize = 1024;
const MAX_DATA_CHARACTERS: usize = 206;
const MAX_DECODED_BYTES: usize = 128;

/// Errors returned while decoding an encoded Base32 secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base32Error {
    /// The input contains no Base32 data.
    EmptyInput,
    /// The raw input exceeds the bounded size accepted by the decoder.
    InputTooLong,
    /// The number of data characters cannot form a valid Base32 encoding.
    InvalidLength,
    /// Padding is misplaced or has an invalid count.
    InvalidPadding,
    /// The input contains a character outside the Base32 alphabet.
    InvalidCharacter,
    /// Unused bits in the final Base32 symbol are not zero.
    NonZeroTrailingBits,
    /// The decoded output is empty or exceeds the supported secret size.
    DecodedLengthOutOfRange,
}

impl fmt::Display for Base32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyInput => "Enter a Base32 secret.",
            Self::InputTooLong => "The Base32 secret exceeds the supported input length.",
            Self::InvalidLength => "The Base32 secret has an invalid length.",
            Self::InvalidPadding => "The Base32 secret has invalid padding.",
            Self::InvalidCharacter => "The Base32 secret contains an invalid character.",
            Self::NonZeroTrailingBits => "The Base32 secret has non-zero unused trailing bits.",
            Self::DecodedLengthOutOfRange => "The decoded Base32 secret must be 1 to 128 bytes.",
        };

        f.write_str(message)
    }
}

impl std::error::Error for Base32Error {}

/// Decode an RFC 4648 Base32 string into a zeroizing byte buffer.
///
/// The decoder accepts either canonical padding or no padding. If padding is
/// present, it must be complete and correctly sized. Lowercase input, ASCII
/// whitespace, and hyphen separators are accepted. Non-zero unused trailing
/// bits and inputs that exceed the decoder's bounds are rejected.
pub fn decode_base32(input: &str) -> Result<Zeroizing<Vec<u8>>, Base32Error> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(Base32Error::InputTooLong);
    }

    let compact = Zeroizing::new(
        input
            .chars()
            .filter(|character| !character.is_ascii_whitespace() && *character != '-')
            .collect::<String>(),
    );

    if compact.is_empty() {
        return Err(Base32Error::EmptyInput);
    }

    let first_padding = compact.find('=').unwrap_or(compact.len());
    let data = &compact[..first_padding];
    let padding = &compact[first_padding..];

    if padding.chars().any(|character| character != '=') {
        return Err(Base32Error::InvalidPadding);
    }
    if data.is_empty() || data.len() > MAX_DATA_CHARACTERS {
        return Err(Base32Error::InvalidLength);
    }

    let expected_padding = match data.len() % 8 {
        0 => 0,
        2 => 6,
        4 => 4,
        5 => 3,
        7 => 1,
        _ => return Err(Base32Error::InvalidLength),
    };
    if !padding.is_empty()
        && (!compact.len().is_multiple_of(8) || padding.len() != expected_padding)
    {
        return Err(Base32Error::InvalidPadding);
    }

    let mut output = Zeroizing::new(Vec::with_capacity(data.len().saturating_mul(5) / 8));
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;

    for character in data.chars() {
        let uppercase = character.to_ascii_uppercase();
        let value = match uppercase {
            'A'..='Z' => uppercase as u8 - b'A',
            '2'..='7' => uppercase as u8 - b'2' + 26,
            _ => return Err(Base32Error::InvalidCharacter),
        };

        accumulator = (accumulator << 5) | u32::from(value);
        bits += 5;

        if bits >= 8 {
            bits -= 8;
            output.push(((accumulator >> bits) & 0xFF) as u8);
            accumulator &= (1_u32 << bits) - 1;
        }
    }

    if bits > 0 && accumulator != 0 {
        return Err(Base32Error::NonZeroTrailingBits);
    }
    if output.is_empty() || output.len() > MAX_DECODED_BYTES {
        return Err(Base32Error::DecodedLengthOutOfRange);
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_rfc_4648_test_vectors() {
        let vectors: [(&str, &[u8]); 6] = [
            ("MY======", b"f"),
            ("MZXQ====", b"fo"),
            ("MZXW6===", b"foo"),
            ("MZXW6YQ=", b"foob"),
            ("MZXW6YTB", b"fooba"),
            ("MZXW6YTBOI======", b"foobar"),
        ];

        for (encoded, expected) in vectors {
            let decoded = decode_base32(encoded).expect("RFC 4648 vector should decode");
            assert_eq!(decoded.as_slice(), expected, "input {encoded}");
        }
    }

    #[test]
    fn accepts_unpadded_lowercase_and_separators() {
        let decoded = decode_base32("mzxw6-ytb oi").expect("formatted Base32 should decode");
        assert_eq!(decoded.as_slice(), b"foobar");
    }

    #[test]
    fn rejects_invalid_alphabet_and_length() {
        assert_eq!(
            decode_base32("M0").err(),
            Some(Base32Error::InvalidCharacter)
        );
        assert_eq!(decode_base32("A").err(), Some(Base32Error::InvalidLength));
        assert_eq!(decode_base32("   - ").err(), Some(Base32Error::EmptyInput));
    }

    #[test]
    fn rejects_malformed_padding() {
        assert_eq!(
            decode_base32("MY=====").err(),
            Some(Base32Error::InvalidPadding)
        );
        assert_eq!(
            decode_base32("M=Y=====").err(),
            Some(Base32Error::InvalidPadding)
        );
    }

    #[test]
    fn rejects_nonzero_unused_trailing_bits() {
        assert_eq!(
            decode_base32("MZ").err(),
            Some(Base32Error::NonZeroTrailingBits)
        );
        assert_eq!(
            decode_base32("MY").expect("canonical tail").as_slice(),
            b"f"
        );
    }

    #[test]
    fn enforces_input_and_decoded_size_bounds() {
        assert_eq!(
            decode_base32(&" ".repeat(MAX_INPUT_BYTES + 1)).err(),
            Some(Base32Error::InputTooLong)
        );
        assert_eq!(
            decode_base32(&"A".repeat(208)).err(),
            Some(Base32Error::DecodedLengthOutOfRange)
        );

        let maximum = format!("{}===", "A".repeat(205));
        assert_eq!(
            decode_base32(&maximum)
                .expect("128-byte secret is supported")
                .len(),
            MAX_DECODED_BYTES
        );
    }
}
