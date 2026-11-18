use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;

use super::{CryptoError, SecretKey};

/// XChaCha20-Poly1305 nonce length in bytes.
pub const NONCE_BYTES: usize = 24;

/// Poly1305 authentication-tag length in bytes.
pub const TAG_BYTES: usize = 16;

/// An authenticated ciphertext and its public nonce.
///
/// The nonce is not secret. A fresh random nonce is generated for every
/// encryption operation. The caller must authenticate vault metadata by
/// supplying it as associated data.
#[derive(Debug, PartialEq, Eq)]
pub struct EncryptedPayload {
    nonce: [u8; NONCE_BYTES],
    ciphertext: Vec<u8>,
}

impl EncryptedPayload {
    /// Construct an encrypted payload read from a serialized container.
    ///
    /// This checks only the minimum ciphertext length. Authentication is
    /// performed by decrypt before plaintext is returned.
    pub fn from_parts(nonce: [u8; NONCE_BYTES], ciphertext: Vec<u8>) -> Result<Self, CryptoError> {
        if ciphertext.len() < TAG_BYTES {
            return Err(CryptoError::InvalidCiphertext);
        }

        Ok(Self { nonce, ciphertext })
    }

    /// Return the public nonce.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; NONCE_BYTES] {
        &self.nonce
    }

    /// Return the ciphertext, including its authentication tag.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Consume the payload and return its nonce and ciphertext.
    #[must_use]
    pub fn into_parts(self) -> ([u8; NONCE_BYTES], Vec<u8>) {
        (self.nonce, self.ciphertext)
    }
}

/// Encrypt a message using XChaCha20-Poly1305 with a fresh random nonce.
///
/// Associated data is authenticated but not encrypted. The future vault
/// container must use this to bind the format version and security header.
pub fn encrypt(
    key: &SecretKey,
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<EncryptedPayload, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut nonce_bytes = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce_bytes).map_err(|_| CryptoError::RandomnessUnavailable)?;
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;

    EncryptedPayload::from_parts(nonce_bytes, ciphertext)
}

/// Authenticate and decrypt a payload.
///
/// Plaintext is returned in a zeroizing buffer so it is cleared when dropped.
/// Callers must still avoid making unnecessary copies of decrypted data.
pub fn decrypt(
    key: &SecretKey,
    payload: &EncryptedPayload,
    associated_data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose())
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let nonce = XNonce::from_slice(&payload.nonce);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: payload.ciphertext.as_ref(),
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypts_and_authenticates_payloads() {
        let key = SecretKey::from_bytes([0xA5; 32]);
        let plaintext = b"SuikaAuthenticator test vault";
        let aad = b"suika-vault-format-v1";

        let encrypted = encrypt(&key, plaintext, aad).expect("encryption should succeed");
        let recovered = decrypt(&key, &encrypted, aad).expect("decryption should succeed");

        assert_eq!(&recovered[..], plaintext);
        assert_eq!(encrypted.ciphertext().len(), plaintext.len() + TAG_BYTES);
    }

    #[test]
    fn rejects_wrong_associated_data() {
        let key = SecretKey::from_bytes([0x37; 32]);
        let encrypted = encrypt(&key, b"private", b"header-v1").expect("encryption should succeed");

        assert_eq!(
            decrypt(&key, &encrypted, b"header-v2").err(),
            Some(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn rejects_modified_ciphertext() {
        let key = SecretKey::from_bytes([0x91; 32]);
        let encrypted = encrypt(&key, b"tamper test", b"aad").expect("encryption should succeed");
        let (nonce, mut ciphertext) = encrypted.into_parts();
        ciphertext[0] ^= 0x01;

        let modified =
            EncryptedPayload::from_parts(nonce, ciphertext).expect("length remains valid");

        assert_eq!(
            decrypt(&key, &modified, b"aad").err(),
            Some(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn rejects_payload_without_an_authentication_tag() {
        assert_eq!(
            EncryptedPayload::from_parts([0_u8; NONCE_BYTES], vec![0_u8; TAG_BYTES - 1]).err(),
            Some(CryptoError::InvalidCiphertext)
        );
    }
}
