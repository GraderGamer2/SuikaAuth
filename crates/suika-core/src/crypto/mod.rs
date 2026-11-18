//! Password-based key derivation and authenticated encryption.

mod aead;
mod error;
mod key;

pub use aead::{EncryptedPayload, NONCE_BYTES, TAG_BYTES, decrypt, encrypt};
pub use error::CryptoError;
pub use key::{KdfParams, SALT_BYTES, SecretKey, derive_wrapping_key, generate_salt};
