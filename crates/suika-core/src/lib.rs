#![forbid(unsafe_code)]

//! Shared security and authentication primitives for SuikaAuthenticator.
//!
//! This crate deliberately contains no UI, filesystem, database, network, or
//! operating-system keyring integration. Platform applications are responsible
//! for those concerns and must use this crate for cryptographic operations.

pub mod crypto;
pub mod otp;
pub mod vault;
