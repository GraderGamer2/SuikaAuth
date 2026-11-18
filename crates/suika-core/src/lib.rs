#![forbid(unsafe_code)]

//! Shared security and authentication primitives for SuikaAuthenticator.
//!
//! This crate deliberately contains no UI, filesystem, database server, network,
//! or operating-system keyring integration. Platform applications are
//! responsible for those concerns and must use this crate for core operations.

pub mod accounts;
pub mod base32;
pub mod crypto;
pub mod otp;
pub mod storage;
pub mod vault;
