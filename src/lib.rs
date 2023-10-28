//! Cryptography algorithms
//!
//! # Security Warning
//!
//! Theses implementations are for learning purposes and should not be used in anything serious.

#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
// no_std support is not on by default
#![cfg_attr(feature = "no_std", no_std)]

/// Error code definitions
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorCode {
    /// A wrong key type was provided
    WrongKeyType,
    /// An argument did not pass the check
    InvalidArgument,
    /// Provided pointer to receive data is not large enough
    InsufficientMemory,
    /// Unknown error code
    #[default]
    Unknown,
}

// Block cipher algorithms
pub mod block_cipher;
