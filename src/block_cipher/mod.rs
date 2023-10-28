//! Block cipher algorithms

use crate::ErrorCode;

// #[cfg(feature = "aes")]
pub mod aes;

pub trait KeyInit {
    /// Initialize the algorithm
    fn new(key: &[u8]) -> Result<Self, ErrorCode>
    where
        Self: Sized;
}
pub trait BlockCipher {
    /// Encrypt a block in place
    fn encrypt_block(&self, block: &mut [u8]) -> Result<(), ErrorCode>;
    /// Decrypt a block in place
    fn decrypt_block(&self, block: &mut [u8]) -> Result<(), ErrorCode>;
}
