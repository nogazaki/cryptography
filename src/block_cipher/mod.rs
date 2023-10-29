//! Block cipher algorithms
use crate::ErrorCode;

// #[cfg(feature = "aes")]
pub mod aes;

pub mod ecb;

pub trait KeyInit {
    /// Initialize the algorithm
    fn new(key: &[u8]) -> Result<Self, ErrorCode>
    where
        Self: Sized;
}

pub trait BlockCipher {
    /// Fixed-length in bytes of a block
    const BLOCK_SIZE: usize;
    /// Encrypt a block in place
    fn encrypt_block(&self, in_block: &[u8], out_block: &mut [u8]) -> Result<usize, ErrorCode>;
    /// Decrypt a block in place
    fn decrypt_block(&self, in_block: &[u8], out_block: &mut [u8]) -> Result<usize, ErrorCode>;
}
