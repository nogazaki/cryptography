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
    fn encrypt_block_in_place(&self, block: &mut [u8; Self::BLOCK_SIZE]);
    /// Decrypt a block in place
    fn decrypt_block_in_place(&self, block: &mut [u8; Self::BLOCK_SIZE]);

    /// Encrypt a block
    fn encrypt_block(&self, block: &[u8; Self::BLOCK_SIZE], out: &mut [u8; Self::BLOCK_SIZE]);
    /// Decrypt a block
    fn decrypt_block(&self, block: &[u8; Self::BLOCK_SIZE], out: &mut [u8; Self::BLOCK_SIZE]);
}
