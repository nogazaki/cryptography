//! Block cipher algorithms
use crate::ErrorCode;

// #[cfg(feature = "aes")]
pub mod aes;

pub mod cbc;
pub mod ecb;

pub trait BlockCipherInit {
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

pub trait Encrypt {
    fn encrypt(self, plain_text: &[u8], cipher_text: &mut [u8]) -> Result<(), ErrorCode>;
}

pub trait Decrypt {
    fn decrypt(self, cipher_text: &[u8], plain_text: &mut [u8]) -> Result<(), ErrorCode>;
}
