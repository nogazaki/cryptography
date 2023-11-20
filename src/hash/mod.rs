//! Collection of [cryptographic hash functions]
//!
//! [cryptographic hash functions]: https://en.wikipedia.org/wiki/Cryptographic_hash_function

use crate::ErrorCode;

/// Types that calculate fixed-sized digests
pub trait DigestUser {
    const DIGEST_SIZE: usize;

    /// Get digest size in bytes
    #[inline]
    fn get_digest_size(&self) -> usize {
        Self::DIGEST_SIZE
    }
}

/// Functionalities of types that calculate fixed-sized digests
pub trait Digest: DigestUser {
    /// Create new hasher instance
    fn new() -> Self;
    /// Reset hasher instance
    fn reset(&mut self);

    /// Update hasher instance using provided data
    fn update(&mut self, data: impl AsRef<[u8]>);
    /// Update hasher instance using provided data, chainable
    fn chain_update(self, data: impl AsRef<[u8]>) -> Self;

    /// Finalize data, consume the hasher instance
    fn finalize(self) -> [u8; Self::DIGEST_SIZE];
    /// Finalize data into provided buffer, consume the hasher instance
    fn finalize_into(self, buffer: &mut [u8]) -> Result<usize, ErrorCode>;
    /// Finalize data, reset the hasher instance
    fn finalize_reset(&mut self) -> [u8; Self::DIGEST_SIZE];
    /// Finalize data into provided buffer, reset the hasher instance
    fn finalize_into_reset(&mut self, buffer: &mut [u8]) -> Result<usize, ErrorCode>;
}

/// Secure Hash Algorithm 1 ([SHA-1](https://en.wikipedia.org/wiki/SHA-1))
mod sha1;
pub use sha1::Sha1;
/// Secure Hash Algorithm 2 ([SHA-2](https://en.wikipedia.org/wiki/SHA-2))
mod sha2;
pub use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

/* -------------------------------------------------------------------------------- */

mod hasher;
use hasher::*;

pub(crate) trait Update {
    fn trait_update(&mut self, data: &[u8]);
}

pub(crate) trait Finalize: DigestUser {
    fn trait_finalize(&mut self, out: &mut [u8; Self::DIGEST_SIZE]);
}

impl<T> Digest for T
where
    T: DigestUser + Default + Update + Finalize,
    [(); Self::DIGEST_SIZE]:,
{
    #[inline]
    fn new() -> Self {
        Self::default()
    }
    #[inline]
    fn reset(&mut self) {
        *self = Self::default();
    }

    #[inline]
    fn update(&mut self, data: impl AsRef<[u8]>) {
        Update::trait_update(self, data.as_ref());
    }
    #[inline]
    fn chain_update(mut self, data: impl AsRef<[u8]>) -> Self {
        Update::trait_update(&mut self, data.as_ref());
        self
    }

    #[inline]
    fn finalize(mut self) -> [u8; Self::DIGEST_SIZE] {
        let mut out = [0u8; Self::DIGEST_SIZE];
        Finalize::trait_finalize(&mut self, &mut out);

        out
    }
    #[inline]
    fn finalize_into(self, buffer: &mut [u8]) -> Result<usize, ErrorCode> {
        if buffer.len() < Self::DIGEST_SIZE {
            return Err(ErrorCode::InsufficientMemory);
        }

        let digest = self.finalize();
        buffer[..Self::DIGEST_SIZE].copy_from_slice(&digest);

        Ok(Self::DIGEST_SIZE)
    }
    #[inline]
    fn finalize_reset(&mut self) -> [u8; Self::DIGEST_SIZE] {
        let mut out = [0u8; Self::DIGEST_SIZE];
        Finalize::trait_finalize(self, &mut out);
        *self = Default::default();

        out
    }
    #[inline]
    fn finalize_into_reset(&mut self, buffer: &mut [u8]) -> Result<usize, ErrorCode> {
        if buffer.len() < Self::DIGEST_SIZE {
            return Err(ErrorCode::InsufficientMemory);
        }

        let digest = self.finalize_reset();
        buffer[..Self::DIGEST_SIZE].copy_from_slice(&digest);

        Ok(Self::DIGEST_SIZE)
    }
}
