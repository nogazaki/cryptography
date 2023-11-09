//! Advanced Encryption Standard ([AES], a.k.a. Rijndael).
//!
//! [AES]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard

use super::*;

/// Rijndael forward look up table
const S_BOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Rijndael inverse look up table
const S_BOX_INV: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

const AES_BLOCK_SIZE_BYTES: usize = 16;

/// Round key addition
///
/// Each bytes of the state is combined with a byte of the round key using bitwise XOR
///
/// # Arguments
///
/// * `state` - current AES state block
/// * `key` - slice containing the round key to be add to `state`
///
fn add_round_key(state: &mut [u32; 4], key: &[u32]) {
    for i in 0..4 {
        state[i] ^= key[i];
    }
}

/// Non-linear substitution step where each byte is replaced with another according to [S_BOX]
///
/// # Arguments
///
/// * `state` - current AES state block
///
fn sub_bytes(state: &mut [u32; 4]) {
    for word in state {
        let bytes = (*word).to_be_bytes().map(|byte| S_BOX[byte as usize]);
        *word = u32::from_be_bytes(bytes);
    }
}
/// Non-linear substitution step where each byte is replaced with another according to [S_BOX_INV]
///
/// # Arguments
///
/// * `state` - current AES state block
///
fn inv_sub_bytes(state: &mut [u32; 4]) {
    for word in state {
        let bytes = (*word).to_be_bytes().map(|byte| S_BOX_INV[byte as usize]);
        *word = u32::from_be_bytes(bytes);
    }
}

/// Transposition step where each row of the state is shifted cyclically a certain number of steps to the left
///
/// # Arguments
///
/// * `state` - current AES state block
///
fn shift_rows(state: &mut [u32; 4]) {
    #[rustfmt::skip]
    let s0 = (state[0] & (0xff << 24)) | (state[1] & (0xff << 16)) | (state[2] & (0xff << 8)) | (state[3] & 0xff);
    #[rustfmt::skip]
    let s1 = (state[1] & (0xff << 24)) | (state[2] & (0xff << 16)) | (state[3] & (0xff << 8)) | (state[0] & 0xff);
    #[rustfmt::skip]
    let s2 = (state[2] & (0xff << 24)) | (state[3] & (0xff << 16)) | (state[0] & (0xff << 8)) | (state[1] & 0xff);
    #[rustfmt::skip]
    let s3 = (state[3] & (0xff << 24)) | (state[0] & (0xff << 16)) | (state[1] & (0xff << 8)) | (state[2] & 0xff);

    (state[0], state[1], state[2], state[3]) = (s0, s1, s2, s3);
}
/// Transposition step where each row of the state is shifted cyclically a certain number of steps to the right
///
/// # Arguments
///
/// * `state` - current AES state block
///
fn inv_shift_rows(state: &mut [u32; 4]) {
    #[rustfmt::skip]
    let s0 = (state[0] & (0xff << 24)) | (state[3] & (0xff << 16)) | (state[2] & (0xff << 8)) | (state[1] & 0xff);
    #[rustfmt::skip]
    let s1 = (state[1] & (0xff << 24)) | (state[0] & (0xff << 16)) | (state[3] & (0xff << 8)) | (state[2] & 0xff);
    #[rustfmt::skip]
    let s2 = (state[2] & (0xff << 24)) | (state[1] & (0xff << 16)) | (state[0] & (0xff << 8)) | (state[3] & 0xff);
    #[rustfmt::skip]
    let s3 = (state[3] & (0xff << 24)) | (state[2] & (0xff << 16)) | (state[1] & (0xff << 8)) | (state[0] & 0xff);

    (state[0], state[1], state[2], state[3]) = (s0, s1, s2, s3);
}

/// Galois Field multiplication for G(2^8)
///
/// # Arguments
///
/// * `a`, `b` - two number to be multiplied
///
/// * return the product `a` * `b` in G(2^8)
///
pub(self) fn g_256_multiply(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;

    for _ in 0..8 {
        if b & 1 != 0 {
            product ^= a;
        }
        if a & 0x80 != 0 {
            a = (a << 1) ^ 0x1b
        } else {
            a <<= 1
        }

        b >>= 1;
    }

    product
}

/// Linear mixing operation which operates on the columns of the state, combining the four bytes in each column
///
/// # Arguments
///
/// * `state` - current AES state block
///
fn mix_columns(state: &mut [u32; 4]) {
    for word in state {
        let bytes = (*word).to_be_bytes();
        *word = u32::from_be_bytes([
            g_256_multiply(bytes[0], 2) ^ g_256_multiply(bytes[1], 3) ^ bytes[2] ^ bytes[3],
            bytes[0] ^ g_256_multiply(bytes[1], 2) ^ g_256_multiply(bytes[2], 3) ^ bytes[3],
            bytes[0] ^ bytes[1] ^ g_256_multiply(bytes[2], 2) ^ g_256_multiply(bytes[3], 3),
            g_256_multiply(bytes[0], 3) ^ bytes[1] ^ bytes[2] ^ g_256_multiply(bytes[3], 2),
        ])
    }
}
/// Linear mixing operation which operates on the columns of the state, combining the four bytes in each column
///
/// # Arguments
///
/// * `state` - current AES state block
///
fn inv_mix_columns(state: &mut [u32; 4]) {
    for word in state {
        let bytes = (*word).to_be_bytes();
        *word = u32::from_be_bytes([
            g_256_multiply(bytes[0], 0x0e)
                ^ g_256_multiply(bytes[1], 0x0b)
                ^ g_256_multiply(bytes[2], 0x0d)
                ^ g_256_multiply(bytes[3], 0x09),
            g_256_multiply(bytes[0], 0x09)
                ^ g_256_multiply(bytes[1], 0x0e)
                ^ g_256_multiply(bytes[2], 0x0b)
                ^ g_256_multiply(bytes[3], 0x0d),
            g_256_multiply(bytes[0], 0x0d)
                ^ g_256_multiply(bytes[1], 0x09)
                ^ g_256_multiply(bytes[2], 0x0e)
                ^ g_256_multiply(bytes[3], 0x0b),
            g_256_multiply(bytes[0], 0x0b)
                ^ g_256_multiply(bytes[1], 0x0d)
                ^ g_256_multiply(bytes[2], 0x09)
                ^ g_256_multiply(bytes[3], 0x0e),
        ])
    }
}

/// AES cipher, encrypt a block in place
///
/// # Arguments
///
/// * `block` - AES block to be encrypted
/// * `round_keys` - expanded AES key, whose length determind AES 'flavour'
///
fn aes_encrypt_block(block: &mut [u8; AES_BLOCK_SIZE_BYTES], round_keys: &[u32]) {
    let mut state = [
        u32::from_be_bytes([block[00], block[01], block[02], block[03]]),
        u32::from_be_bytes([block[04], block[05], block[06], block[07]]),
        u32::from_be_bytes([block[08], block[09], block[10], block[11]]),
        u32::from_be_bytes([block[12], block[13], block[14], block[15]]),
    ];

    add_round_key(&mut state, &round_keys[0..4]);

    for round in 1..round_keys.len() / 4 - 1 {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, &round_keys[round * 4..][..4]);
    }

    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &round_keys[round_keys.len() - 4..]);

    for i in 0..4 {
        block[i * 4..][..4].copy_from_slice(&state[i].to_be_bytes());
    }
}
/// AES inverse cipher, decrypt a block in place
///
/// # Arguments
///
/// * `block` - AES block to be decrypted
/// * `round_keys` - expanded AES key, whose length determind AES 'flavour'
///
fn aes_decrypt_block(block: &mut [u8; AES_BLOCK_SIZE_BYTES], round_keys: &[u32]) {
    let mut state = [
        u32::from_be_bytes([block[00], block[01], block[02], block[03]]),
        u32::from_be_bytes([block[04], block[05], block[06], block[07]]),
        u32::from_be_bytes([block[08], block[09], block[10], block[11]]),
        u32::from_be_bytes([block[12], block[13], block[14], block[15]]),
    ];

    add_round_key(&mut state, &round_keys[round_keys.len() - 4..]);

    for round in (1..round_keys.len() / 4 - 1).rev() {
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, &round_keys[round * 4..][..4]);
        inv_mix_columns(&mut state);
    }

    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    add_round_key(&mut state, &round_keys[0..4]);

    for i in 0..4 {
        block[i * 4..][..4].copy_from_slice(&state[i].to_be_bytes());
    }
}
/// AES key expansion routine
///
/// # Arguments
///
/// * `key` - slice containing AES key to be expanded
/// * `round_keys` - slice to receive expanded AES key
///
fn aes_key_expand(key: &[u8], round_keys: &mut [u32]) {
    let mut r_cons = 1u8;

    let nk = key.len() / 4;

    for i in 0..nk {
        round_keys[i] = u32::from_be_bytes([
            key[i * 4 + 0],
            key[i * 4 + 1],
            key[i * 4 + 2],
            key[i * 4 + 3],
        ])
    }

    for i in nk..round_keys.len() {
        let mut word = round_keys[i - 1];
        if i % nk == 0 {
            let mut bytes = word.to_be_bytes().map(|byte| S_BOX[byte as usize]);
            bytes.rotate_left(1);

            word = u32::from_be_bytes(bytes) ^ ((r_cons as u32) << 24);
            r_cons = g_256_multiply(r_cons, 2);
        } else if (nk > 6) && (i % nk == 4) {
            let bytes = word.to_be_bytes().map(|byte| S_BOX[byte as usize]);
            word = u32::from_be_bytes(bytes);
        }
        round_keys[i] = round_keys[i - nk] ^ word;
    }
}

macro_rules! define_and_implement {
    ($name:ident, $key_size:literal) => {
        #[doc = concat!("AES algorithm, ", $key_size, "bits 'flavour'")]
        /// # Example
        ///
        /// ```
        /// use cryptography::block_cipher::{BlockCipherInit, aes::*};
        ///
        #[doc = concat!("let cipher_key = [0u8; ", $key_size, " / 8];")]
        #[doc = concat!("let aes = Aes", $key_size, "::new(&cipher_key);")]
        ///
        /// assert!(aes.is_ok());
        /// ```
        ///
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name {
            key: [u32; $key_size / 8 + 28],
        }
        impl BlockCipherInit for $name {
            /// Initialize and schedule a key for the algorithm
            fn new(key: &[u8]) -> Result<Self, ErrorCode> {
                if key.len() != $key_size / 8 {
                    return Err(ErrorCode::InvalidArgument);
                }
                let mut round_keys = [0u32; $key_size / 8 + 28];
                aes_key_expand(key, &mut round_keys);

                Ok(Self { key: round_keys })
            }
        }
        impl BlockCipher for $name {
            /// Fixed-length in bytes of a block
            const BLOCK_SIZE: usize = AES_BLOCK_SIZE_BYTES;

            /// Encrypt a block in place
            fn encrypt_block_in_place(&self, block: &mut [u8; Self::BLOCK_SIZE]) {
                aes_encrypt_block(block, &self.key)
            }
            /// Decrypt a block in place
            fn decrypt_block_in_place(&self, block: &mut [u8; Self::BLOCK_SIZE]) {
                aes_decrypt_block(block, &self.key)
            }

            /// Encrypt a block
            fn encrypt_block(
                &self,
                block: &[u8; Self::BLOCK_SIZE],
                out: &mut [u8; Self::BLOCK_SIZE],
            ) {
                let mut internal = block.clone();
                aes_encrypt_block(&mut internal, &self.key);

                out.clone_from_slice(&internal)
            }
            /// Decrypt a block
            fn decrypt_block(
                &self,
                block: &[u8; Self::BLOCK_SIZE],
                out: &mut [u8; Self::BLOCK_SIZE],
            ) {
                let mut internal = block.clone();
                aes_decrypt_block(&mut internal, &self.key);

                out.clone_from_slice(&internal)
            }
        }
        impl Drop for $name {
            fn drop(&mut self) {
                self.key.fill(0)
            }
        }
    };
}

define_and_implement!(Aes128, 128);
define_and_implement!(Aes192, 192);
define_and_implement!(Aes256, 256);

/// Test module
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn g256_multiply_correctness() {
        let mut num = 0x01;

        let exponents = [
            0x01, 0xe5, 0x4c, 0xb5, 0xfb, 0x9f, 0xfc, 0x12, 0x03, 0x34, 0xd4, 0xc4, 0x16, 0xba,
            0x1f, 0x36, 0x05, 0x5c, 0x67, 0x57, 0x3a, 0xd5, 0x21, 0x5a, 0x0f, 0xe4, 0xa9, 0xf9,
            0x4e, 0x64, 0x63, 0xee, 0x11, 0x37, 0xe0, 0x10, 0xd2, 0xac, 0xa5, 0x29, 0x33, 0x59,
            0x3b, 0x30, 0x6d, 0xef, 0xf4, 0x7b, 0x55, 0xeb, 0x4d, 0x50, 0xb7, 0x2a, 0x07, 0x8d,
            0xff, 0x26, 0xd7, 0xf0, 0xc2, 0x7e, 0x09, 0x8c, 0x1a, 0x6a, 0x62, 0x0b, 0x5d, 0x82,
            0x1b, 0x8f, 0x2e, 0xbe, 0xa6, 0x1d, 0xe7, 0x9d, 0x2d, 0x8a, 0x72, 0xd9, 0xf1, 0x27,
            0x32, 0xbc, 0x77, 0x85, 0x96, 0x70, 0x08, 0x69, 0x56, 0xdf, 0x99, 0x94, 0xa1, 0x90,
            0x18, 0xbb, 0xfa, 0x7a, 0xb0, 0xa7, 0xf8, 0xab, 0x28, 0xd6, 0x15, 0x8e, 0xcb, 0xf2,
            0x13, 0xe6, 0x78, 0x61, 0x3f, 0x89, 0x46, 0x0d, 0x35, 0x31, 0x88, 0xa3, 0x41, 0x80,
            0xca, 0x17, 0x5f, 0x53, 0x83, 0xfe, 0xc3, 0x9b, 0x45, 0x39, 0xe1, 0xf5, 0x9e, 0x19,
            0x5e, 0xb6, 0xcf, 0x4b, 0x38, 0x04, 0xb9, 0x2b, 0xe2, 0xc1, 0x4a, 0xdd, 0x48, 0x0c,
            0xd0, 0x7d, 0x3d, 0x58, 0xde, 0x7c, 0xd8, 0x14, 0x6b, 0x87, 0x47, 0xe8, 0x79, 0x84,
            0x73, 0x3c, 0xbd, 0x92, 0xc9, 0x23, 0x8b, 0x97, 0x95, 0x44, 0xdc, 0xad, 0x40, 0x65,
            0x86, 0xa2, 0xa4, 0xcc, 0x7f, 0xec, 0xc0, 0xaf, 0x91, 0xfd, 0xf7, 0x4f, 0x81, 0x2f,
            0x5b, 0xea, 0xa8, 0x1c, 0x02, 0xd1, 0x98, 0x71, 0xed, 0x25, 0xe3, 0x24, 0x06, 0x68,
            0xb3, 0x93, 0x2c, 0x6f, 0x3e, 0x6c, 0x0a, 0xb8, 0xce, 0xae, 0x74, 0xb1, 0x42, 0xb4,
            0x1e, 0xd3, 0x49, 0xe9, 0x9c, 0xc8, 0xc6, 0xc7, 0x22, 0x6e, 0xdb, 0x20, 0xbf, 0x43,
            0x51, 0x52, 0x66, 0xb2, 0x76, 0x60, 0xda, 0xc5, 0xf3, 0xf6, 0xaa, 0xcd, 0x9a, 0xa0,
            0x75, 0x54, 0x0e, 0x01,
        ];

        for i in 1..256 {
            num = g_256_multiply(num, 0xe5);
            assert_eq!(num, exponents[i]);
        }
    }

    #[test]
    fn add_round_key_correctness() {
        let mut state = [0x3243f6a8, 0x885a308d, 0x313198a2, 0xe0370734];
        let round_key = [0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c];

        add_round_key(&mut state, &round_key);
        assert_eq!(state, [0x193de3be, 0xa0f4e22b, 0x9ac68d2a, 0xe9f84808]);
    }

    #[test]
    fn sub_bytes_and_inverse_sub_bytes_correctness() {
        let original = [0x193de3be, 0xa0f4e22b, 0x9ac68d2a, 0xe9f84808];
        let substituted = [0xd42711ae, 0xe0bf98f1, 0xb8b45de5, 0x1e415230];

        let mut state = original.clone();

        sub_bytes(&mut state);
        assert_eq!(state, substituted);
        inv_sub_bytes(&mut state);
        assert_eq!(state, original);
    }

    #[test]
    fn shift_rows_and_inverse_shift_row_correctness() {
        let original = [0xd42711ae, 0xe0bf98f1, 0xb8b45de5, 0x1e415230];
        let shifted = [0xd4bf5d30, 0xe0b452ae, 0xb84111f1, 0x1e2798e5];

        let mut state = original.clone();

        shift_rows(&mut state);
        assert_eq!(state, shifted);
        inv_shift_rows(&mut state);
        assert_eq!(state, original);
    }

    #[test]
    fn mix_columns_and_inverse_mix_column_correctness() {
        let original = [0xd4bf5d30, 0xe0b452ae, 0xb84111f1, 0x1e2798e5];
        let mixed = [0x046681e5, 0xe0cb199a, 0x48f8d37a, 0x2806264c];

        let mut state = original.clone();

        mix_columns(&mut state);
        assert_eq!(state, mixed);
        inv_mix_columns(&mut state);
        assert_eq!(state, original);
    }

    #[test]
    fn key_expansion_error_handling() {
        let key = [0u8; 33];

        // AES-128 key expansion
        assert!(
            Aes128::new(&key[..15]).is_err_and(|err| err == ErrorCode::InvalidArgument),
            "Key too short, initialization should have failed"
        );
        assert!(
            Aes128::new(&key[..17]).is_err_and(|err| err == ErrorCode::InvalidArgument),
            "Key too long, initialization should have failed"
        );

        // AES-192 key expansion
        assert!(
            Aes192::new(&key[..23]).is_err_and(|err| err == ErrorCode::InvalidArgument),
            "Key too short, initialization should have failed"
        );
        assert!(
            Aes192::new(&key[..25]).is_err_and(|err| err == ErrorCode::InvalidArgument),
            "Key too long, initialization should have failed"
        );

        assert!(
            Aes256::new(&key[..31]).is_err_and(|err| err == ErrorCode::InvalidArgument),
            "Key too short, initialization should have failed"
        );
        assert!(
            Aes256::new(&key[..33]).is_err_and(|err| err == ErrorCode::InvalidArgument),
            "Key too long, initialization should have failed"
        );
    }

    #[test]
    fn key_expansion_correctness() {
        // AES-128 key expansion
        let cipher_key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let expanded_cipher_key = [
            0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c, 0xa0fafe17, 0x88542cb1, 0x23a33939,
            0x2a6c7605, 0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f, 0x3d80477d, 0x4716fe3e,
            0x1e237e44, 0x6d7a883b, 0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00, 0xd4d1c6f8,
            0x7c839d87, 0xcaf2b8bc, 0x11f915bc, 0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
            0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f, 0xead27321, 0xb58dbad2, 0x312bf560,
            0x7f8d292f, 0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e, 0xd014f9a8, 0xc9ee2589,
            0xe13f0cc8, 0xb6630ca6,
        ];

        assert!(
            Aes128::new(&cipher_key).is_ok_and(|aes| aes.key == expanded_cipher_key),
            "Key expansion operation failed unexpectedly or result was incorrect"
        );

        // AES-192 key expansion
        let cipher_key = [
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90,
            0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
        ];
        let expanded_cipher_key = [
            0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 0x62f8ead2, 0x522c6b7b, 0xfe0c91f7,
            0x2402f5a5, 0xec12068e, 0x6c827f6b, 0x0e7a95b9, 0x5c56fec2, 0x4db7b4bd, 0x69b54118,
            0x85a74796, 0xe92538fd, 0xe75fad44, 0xbb095386, 0x485af057, 0x21efb14f, 0xa448f6d9,
            0x4d6dce24, 0xaa326360, 0x113b30e6, 0xa25e7ed5, 0x83b1cf9a, 0x27f93943, 0x6a94f767,
            0xc0a69407, 0xd19da4e1, 0xec1786eb, 0x6fa64971, 0x485f7032, 0x22cb8755, 0xe26d1352,
            0x33f0b7b3, 0x40beeb28, 0x2f18a259, 0x6747d26b, 0x458c553e, 0xa7e1466c, 0x9411f1df,
            0x821f750a, 0xad07d753, 0xca400538, 0x8fcc5006, 0x282d166a, 0xbc3ce7b5, 0xe98ba06f,
            0x448c773c, 0x8ecc7204, 0x01002202,
        ];

        assert!(
            Aes192::new(&cipher_key).is_ok_and(|aes| aes.key == expanded_cipher_key),
            "Key expansion operation failed unexpectedly or result was incorrect"
        );

        // AES-256 key expansion
        let cipher_key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let expanded_cipher_key = [
            0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3,
            0x0914dff4, 0x9ba35411, 0x8e6925af, 0xa51a8b5f, 0x2067fcde, 0xa8b09c1a, 0x93d194cd,
            0xbe49846e, 0xb75d5b9a, 0xd59aecb8, 0x5bf3c917, 0xfee94248, 0xde8ebe96, 0xb5a9328a,
            0x2678a647, 0x98312229, 0x2f6c79b3, 0x812c81ad, 0xdadf48ba, 0x24360af2, 0xfab8b464,
            0x98c5bfc9, 0xbebd198e, 0x268c3ba7, 0x09e04214, 0x68007bac, 0xb2df3316, 0x96e939e4,
            0x6c518d80, 0xc814e204, 0x76a9fb8a, 0x5025c02d, 0x59c58239, 0xde136967, 0x6ccc5a71,
            0xfa256395, 0x9674ee15, 0x5886ca5d, 0x2e2f31d7, 0x7e0af1fa, 0x27cf73c3, 0x749c47ab,
            0x18501dda, 0xe2757e4f, 0x7401905a, 0xcafaaae3, 0xe4d59b34, 0x9adf6ace, 0xbd10190d,
            0xfe4890d1, 0xe6188d0b, 0x046df344, 0x706c631e,
        ];

        assert!(
            Aes256::new(&cipher_key).is_ok_and(|aes| aes.key == expanded_cipher_key),
            "Key expansion operation failed unexpectedly or result was incorrect"
        );
    }

    #[test]
    fn correctness() {
        {
            let key = [0u8; AES_BLOCK_SIZE_BYTES];
            let mut block = [0u8; AES_BLOCK_SIZE_BYTES];
            let mut result = [0u8; AES_BLOCK_SIZE_BYTES];

            let aes = Aes128::new(&key).expect("Key buffer is valid");

            aes.encrypt_block(&block, &mut result);
            let _ = aes.encrypt_block_in_place(&mut block);
            assert!(result == block);

            aes.encrypt_block(&block, &mut result);
            let _ = aes.encrypt_block_in_place(&mut block);
            assert!(result == block);
        }

        let plain_text = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];

        // AES-128 cipher
        let cipher_text = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];
        let mut block = plain_text.clone();
        let aes = Aes128::new(&key[0..16]).expect("Key buffer is valid");
        aes.encrypt_block_in_place(&mut block);
        assert_eq!(block, cipher_text);
        aes.decrypt_block_in_place(&mut block);
        assert_eq!(block, plain_text);

        // AES-192 cipher
        let cipher_text = [
            0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d,
            0x71, 0x91,
        ];
        let mut block = plain_text.clone();
        let aes = Aes192::new(&key[0..24]).expect("Key buffer is valid");
        aes.encrypt_block_in_place(&mut block);
        assert_eq!(block, cipher_text);
        aes.decrypt_block_in_place(&mut block);
        assert_eq!(block, plain_text);

        // AES-256 cipher
        let cipher_text = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ];
        let mut block = plain_text.clone();
        let aes = Aes256::new(&key[0..32]).expect("Key buffer is valid");
        aes.encrypt_block_in_place(&mut block);
        assert_eq!(block, cipher_text);
        aes.decrypt_block_in_place(&mut block);
        assert_eq!(block, plain_text);
    }
}
