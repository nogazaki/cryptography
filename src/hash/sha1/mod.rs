use super::{DigestUser, Hasher, HasherCore};
use crate::utils::{
    self,
    block::{BlockBuffer, BlockUser},
};

const BLOCK_SIZE_BIT: usize = 512;
pub const BLOCK_SIZE_BYTE: usize = BLOCK_SIZE_BIT >> 3;

const DIGEST_SIZE_BIT: usize = 160;
pub const DIGEST_SIZE_BYTE: usize = DIGEST_SIZE_BIT >> 3;

/// Sha-1 core constants
const K: [u32; 4] = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];

#[inline(always)]
fn sha1_functions(x: u32, y: u32, z: u32, t: usize) -> u32 {
    match t {
        0..=19 => utils::choice!(x, y, z),
        20..=39 => x ^ y ^ z,
        40..=59 => utils::majority!(x, y, z),
        60..=79 => x ^ y ^ z,

        _ => unreachable!(),
    }
}

/// SHA-1 core hash computation for a single block
#[inline(always)]
fn sha1_core_digest_block(state: &mut [u32; 5], block: &[u8; BLOCK_SIZE_BYTE]) {
    let mut words = [0u32; 80];
    for (bytes, word) in block.chunks_exact(4).zip(words.iter_mut()) {
        *word = u32::from_be_bytes(bytes.try_into().unwrap_or_default());
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];

    for t in 0..80 {
        if t >= 16 {
            words[t] = (words[t - 3] ^ words[t - 8] ^ words[t - 14] ^ words[t - 16]).rotate_left(1);
        };

        let tmp = a
            .rotate_left(5)
            .wrapping_add(sha1_functions(b, c, d, t))
            .wrapping_add(e)
            .wrapping_add(K[t / 20])
            .wrapping_add(words[t]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = tmp;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

pub struct Sha1Core {
    state: [u32; 5],
    blocks_num: u64,
}

impl BlockUser for Sha1Core {
    const BLOCK_SIZE: usize = BLOCK_SIZE_BYTE;
}

impl DigestUser for Sha1Core {
    const DIGEST_SIZE: usize = DIGEST_SIZE_BYTE;
}

impl HasherCore for Sha1Core {
    type Buffer = BlockBuffer<{ BLOCK_SIZE_BYTE }>;

    fn new(_bit_len: usize) -> Self {
        let state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
        let blocks_num = 0;

        Sha1Core { state, blocks_num }
    }

    fn compress(&mut self, blocks: &[[u8; Self::BLOCK_SIZE]]) {
        self.blocks_num += blocks.len() as u64;

        for block in blocks.iter() {
            sha1_core_digest_block(&mut self.state, block);
        }
    }

    fn finalize(&mut self, buffer: &mut Self::Buffer, out: &mut [u8; Self::DIGEST_SIZE]) {
        const SUFFIX_POS: usize = Sha1Core::BLOCK_SIZE - core::mem::size_of::<u64>();

        let pos = buffer.get_pos();
        let msg_len = ((self.blocks_num * BLOCK_SIZE_BYTE as u64) + pos as u64) * 8;

        buffer.buf[pos] = 0x80;
        buffer.buf[pos + 1..].fill(0);

        if pos + 1 > SUFFIX_POS {
            self.compress(core::slice::from_ref(&buffer.buf));
            buffer.buf.fill(0);
        }

        buffer.buf[SUFFIX_POS..].clone_from_slice(&msg_len.to_be_bytes());
        self.compress(core::slice::from_ref(&buffer.buf));

        out.chunks_exact_mut(4)
            .zip(self.state.iter())
            .for_each(|(chunk, &hash)| chunk.copy_from_slice(&hash.to_be_bytes()))
    }
}

/// Secure Hash Algorithm 1 ([SHA-1](https://en.wikipedia.org/wiki/SHA-1))
///
/// # Example
///
/// ```
/// use cryptography::hash::{Sha1, Digest};
///
/// let message = "The quick brown fox jumps over the lazy dog";
/// let hash = [ 0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84,
///              0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12, ];
/// let mut hasher = Sha1::new();
/// hasher.update(message);
/// let result = hasher.finalize();
/// assert_eq!(result, hash);
///
/// let message = "The quick brown fox jumps over the lazy cog";
/// let hash = [ 0xde, 0x9f, 0x2c, 0x7f, 0xd2, 0x5e, 0x1b, 0x3a, 0xfa, 0xd3,
///              0xe8, 0x5a, 0x0b, 0xd1, 0x7d, 0x9b, 0x10, 0x0d, 0xb4, 0xb3, ];
/// let mut result = [0u8; 20];
/// Sha1::new().chain_update(message).finalize_into(&mut result);
/// assert_eq!(result, hash);
///
/// ```
pub type Sha1 = Hasher<Sha1Core, 160>;
