use crate::hash::DigestUser;
use crate::utils::block::BlockUser;

use super::{Finalize, Update};

pub(crate) trait HasherCore: BlockUser + DigestUser {
    type Buffer: Default + BlockUser;

    #[allow(non_upper_case_globals)]
    const value_check: () = assert!(Self::BLOCK_SIZE == Self::Buffer::BLOCK_SIZE);

    fn new(bit_len: usize) -> Self;
    fn compress(&mut self, blocks: &[[u8; Self::BLOCK_SIZE]]);
    fn finalize(&mut self, buffer: &mut Self::Buffer, out: &mut [u8; Self::DIGEST_SIZE]);
}

#[allow(private_bounds)]
pub struct Hasher<Core: HasherCore, const DIGEST_SIZE_BIT: usize> {
    core: Core,
    buffer: Core::Buffer,
}

impl<Core: HasherCore, const DIGEST_SIZE_BIT: usize> BlockUser for Hasher<Core, DIGEST_SIZE_BIT> {
    const BLOCK_SIZE: usize = Core::BLOCK_SIZE;
}

impl<Core: HasherCore, const DIGEST_SIZE_BIT: usize> DigestUser for Hasher<Core, DIGEST_SIZE_BIT> {
    const DIGEST_SIZE: usize = DIGEST_SIZE_BIT / 8;
}

impl<Core: HasherCore, const DIGEST_SIZE_BIT: usize> Default for Hasher<Core, DIGEST_SIZE_BIT> {
    fn default() -> Self {
        let core = Core::new(DIGEST_SIZE_BIT);
        let buffer = Default::default();

        Self { core, buffer }
    }
}

impl<Core, const DIGEST_SIZE_BIT: usize> Update for Hasher<Core, DIGEST_SIZE_BIT>
where
    Core: HasherCore,
    [(); Core::BLOCK_SIZE]:,
    [(); Core::Buffer::BLOCK_SIZE]:,
{
    fn trait_update(&mut self, data: &[u8]) {
        let Self { core, buffer } = self;

        buffer.process_data(data, |blocks: &[[u8; Core::Buffer::BLOCK_SIZE]]| {
            // SAFETY: Core::Buffer::BLOCK_SIZE is Core::BLOCK_SIZE
            core.compress(unsafe {
                core::slice::from_raw_parts(
                    blocks.as_ptr() as *const u8 as *const [u8; Core::BLOCK_SIZE],
                    blocks.len(),
                )
            });
        });
    }
}

impl<Core, const DIGEST_SIZE_BIT: usize> Finalize for Hasher<Core, DIGEST_SIZE_BIT>
where
    Core: HasherCore,
    [(); Core::DIGEST_SIZE]:,
{
    fn trait_finalize(&mut self, out: &mut [u8; Self::DIGEST_SIZE]) {
        let Self { core, buffer } = self;

        let mut full_digest = [0u8; Core::DIGEST_SIZE];
        core.finalize(buffer, &mut full_digest);

        out.copy_from_slice(&full_digest[..Self::DIGEST_SIZE])
    }
}
