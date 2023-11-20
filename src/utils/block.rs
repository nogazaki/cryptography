//! Functionalities for types that operate on blocks

/// Trait for types that operate on blocks
pub(crate) trait BlockUser {
    const BLOCK_SIZE: usize;

    #[inline]
    fn get_block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }

    /// Splitting a slice into blocks, with leftover
    #[inline]
    fn split_blocks(data: &[u8]) -> (&[[u8; Self::BLOCK_SIZE]], &[u8]) {
        let blocks_num = data.len() / Self::BLOCK_SIZE;
        let blocks_len = blocks_num * Self::BLOCK_SIZE;
        let tail_len = data.len() - blocks_len;

        // SAFETY: created slices does not point outside of `data`
        unsafe {
            let blocks_ptr = data.as_ptr() as *const [u8; Self::BLOCK_SIZE];
            let tail_ptr = data.as_ptr().add(blocks_len);
            (
                core::slice::from_raw_parts(blocks_ptr, blocks_num),
                core::slice::from_raw_parts(tail_ptr, tail_len),
            )
        }
    }

    /// Process data in blocks, return the number of bytes not processed
    #[inline]
    fn process_data(
        &mut self,
        data: &[u8],
        mut processor: impl FnMut(&[[u8; Self::BLOCK_SIZE]]),
    ) -> usize {
        let (blocks, tail) = Self::split_blocks(data);
        processor(blocks);

        tail.len()
    }
}

pub(crate) struct BlockBuffer<const BLOCK_SIZE: usize> {
    pub buf: [u8; BLOCK_SIZE],
    pub pos: u8,
}

impl<const BLOCK_SIZE: usize> Default for BlockBuffer<BLOCK_SIZE> {
    fn default() -> Self {
        let buf = [0u8; BLOCK_SIZE];
        let pos = 0;

        Self { buf, pos }
    }
}

impl<const BLOCK_SIZE: usize> BlockBuffer<BLOCK_SIZE> {
    #[inline]
    pub fn get_remain(&self) -> usize {
        BLOCK_SIZE - self.get_pos()
    }
    #[inline]
    pub fn get_pos(&self) -> usize {
        self.pos as usize
    }
    #[inline]
    fn set_pos_uncheck(&mut self, pos: usize) {
        self.pos = pos as u8
    }
    // #[inline]
    // pub fn add_data(&mut self, data: &[u8]) -> Result<(), ()> {
    //     let len = data.len();

    //     if len > self.get_remain() {
    //         Err(())
    //     } else {
    //         let pos = self.get_pos();
    //         self.buf[pos..][..len].copy_from_slice(data);
    //         self.set_pos_uncheck(pos + len);

    //         Ok(())
    //     }
    // }
    // #[inline]
    // pub fn set_data_at_pos(&mut self, data: &[u8], pos: usize) -> Result<(), ()> {
    //     if pos > Self::BLOCK_SIZE {
    //         Err(())
    //     } else {
    //         self.set_pos_uncheck(pos);
    //         self.add_data(data)
    //     }
    // }
    // #[inline]
    // pub fn reset(&mut self) {
    //     *self = Default::default();
    // }
}

impl<const BLOCK_SIZE: usize> BlockUser for BlockBuffer<BLOCK_SIZE> {
    const BLOCK_SIZE: usize = BLOCK_SIZE;

    fn process_data(
        &mut self,
        mut data: &[u8],
        mut processor: impl FnMut(&[[u8; Self::BLOCK_SIZE]]),
    ) -> usize {
        let len = data.len();

        let pos = self.get_pos();
        let rem = self.get_remain();

        if len < rem {
            self.buf[pos..][..len].copy_from_slice(data);
            self.set_pos_uncheck(pos + len);
        } else {
            if pos != 0 {
                let (left, right) = data.split_at(rem);
                self.buf[pos..].copy_from_slice(left);
                // SAFETY: Self::BLOCK_SIZE is BLOCK_SIZE
                processor(unsafe {
                    core::slice::from_raw_parts(
                        &self.buf as *const u8 as *const [u8; Self::BLOCK_SIZE],
                        1,
                    )
                });

                data = right;
            }

            let (blocks, tail) = Self::split_blocks(data);
            if !blocks.is_empty() {
                processor(blocks)
            }

            self.buf[..tail.len()].copy_from_slice(tail);
            self.set_pos_uncheck(tail.len());
        }

        0
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn block_splitting() {
        const TAIL_LEN: usize = 3;
        const BLOCKS_NUM: usize = 5;
        const BLOCK_SIZE: usize = 16;

        struct S;
        impl BlockUser for S {
            const BLOCK_SIZE: usize = BLOCK_SIZE;
        }

        let data: [u8; BLOCK_SIZE * BLOCKS_NUM + TAIL_LEN] = core::array::from_fn(|i| i as u8);

        for i in 0..=BLOCKS_NUM {
            // No leftover bytes
            let (blocks, leftover) = S::split_blocks(&data[..BLOCK_SIZE * i]);
            assert_eq!(blocks.len(), i);
            for (offset, &block) in blocks.iter().enumerate() {
                assert_eq!(block, data[offset * BLOCK_SIZE..][..BLOCK_SIZE]);
            }
            assert_eq!(leftover.len(), 0);

            // Leftover bytes
            let (blocks, leftover) = S::split_blocks(&data[..BLOCK_SIZE * i + TAIL_LEN]);
            assert_eq!(blocks.len(), i);
            for (offset, &block) in blocks.iter().enumerate() {
                assert_eq!(block, data[offset * BLOCK_SIZE..][..BLOCK_SIZE]);
            }
            assert_eq!(leftover.len(), TAIL_LEN);
            assert_eq!(*leftover, data[BLOCK_SIZE * i..][..TAIL_LEN])
        }
    }
}
