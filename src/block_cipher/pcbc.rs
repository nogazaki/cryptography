use super::*;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Encryptor<T: BlockCipherInit + BlockCipher>
where
    [(); T::BLOCK_SIZE]:,
{
    engine: T,
    iv: [u8; T::BLOCK_SIZE],
}
impl<T: BlockCipherInit + BlockCipher> Encryptor<T>
where
    [(); T::BLOCK_SIZE]:,
{
    #[inline]
    pub fn new(key: &[u8], iv: Option<&[u8; T::BLOCK_SIZE]>) -> Result<Self, ErrorCode> {
        Ok(Self {
            engine: T::new(key)?,
            iv: match iv {
                None => [0u8; T::BLOCK_SIZE],
                Some(&data) => data,
            },
        })
    }
}
impl<T: BlockCipherInit + BlockCipher> Encrypt for Encryptor<T>
where
    [(); T::BLOCK_SIZE]:,
{
    fn encrypt(mut self, plain_text: &[u8], cipher_text: &mut [u8]) -> Result<(), ErrorCode> {
        if plain_text.len() % T::BLOCK_SIZE != 0 {
            return Err(ErrorCode::InvalidArgument);
        }

        if cipher_text.len() < plain_text.len() {
            return Err(ErrorCode::InsufficientMemory);
        }

        for i in (0..plain_text.len()).step_by(T::BLOCK_SIZE) {
            self.iv
                .iter_mut()
                .zip(plain_text[i..i + T::BLOCK_SIZE].iter())
                .for_each(|(prev, &plain)| *prev ^= plain);

            self.engine.encrypt_block_in_place(&mut self.iv);
            cipher_text[i..i + T::BLOCK_SIZE].clone_from_slice(&self.iv);

            self.iv
                .iter_mut()
                .zip(plain_text[i..i + T::BLOCK_SIZE].iter())
                .for_each(|(prev, &plain)| *prev ^= plain);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Decryptor<T: BlockCipherInit + BlockCipher>
where
    [(); T::BLOCK_SIZE]:,
{
    engine: T,
    iv: [u8; T::BLOCK_SIZE],
}
impl<T: BlockCipherInit + BlockCipher> Decryptor<T>
where
    [(); T::BLOCK_SIZE]:,
{
    #[inline]
    pub fn new(key: &[u8], iv: Option<&[u8; T::BLOCK_SIZE]>) -> Result<Self, ErrorCode> {
        Ok(Self {
            engine: T::new(key)?,
            iv: match iv {
                None => [0u8; T::BLOCK_SIZE],
                Some(&data) => data,
            },
        })
    }
}
impl<T: BlockCipherInit + BlockCipher> Decrypt for Decryptor<T>
where
    [(); T::BLOCK_SIZE]:,
{
    fn decrypt(mut self, cipher_text: &[u8], plain_text: &mut [u8]) -> Result<(), ErrorCode> {
        if cipher_text.len() % T::BLOCK_SIZE != 0 {
            return Err(ErrorCode::InvalidArgument);
        }

        if plain_text.len() < cipher_text.len() {
            return Err(ErrorCode::InsufficientMemory);
        }

        for i in (0..cipher_text.len()).step_by(T::BLOCK_SIZE) {
            let mut block = [0u8; T::BLOCK_SIZE];
            self.engine.decrypt_block(
                (&cipher_text[i..i + T::BLOCK_SIZE])
                    .try_into()
                    .expect("a slice of `BLOCK_SIZE` is guaranteed"),
                &mut block,
            );

            plain_text[i..i + T::BLOCK_SIZE]
                .iter_mut()
                .zip(self.iv.iter())
                .zip(block.iter())
                .for_each(|((plain, &b), &c)| *plain = b ^ c);

            self.iv
                .iter_mut()
                .zip(plain_text[i..i + T::BLOCK_SIZE].iter())
                .zip(cipher_text[i..i + T::BLOCK_SIZE].iter())
                .for_each(|((plain, &b), &c)| *plain = b ^ c);
        }

        Ok(())
    }
}

/// Test module
#[cfg(test)]
mod test {
    use super::{aes::*, *};

    #[test]
    fn error_handling() {
        let key = [0xAA; 32];
        let iv = [0xAA; 16];

        assert!(
            Encryptor::<Aes192>::new(&key, None)
                .is_err_and(|err| err == ErrorCode::InvalidArgument),
            "Key too long, initialization should have failed"
        );
        assert!(
            Decryptor::<Aes192>::new(&key, None)
                .is_err_and(|err| err == ErrorCode::InvalidArgument),
            "Key too long, initialization should have failed"
        );

        let plain_text = [0xAA; 32];
        let mut cipher_text = plain_text.clone();
        let encryptor = Encryptor::<Aes256>::new(&key, None).expect("Key buffer is valid");
        let result = encryptor.encrypt(&plain_text[0..15], &mut cipher_text);
        assert!(
            result.is_err_and(|err| err == ErrorCode::InvalidArgument),
            "Plain text length is not divisible by block length, encryption should have failed"
        );
        assert_eq!(
            cipher_text, plain_text,
            "Nothing has been written to output buffer"
        );

        let cipher_text = [0xAA; 32];
        let mut plain_text = cipher_text.clone();
        let decryptor = Decryptor::<Aes256>::new(&key, None).expect("Key buffer is valid");
        let result = decryptor.decrypt(&cipher_text[0..15], &mut plain_text);
        assert!(
            result.is_err_and(|err| err == ErrorCode::InvalidArgument),
            "Plain text length is not divisible by block length, encryption should have failed"
        );
        assert_eq!(
            plain_text, cipher_text,
            "Nothing has been written to output buffer"
        );

        let encryptor = Encryptor::<Aes256>::new(&key, None).expect("Key buffer is valid");
        assert_eq!(encryptor.iv, [0u8; 16]);
        let encryptor = Encryptor::<Aes256>::new(&key, Some(&iv)).expect("Key buffer is valid");
        assert_eq!(encryptor.iv, iv);

        let decryptor = Decryptor::<Aes256>::new(&key, None).expect("Key buffer is valid");
        assert_eq!(decryptor.iv, [0u8; 16]);
        let decryptor = Decryptor::<Aes256>::new(&key, Some(&iv)).expect("Key buffer is valid");
        assert_eq!(decryptor.iv, iv);
    }

    #[test]
    fn correctness() {
        // TODO: find test vectors
    }
}
