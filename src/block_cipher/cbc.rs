use super::*;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Encryptor<T: KeyInit + BlockCipher>
where
    [(); T::BLOCK_SIZE]:,
{
    engine: T,
    iv: [u8; T::BLOCK_SIZE],
}
impl<T: KeyInit + BlockCipher> Encryptor<T>
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
impl<T: KeyInit + BlockCipher> Encrypt for Encryptor<T>
where
    [(); T::BLOCK_SIZE]:,
{
    fn encrypt(&mut self, plain_text: &[u8], cipher_text: &mut [u8]) -> Result<(), ErrorCode> {
        if plain_text.len() % T::BLOCK_SIZE != 0 {
            return Err(ErrorCode::InvalidArgument);
        }

        if cipher_text.len() < plain_text.len() {
            return Err(ErrorCode::InsufficientMemory);
        }

        let mut context = self.iv.clone();
        for i in (0..plain_text.len()).step_by(T::BLOCK_SIZE) {
            context
                .iter_mut()
                .zip(plain_text[i..i + T::BLOCK_SIZE].iter())
                .for_each(|(prev, &plain)| *prev ^= plain);

            self.engine.encrypt_block_in_place(&mut context);

            cipher_text[i..i + T::BLOCK_SIZE].clone_from_slice(&context);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Decryptor<T: KeyInit + BlockCipher>
where
    [(); T::BLOCK_SIZE]:,
{
    engine: T,
    iv: [u8; T::BLOCK_SIZE],
}
impl<T: KeyInit + BlockCipher> Decryptor<T>
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
impl<T: KeyInit + BlockCipher> Decrypt for Decryptor<T>
where
    [(); T::BLOCK_SIZE]:,
{
    fn decrypt(&mut self, cipher_text: &[u8], plain_text: &mut [u8]) -> Result<(), ErrorCode> {
        if cipher_text.len() % T::BLOCK_SIZE != 0 {
            return Err(ErrorCode::InvalidArgument);
        }

        if plain_text.len() < cipher_text.len() {
            return Err(ErrorCode::InsufficientMemory);
        }

        let mut context = self.iv.clone();
        for i in (0..plain_text.len()).step_by(T::BLOCK_SIZE) {
            let mut block = [0u8; T::BLOCK_SIZE];
            self.engine.decrypt_block(
                (&cipher_text[i..i + T::BLOCK_SIZE])
                    .try_into()
                    .expect("a slice of `BLOCK_SIZE` is guaranteed"),
                &mut block,
            );

            plain_text[i..i + T::BLOCK_SIZE]
                .iter_mut()
                .zip(block.iter().zip(context.iter()))
                .for_each(|(plain, (&b, &c))| *plain = b ^ c);

            context.clone_from_slice(&cipher_text[i..i + T::BLOCK_SIZE]);
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
        let mut encryptor = Encryptor::<Aes256>::new(&key, None).expect("Key buffer is valid");
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
        let mut decryptor = Decryptor::<Aes256>::new(&key, None).expect("Key buffer is valid");
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
        let mut buffer = [0u8; 160];

        // AES-128
        let key = [
            0x2c, 0x14, 0x41, 0x37, 0x51, 0xc3, 0x1e, 0x27, 0x30, 0x57, 0x0b, 0xa3, 0x36, 0x1c,
            0x78, 0x6b,
        ];
        let iv = [
            0x1d, 0xbb, 0xeb, 0x2f, 0x19, 0xab, 0xb4, 0x48, 0xaf, 0x84, 0x97, 0x96, 0x24, 0x4a,
            0x19, 0xd7,
        ];
        let plain_text = [
            0x40, 0xd9, 0x30, 0xf9, 0xa0, 0x53, 0x34, 0xd9, 0x81, 0x6f, 0xe2, 0x04, 0x99, 0x9c,
            0x3f, 0x82, 0xa0, 0x3f, 0x6a, 0x04, 0x57, 0xa8, 0xc4, 0x75, 0xc9, 0x45, 0x53, 0xd1,
            0xd1, 0x16, 0x69, 0x3a, 0xdc, 0x61, 0x80, 0x49, 0xf0, 0xa7, 0x69, 0xa2, 0xee, 0xd6,
            0xa6, 0xcb, 0x14, 0xc0, 0x14, 0x3e, 0xc5, 0xcc, 0xcd, 0xbc, 0x8d, 0xec, 0x4c, 0xe5,
            0x60, 0xcf, 0xd2, 0x06, 0x22, 0x57, 0x09, 0x32, 0x6d, 0x4d, 0xe7, 0x94, 0x8e, 0x54,
            0xd6, 0x03, 0xd0, 0x1b, 0x12, 0xd7, 0xfe, 0xd7, 0x52, 0xfb, 0x23, 0xf1, 0xaa, 0x44,
            0x94, 0xfb, 0xb0, 0x01, 0x30, 0xe9, 0xde, 0xd4, 0xe7, 0x7e, 0x37, 0xc0, 0x79, 0x04,
            0x2d, 0x82, 0x80, 0x40, 0xc3, 0x25, 0xb1, 0xa5, 0xef, 0xd1, 0x5f, 0xc8, 0x42, 0xe4,
            0x40, 0x14, 0xca, 0x43, 0x74, 0xbf, 0x38, 0xf3, 0xc3, 0xfc, 0x3e, 0xe3, 0x27, 0x73,
            0x3b, 0x0c, 0x8a, 0xee, 0x1a, 0xbc, 0xd0, 0x55, 0x77, 0x2f, 0x18, 0xdc, 0x04, 0x60,
            0x3f, 0x7b, 0x2c, 0x1e, 0xa6, 0x9f, 0xf6, 0x62, 0x36, 0x1f, 0x2b, 0xe0, 0xa1, 0x71,
            0xbb, 0xdc, 0xea, 0x1e, 0x5d, 0x3f,
        ];
        let cipher_text = [
            0x6b, 0xe8, 0xa1, 0x28, 0x00, 0x45, 0x5a, 0x32, 0x05, 0x38, 0x85, 0x3e, 0x0c, 0xba,
            0x31, 0xbd, 0x2d, 0x80, 0xea, 0x0c, 0x85, 0x16, 0x4a, 0x4c, 0x5c, 0x26, 0x1a, 0xe4,
            0x85, 0x41, 0x7d, 0x93, 0xef, 0xfe, 0x2e, 0xbc, 0x0d, 0x0a, 0x0b, 0x51, 0xd6, 0xea,
            0x18, 0x63, 0x3d, 0x21, 0x0c, 0xf6, 0x3c, 0x0c, 0x4d, 0xdb, 0xc2, 0x76, 0x07, 0xf2,
            0xe8, 0x1e, 0xd9, 0x11, 0x31, 0x91, 0xef, 0x86, 0xd5, 0x6f, 0x3b, 0x99, 0xbe, 0x6c,
            0x41, 0x5a, 0x41, 0x50, 0x29, 0x9f, 0xb8, 0x46, 0xce, 0x71, 0x60, 0xb4, 0x0b, 0x63,
            0xba, 0xf1, 0x17, 0x9d, 0x19, 0x27, 0x5a, 0x2e, 0x83, 0x69, 0x83, 0x76, 0xd2, 0x8b,
            0x92, 0x54, 0x8c, 0x68, 0xe0, 0x6e, 0x6d, 0x99, 0x4e, 0x2c, 0x15, 0x01, 0xed, 0x29,
            0x70, 0x14, 0xe7, 0x02, 0xcd, 0xef, 0xee, 0x2f, 0x65, 0x64, 0x47, 0x70, 0x60, 0x09,
            0x61, 0x4d, 0x80, 0x1d, 0xe1, 0xca, 0xaf, 0x73, 0xf8, 0xb7, 0xfa, 0x56, 0xcf, 0x1b,
            0xa9, 0x4b, 0x63, 0x19, 0x33, 0xbb, 0xe5, 0x77, 0x62, 0x43, 0x80, 0x85, 0x0f, 0x11,
            0x74, 0x35, 0xa0, 0x35, 0x5b, 0x2b,
        ];
        let mut encryptor = Encryptor::<Aes128>::new(&key, Some(&iv)).expect("Key buffer is valid");
        let mut decryptor = Decryptor::<Aes128>::new(&key, Some(&iv)).expect("Key buffer is valid");
        buffer.fill(0);
        let result = encryptor.encrypt(&plain_text, &mut buffer);
        assert!(result.is_ok_and(|_| buffer == cipher_text));
        buffer.fill(0);
        let result = decryptor.decrypt(&cipher_text, &mut buffer);
        assert!(result.is_ok_and(|_| buffer == plain_text));

        // AES-192
        let key = [
            0x16, 0x2a, 0xd5, 0x0e, 0xe6, 0x4a, 0x07, 0x02, 0xaa, 0x55, 0x1f, 0x57, 0x1d, 0xed,
            0xc1, 0x6b, 0x2c, 0x1b, 0x6a, 0x1e, 0x4d, 0x4b, 0x5e, 0xee,
        ];
        let iv = [
            0x24, 0x40, 0x80, 0x38, 0x16, 0x1a, 0x2c, 0xca, 0xe0, 0x7b, 0x02, 0x9b, 0xb6, 0x63,
            0x55, 0xc1,
        ];
        let plain_text = [
            0xbe, 0x8a, 0xbf, 0x00, 0x90, 0x13, 0x63, 0x98, 0x7a, 0x82, 0xcc, 0x77, 0xd0, 0xec,
            0x91, 0x69, 0x7b, 0xa3, 0x85, 0x7f, 0x9e, 0x4f, 0x84, 0xbd, 0x79, 0x40, 0x6c, 0x13,
            0x8d, 0x02, 0x69, 0x8f, 0x00, 0x32, 0x76, 0xd0, 0x44, 0x91, 0x20, 0xbe, 0xf4, 0x57,
            0x8d, 0x78, 0xfe, 0xca, 0xbe, 0x8e, 0x07, 0x0e, 0x11, 0x71, 0x0b, 0x3f, 0x0a, 0x27,
            0x44, 0xbd, 0x52, 0x43, 0x4e, 0xc7, 0x00, 0x15, 0x88, 0x4c, 0x18, 0x1e, 0xbd, 0xfd,
            0x51, 0xc6, 0x04, 0xa7, 0x1c, 0x52, 0xe4, 0xc0, 0xe1, 0x10, 0xbc, 0x40, 0x8c, 0xd4,
            0x62, 0xb2, 0x48, 0xa8, 0x0b, 0x8a, 0x8a, 0xc0, 0x6b, 0xb9, 0x52, 0xac, 0x1d, 0x7f,
            0xae, 0xd1, 0x44, 0x80, 0x7f, 0x1a, 0x73, 0x1b, 0x7f, 0xeb, 0xca, 0xf7, 0x83, 0x57,
            0x62, 0xde, 0xfe, 0x92, 0xec, 0xcf, 0xc7, 0xa9, 0x94, 0x4e, 0x1c, 0x70, 0x2c, 0xff,
            0xe6, 0xbc, 0x86, 0x73, 0x3e, 0xd3, 0x21, 0x42, 0x31, 0x21, 0x08, 0x5a, 0xc0, 0x2d,
            0xf8, 0x96, 0x2b, 0xcb, 0xc1, 0x93, 0x70, 0x92, 0xee, 0xbf, 0x0e, 0x90, 0xa8, 0xb2,
            0x0e, 0x3d, 0xd8, 0xc2, 0x44, 0xae,
        ];
        let cipher_text = [
            0xc8, 0x2c, 0xf2, 0xc4, 0x76, 0xde, 0xa8, 0xcb, 0x6a, 0x6e, 0x60, 0x7a, 0x40, 0xd2,
            0xf0, 0x39, 0x1b, 0xe8, 0x2e, 0xa9, 0xec, 0x84, 0xa5, 0x37, 0xa6, 0x82, 0x0f, 0x9a,
            0xfb, 0x99, 0x7b, 0x76, 0x39, 0x7d, 0x00, 0x54, 0x24, 0xfa, 0xa6, 0xa7, 0x4d, 0xc4,
            0xe8, 0xc7, 0xaa, 0x4a, 0x89, 0x00, 0x69, 0x0f, 0x89, 0x4b, 0x6d, 0x1d, 0xca, 0x80,
            0x67, 0x53, 0x93, 0xd2, 0x24, 0x3a, 0xda, 0xc7, 0x62, 0xf1, 0x59, 0x30, 0x1e, 0x35,
            0x7e, 0x98, 0xb7, 0x24, 0x76, 0x23, 0x10, 0xcd, 0x5a, 0x7b, 0xaf, 0xe1, 0xc2, 0xa0,
            0x30, 0xdb, 0xa4, 0x6f, 0xd9, 0x3a, 0x9f, 0xdb, 0x89, 0xcc, 0x13, 0x2c, 0xa9, 0xc1,
            0x7d, 0xc7, 0x20, 0x31, 0xec, 0x68, 0x22, 0xee, 0x5a, 0x9d, 0x99, 0xdb, 0xca, 0x66,
            0xc7, 0x84, 0xc0, 0x1b, 0x08, 0x85, 0xcb, 0xb6, 0x2e, 0x29, 0xd9, 0x78, 0x01, 0x92,
            0x7e, 0xc4, 0x15, 0xa5, 0xd2, 0x15, 0x15, 0x8d, 0x32, 0x5f, 0x9e, 0xe6, 0x89, 0x43,
            0x7a, 0xd1, 0xb7, 0x68, 0x4a, 0xd3, 0x3c, 0x0d, 0x92, 0x73, 0x94, 0x51, 0xac, 0x87,
            0xf3, 0x9f, 0xf8, 0xc3, 0x1b, 0x84,
        ];
        let mut encryptor = Encryptor::<Aes192>::new(&key, Some(&iv)).expect("Key buffer is valid");
        let mut decryptor = Decryptor::<Aes192>::new(&key, Some(&iv)).expect("Key buffer is valid");
        buffer.fill(0);
        let result = encryptor.encrypt(&plain_text, &mut buffer);
        assert!(result.is_ok_and(|_| buffer == cipher_text));
        buffer.fill(0);
        let result = decryptor.decrypt(&cipher_text, &mut buffer);
        assert!(result.is_ok_and(|_| buffer == plain_text));

        // AES-256
        let key = [
            0x48, 0xbe, 0x59, 0x7e, 0x63, 0x2c, 0x16, 0x77, 0x23, 0x24, 0xc8, 0xd3, 0xfa, 0x1d,
            0x9c, 0x5a, 0x9e, 0xcd, 0x01, 0x0f, 0x14, 0xec, 0x5d, 0x11, 0x0d, 0x3b, 0xfe, 0xc3,
            0x76, 0xc5, 0x53, 0x2b,
        ];
        let iv = [
            0xd6, 0xd5, 0x81, 0xb8, 0xcf, 0x04, 0xeb, 0xd3, 0xb6, 0xea, 0xa1, 0xb5, 0x3f, 0x04,
            0x7e, 0xe1,
        ];
        let plain_text = [
            0x0c, 0x63, 0xd4, 0x13, 0xd3, 0x86, 0x45, 0x70, 0xe7, 0x0b, 0xb6, 0x61, 0x8b, 0xf8,
            0xa4, 0xb9, 0x58, 0x55, 0x86, 0x68, 0x8c, 0x32, 0xbb, 0xa0, 0xa5, 0xec, 0xc1, 0x36,
            0x2f, 0xad, 0xa7, 0x4a, 0xda, 0x32, 0xc5, 0x2a, 0xcf, 0xd1, 0xaa, 0x74, 0x44, 0xba,
            0x56, 0x7b, 0x4e, 0x7d, 0xaa, 0xec, 0xf7, 0xcc, 0x1c, 0xb2, 0x91, 0x82, 0xaf, 0x16,
            0x4a, 0xe5, 0x23, 0x2b, 0x00, 0x28, 0x68, 0x69, 0x56, 0x35, 0x59, 0x98, 0x07, 0xa9,
            0xa7, 0xf0, 0x7a, 0x1f, 0x13, 0x7e, 0x97, 0xb1, 0xe1, 0xc9, 0xda, 0xbc, 0x89, 0xb6,
            0xa5, 0xe4, 0xaf, 0xa9, 0xdb, 0x58, 0x55, 0xed, 0xaa, 0x57, 0x50, 0x56, 0xa8, 0xf4,
            0xf8, 0x24, 0x22, 0x16, 0x24, 0x2b, 0xb0, 0xc2, 0x56, 0x31, 0x0d, 0x9d, 0x32, 0x98,
            0x26, 0xac, 0x35, 0x3d, 0x71, 0x5f, 0xa3, 0x9f, 0x80, 0xce, 0xc1, 0x44, 0xd6, 0x42,
            0x45, 0x58, 0xf9, 0xf7, 0x0b, 0x98, 0xc9, 0x20, 0x09, 0x6e, 0x0f, 0x2c, 0x85, 0x5d,
            0x59, 0x48, 0x85, 0xa0, 0x06, 0x25, 0x88, 0x0e, 0x9d, 0xfb, 0x73, 0x41, 0x63, 0xce,
            0xce, 0xf7, 0x2c, 0xf0, 0x30, 0xb8,
        ];
        let cipher_text = [
            0xfc, 0x58, 0x73, 0xe5, 0x0d, 0xe8, 0xfa, 0xf4, 0xc6, 0xb8, 0x4b, 0xa7, 0x07, 0xb0,
            0x85, 0x4e, 0x9d, 0xb9, 0xab, 0x2e, 0x9f, 0x7d, 0x70, 0x7f, 0xbb, 0xa3, 0x38, 0xc6,
            0x84, 0x3a, 0x18, 0xfc, 0x6f, 0xac, 0xeb, 0xaf, 0x66, 0x3d, 0x26, 0x29, 0x6f, 0xb3,
            0x29, 0xb4, 0xd2, 0x6f, 0x18, 0x49, 0x4c, 0x79, 0xe0, 0x9e, 0x77, 0x96, 0x47, 0xf9,
            0xba, 0xfa, 0x87, 0x48, 0x96, 0x30, 0xd7, 0x9f, 0x43, 0x01, 0x61, 0x0c, 0x23, 0x00,
            0xc1, 0x9d, 0xbf, 0x31, 0x48, 0xb7, 0xca, 0xc8, 0xc4, 0xf4, 0x94, 0x41, 0x02, 0x75,
            0x4f, 0x33, 0x2e, 0x92, 0xb6, 0xf7, 0xc5, 0xe7, 0x5b, 0xc6, 0x17, 0x9e, 0xb8, 0x77,
            0xa0, 0x78, 0xd4, 0x71, 0x90, 0x09, 0x02, 0x17, 0x44, 0xc1, 0x4f, 0x13, 0xfd, 0x2a,
            0x55, 0xa2, 0xb9, 0xc4, 0x4d, 0x18, 0x00, 0x06, 0x85, 0xa8, 0x45, 0xa4, 0xf6, 0x32,
            0xc7, 0xc5, 0x6a, 0x77, 0x30, 0x6e, 0xfa, 0x66, 0xa2, 0x4d, 0x05, 0xd0, 0x88, 0xdc,
            0xd7, 0xc1, 0x3f, 0xe2, 0x4f, 0xc4, 0x47, 0x27, 0x59, 0x65, 0xdb, 0x9e, 0x4d, 0x37,
            0xfb, 0xc9, 0x30, 0x44, 0x48, 0xcd,
        ];
        let mut encryptor = Encryptor::<Aes256>::new(&key, Some(&iv)).expect("Key buffer is valid");
        let mut decryptor = Decryptor::<Aes256>::new(&key, Some(&iv)).expect("Key buffer is valid");
        buffer.fill(0);
        let result = encryptor.encrypt(&plain_text, &mut buffer);
        assert!(result.is_ok_and(|_| buffer == cipher_text));
        buffer.fill(0);
        let result = decryptor.decrypt(&cipher_text, &mut buffer);
        assert!(result.is_ok_and(|_| buffer == plain_text));
    }
}
