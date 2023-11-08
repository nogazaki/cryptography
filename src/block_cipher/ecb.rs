use super::*;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ECB<T: KeyInit + BlockCipher> {
    engine: T,
}

impl<T: KeyInit + BlockCipher> ECB<T>
where
    [(); T::BLOCK_SIZE]:,
{
    pub fn init(key: &[u8]) -> Result<Self, ErrorCode> {
        Ok(Self {
            engine: T::new(key)?,
        })
    }

    pub fn encrypt(&self, plain_text: &[u8], cipher_text: &mut [u8]) -> Result<(), ErrorCode> {
        if plain_text.len() % T::BLOCK_SIZE != 0 {
            return Err(ErrorCode::InvalidArgument);
        }

        if cipher_text.len() < plain_text.len() {
            return Err(ErrorCode::InsufficientMemory);
        }

        for i in (0..plain_text.len()).step_by(T::BLOCK_SIZE) {
            self.engine.encrypt_block(
                (&plain_text[i..i + T::BLOCK_SIZE])
                    .try_into()
                    .expect("a slice of `BLOCK_SIZE` is guaranteed"),
                (&mut cipher_text[i..i + T::BLOCK_SIZE])
                    .try_into()
                    .expect("a slice of `BLOCK_SIZE` is guaranteed"),
            )
        }

        Ok(())
    }

    pub fn decrypt(&self, cipher_text: &[u8], plain_text: &mut [u8]) -> Result<(), ErrorCode> {
        if cipher_text.len() % T::BLOCK_SIZE != 0 {
            return Err(ErrorCode::InvalidArgument);
        }

        if plain_text.len() < cipher_text.len() {
            return Err(ErrorCode::InsufficientMemory);
        }

        for i in (0..cipher_text.len()).step_by(T::BLOCK_SIZE) {
            self.engine.decrypt_block(
                (&cipher_text[i..i + T::BLOCK_SIZE])
                    .try_into()
                    .expect("a slice of `BLOCK_SIZE` is guaranteed"),
                (&mut plain_text[i..i + T::BLOCK_SIZE])
                    .try_into()
                    .expect("a slice of `BLOCK_SIZE` is guaranteed"),
            )
        }

        Ok(())
    }
}

/// Test module
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn error_handling() {
        let key = [0u8; 32];
        let plain_text = [0u8; 32];
        let mut cipher_text = plain_text.clone();

        assert!(
            ECB::<aes::Aes192>::init(&key[0..32])
                .is_err_and(|err| err == ErrorCode::InvalidArgument),
            "Key too long, initialization should have failed"
        );

        let ecb_aes = ECB::<aes::Aes128>::init(&key[0..16]).expect("Key buffer is valid");

        let result = ecb_aes.encrypt(&plain_text[0..15], &mut cipher_text);
        assert!(
            result.is_err_and(|err| err == ErrorCode::InvalidArgument),
            "Plain text length is not divisible by block length, encryption should have failed"
        );
        assert_eq!(
            cipher_text, plain_text,
            "Nothing has been written to output buffer"
        );

        let result = ecb_aes.decrypt(&plain_text, &mut cipher_text[0..31]);
        assert!(
            result.is_err_and(|err| err == ErrorCode::InsufficientMemory),
            "Cipher text length is too short, encryption should have failed"
        );
        assert_eq!(
            cipher_text, plain_text,
            "Nothing has been written to output buffer"
        );
    }

    #[test]
    fn correctness() {
        // AES-128
        let key = [
            0xeb, 0xea, 0x9c, 0x6a, 0x82, 0x21, 0x3a, 0x00, 0xac, 0x1d, 0x22, 0xfa, 0xea, 0x22,
            0x11, 0x6f,
        ];
        let plain_text = [
            0x45, 0x1f, 0x45, 0x66, 0x3b, 0x44, 0xfd, 0x00, 0x5f, 0x3c, 0x28, 0x8a, 0xe5, 0x7b,
            0x38, 0x38, 0x83, 0xf0, 0x2d, 0x9a, 0xd3, 0xdc, 0x17, 0x15, 0xf9, 0xe3, 0xd6, 0x94,
            0x85, 0x64, 0x25, 0x7b, 0x9b, 0x06, 0xd7, 0xdd, 0x51, 0x93, 0x5f, 0xee, 0x58, 0x0a,
            0x96, 0xbb, 0xdf, 0xef, 0xb9, 0x18, 0xb4, 0xe6, 0xb1, 0xda, 0xac, 0x80, 0x98, 0x47,
            0x46, 0x55, 0x78, 0xcb, 0x8b, 0x53, 0x56, 0xed, 0x38, 0x55, 0x6f, 0x80, 0x1f, 0xf7,
            0xc1, 0x1e, 0xcb, 0xa9, 0xcd, 0xd2, 0x63, 0x03, 0x9c, 0x15, 0xd0, 0x59, 0x00, 0xfc,
            0x22, 0x8e, 0x1c, 0xaf, 0x30, 0x2d, 0x26, 0x1d, 0x7f, 0xb5, 0x6c, 0xee, 0x66, 0x35,
            0x95, 0xb9, 0x6f, 0x19, 0x2a, 0x78, 0xff, 0x44, 0x55, 0x39, 0x3a, 0x5f, 0xe8, 0x16,
            0x21, 0x70, 0xa0, 0x66, 0xfd, 0xae, 0xac, 0x35, 0x01, 0x94, 0x69, 0xf2, 0x2b, 0x34,
            0x70, 0x68, 0x6b, 0xce, 0xd2, 0xf0, 0x07, 0xa1, 0xa2, 0xe4, 0x3e, 0x01, 0xb4, 0x56,
            0x2c, 0xaa, 0xa5, 0x02, 0xed, 0x54, 0x1b, 0x82, 0x05, 0x87, 0x4e, 0xc1, 0xff, 0xb1,
            0xc8, 0xb2, 0x55, 0x76, 0x69, 0x42,
        ];
        let cipher_text = [
            0x01, 0x04, 0x30, 0x53, 0xf8, 0x32, 0xef, 0x9b, 0x91, 0x1e, 0xd3, 0x87, 0xba, 0x57,
            0x74, 0x51, 0xe3, 0x0d, 0x51, 0xd4, 0xb6, 0xb1, 0x1f, 0x31, 0x9d, 0x4c, 0xd5, 0x39,
            0xd0, 0x67, 0xb7, 0xf4, 0xf9, 0xb4, 0xf4, 0x1f, 0x7f, 0x3d, 0x4e, 0x92, 0x0c, 0x57,
            0xcb, 0xe2, 0xb5, 0xe1, 0x88, 0x5a, 0xa6, 0x62, 0x03, 0xae, 0x49, 0x3e, 0x93, 0xa1,
            0xdf, 0x63, 0x79, 0x3a, 0x95, 0x63, 0xc1, 0x76, 0xbc, 0x67, 0x75, 0xdd, 0x09, 0xcc,
            0x91, 0x61, 0xe2, 0x78, 0xa0, 0x1b, 0xeb, 0x8f, 0xd8, 0xa1, 0x92, 0x00, 0x32, 0x6b,
            0xd9, 0x5a, 0xbc, 0x5f, 0x71, 0x67, 0x68, 0xe3, 0x4f, 0x90, 0xb5, 0x05, 0x23, 0xd3,
            0x0f, 0xda, 0xbb, 0x10, 0x3a, 0x3b, 0xc0, 0x20, 0xaf, 0xbb, 0xb0, 0xcb, 0x3b, 0xd2,
            0xad, 0x51, 0x2a, 0x6f, 0xea, 0x79, 0xf8, 0xd6, 0x4c, 0xef, 0x34, 0x74, 0x58, 0xde,
            0xc4, 0x8b, 0xe8, 0x94, 0x51, 0xcb, 0x0b, 0x80, 0x7d, 0x73, 0x59, 0x3f, 0x27, 0x3d,
            0x9f, 0xc5, 0x21, 0xb7, 0x89, 0xa7, 0x75, 0x24, 0x40, 0x4f, 0x43, 0xe0, 0x0f, 0x20,
            0xb3, 0xb7, 0x7b, 0x93, 0x8b, 0x1a,
        ];
        let mut buffer = plain_text.clone();
        let cipher = ECB::<aes::Aes128>::init(&key).expect("Key buffer is valid");

        let result = cipher.encrypt(&plain_text, &mut buffer);
        assert!(result.is_ok_and(|_| buffer == cipher_text));
        let result = cipher.decrypt(&cipher_text, &mut buffer);
        assert!(result.is_ok_and(|_| buffer == plain_text));

        // AES-192
        let key = [
            0x4f, 0x41, 0xfa, 0x4d, 0x4a, 0x25, 0x10, 0x0b, 0x58, 0x65, 0x51, 0x82, 0x83, 0x73,
            0xbc, 0xca, 0x55, 0x40, 0xc6, 0x8e, 0x9b, 0xf8, 0x45, 0x62,
        ];
        let plain_text = [
            0x7c, 0x72, 0x7b, 0xd3, 0xe7, 0x04, 0x8e, 0x7a, 0x89, 0x95, 0xb7, 0xb1, 0x16, 0x9a,
            0xe4, 0xb5, 0xa5, 0x5e, 0x85, 0x4b, 0xb4, 0xf7, 0xa9, 0x57, 0x6d, 0x78, 0x63, 0xab,
            0x28, 0x68, 0x73, 0x1d, 0x30, 0x73, 0x22, 0xdc, 0xca, 0x60, 0x6e, 0x04, 0x73, 0x43,
            0x67, 0x6f, 0x6a, 0xf4, 0xd9, 0xcf, 0x6e, 0xbf, 0x2b, 0xf9, 0xc9, 0x5d, 0x87, 0x84,
            0x8d, 0x23, 0x3c, 0x93, 0x1e, 0x7a, 0x60, 0xef, 0xf0, 0x8f, 0xb9, 0x59, 0x92, 0x4c,
            0xde, 0x1e, 0xec, 0x86, 0x99, 0xeb, 0xc5, 0x78, 0x90, 0xe3, 0x88, 0x70, 0x24, 0xef,
            0x47, 0xc8, 0x9a, 0x55, 0x00, 0x18, 0x78, 0x8d, 0x1f, 0xaa, 0x32, 0x50, 0x45, 0x2e,
            0x06, 0xf1, 0x48, 0xaf, 0x25, 0xf0, 0x7b, 0xc6, 0x13, 0xcd, 0x2f, 0x0e, 0x50, 0x1a,
            0x79, 0xd7, 0x38, 0xd4, 0x36, 0x1f, 0x28, 0xf3, 0x4d, 0xbe, 0xe2, 0x40, 0x34, 0xe0,
            0x33, 0x67, 0xb6, 0xb8, 0xd3, 0x4d, 0xf3, 0x73, 0x8c, 0xa3, 0xa8, 0x6b, 0x9e, 0xbc,
            0xb0, 0x9e, 0x63, 0x9b, 0xcb, 0x5e, 0x2f, 0x51, 0x9f, 0x4a, 0x7a, 0x86, 0xfc, 0x7c,
            0x41, 0x55, 0x64, 0x04, 0xa9, 0x5d,
        ];
        let cipher_text = [
            0x92, 0x28, 0x12, 0xad, 0x5f, 0xea, 0xcd, 0xf1, 0x1f, 0xe7, 0xfd, 0xae, 0x96, 0x30,
            0x01, 0x49, 0x41, 0x9e, 0x31, 0xcf, 0xf5, 0x40, 0x61, 0xb3, 0xc5, 0xed, 0x27, 0xfd,
            0xb8, 0xb5, 0x0c, 0x9c, 0x09, 0x32, 0xb5, 0x22, 0xa6, 0xc0, 0x4e, 0x48, 0x24, 0x99,
            0xb0, 0x11, 0xef, 0x3c, 0x3e, 0x9d, 0xc5, 0x6a, 0x1a, 0x61, 0xcf, 0xeb, 0x78, 0xb3,
            0x40, 0x32, 0xd2, 0x6d, 0xbd, 0xc3, 0xca, 0xc5, 0x1a, 0x32, 0x79, 0xbc, 0x93, 0x4b,
            0x9b, 0xce, 0x2d, 0x9c, 0x19, 0xbf, 0x85, 0x82, 0x35, 0x61, 0x3b, 0xa7, 0x84, 0xe4,
            0x8e, 0x29, 0x2d, 0x22, 0xc6, 0xb5, 0xa2, 0x8e, 0x1d, 0x1b, 0xb8, 0x60, 0x52, 0x4f,
            0xb7, 0xb5, 0xf9, 0xb3, 0xd9, 0xa5, 0xf4, 0xda, 0x66, 0xe3, 0x40, 0x58, 0x5b, 0xd2,
            0x49, 0x6f, 0xe6, 0xd6, 0x94, 0x2d, 0xb8, 0xd0, 0x5d, 0x71, 0x6f, 0xec, 0x03, 0xb1,
            0x7d, 0x19, 0xab, 0xb5, 0x8b, 0x33, 0x33, 0x2e, 0x24, 0xbe, 0xae, 0xc7, 0x99, 0x5d,
            0x69, 0x52, 0x53, 0x64, 0xfe, 0x13, 0x9a, 0xa1, 0xfd, 0x62, 0x05, 0x46, 0x68, 0xc5,
            0x8f, 0x23, 0xf1, 0xf9, 0x4c, 0xfd,
        ];

        let mut buffer = plain_text.clone();
        let cipher = ECB::<aes::Aes192>::init(&key).expect("Key buffer is valid");

        let result = cipher.encrypt(&plain_text, &mut buffer);
        assert!(result.is_ok());
        assert_eq!(buffer, cipher_text);
        let result = cipher.decrypt(&cipher_text, &mut buffer);
        assert!(result.is_ok());
        assert_eq!(buffer, plain_text);

        // AES-256
        let key = [
            0x44, 0xa2, 0xb5, 0xa7, 0x45, 0x3e, 0x49, 0xf3, 0x82, 0x61, 0x90, 0x4f, 0x21, 0xac,
            0x79, 0x76, 0x41, 0xd1, 0xbc, 0xd8, 0xdd, 0xed, 0xd2, 0x93, 0xf3, 0x19, 0x44, 0x9f,
            0xe6, 0x3b, 0x29, 0x48,
        ];
        let plain_text = [
            0xc9, 0x1b, 0x8a, 0x7b, 0x9c, 0x51, 0x17, 0x84, 0xb6, 0xa3, 0x7f, 0x73, 0xb2, 0x90,
            0x51, 0x6b, 0xb9, 0xef, 0x1e, 0x8d, 0xf6, 0x8d, 0x89, 0xbf, 0x49, 0x16, 0x9e, 0xac,
            0x40, 0x39, 0x65, 0x0c, 0x43, 0x07, 0xb6, 0x26, 0x0e, 0x9c, 0x4e, 0x93, 0x65, 0x02,
            0x23, 0x44, 0x02, 0x52, 0xf5, 0xc7, 0xd3, 0x1c, 0x26, 0xc5, 0x62, 0x09, 0xcb, 0xd0,
            0x95, 0xbf, 0x03, 0x5b, 0x97, 0x05, 0x88, 0x0a, 0x16, 0x28, 0x83, 0x2d, 0xaf, 0x9d,
            0xa5, 0x87, 0xa6, 0xe7, 0x73, 0x53, 0xdb, 0xbc, 0xe1, 0x89, 0xf9, 0x63, 0x23, 0x5d,
            0xf1, 0x60, 0xc0, 0x08, 0xa7, 0x53, 0xe8, 0xcc, 0xea, 0x1e, 0x07, 0x32, 0xaa, 0x46,
            0x9a, 0x97, 0x65, 0x9c, 0x42, 0xe6, 0xe3, 0x1c, 0x16, 0xa7, 0x23, 0x15, 0x3e, 0x39,
            0x95, 0x8a, 0xbe, 0x5b, 0x8a, 0xd8, 0x8f, 0xf2, 0xe8, 0x9a, 0xf4, 0x06, 0x22, 0xca,
            0x0b, 0x0d, 0x67, 0x29, 0xa2, 0x6c, 0x1a, 0xe0, 0x4d, 0x3b, 0x83, 0x67, 0xb5, 0x48,
            0xc4, 0xa6, 0x33, 0x5f, 0x0e, 0x5a, 0x9e, 0xc9, 0x14, 0xbb, 0x61, 0x13, 0xc0, 0x5c,
            0xd0, 0x11, 0x25, 0x52, 0xbc, 0x21,
        ];
        let cipher_text = [
            0x05, 0xd5, 0x1a, 0xf0, 0xe2, 0xb6, 0x1e, 0x2c, 0x06, 0xcb, 0x1e, 0x84, 0x3f, 0xee,
            0x31, 0x72, 0x82, 0x5e, 0x63, 0xb5, 0xd1, 0xce, 0x81, 0x83, 0xb7, 0xe1, 0xdb, 0x62,
            0x68, 0xdb, 0x5a, 0xa7, 0x26, 0x52, 0x1f, 0x46, 0xe9, 0x48, 0x02, 0x8a, 0xa4, 0x43,
            0xaf, 0x9e, 0xbd, 0x8b, 0x7c, 0x6b, 0xaf, 0x95, 0x80, 0x67, 0xab, 0x0d, 0x4a, 0x8a,
            0xc5, 0x30, 0xec, 0xbb, 0x68, 0xcd, 0xfc, 0x3e, 0xb9, 0x30, 0x34, 0xa4, 0x28, 0xeb,
            0x7e, 0x8f, 0x6a, 0x38, 0x13, 0xce, 0xa6, 0x18, 0x90, 0x68, 0xdf, 0xec, 0xfa, 0x26,
            0x8b, 0x7e, 0xcd, 0x59, 0x87, 0xf8, 0xcb, 0x27, 0x32, 0xc6, 0x88, 0x2b, 0xbe, 0xc8,
            0xf7, 0x16, 0xba, 0xc2, 0x54, 0xd7, 0x22, 0x69, 0x23, 0x0a, 0xec, 0x5d, 0xc7, 0xf5,
            0xa6, 0xb8, 0x66, 0xfd, 0x30, 0x52, 0x42, 0x55, 0x2d, 0x40, 0x0f, 0x5b, 0x04, 0x04,
            0xf1, 0x9c, 0xbf, 0xe7, 0x29, 0x1f, 0xab, 0x69, 0x0e, 0xcf, 0xe6, 0x01, 0x8c, 0x43,
            0x09, 0xfc, 0x63, 0x9d, 0x1b, 0x65, 0xfc, 0xb6, 0x5e, 0x64, 0x3e, 0xdb, 0x0a, 0xd1,
            0xf0, 0x9c, 0xfe, 0x9c, 0xee, 0x4a,
        ];

        let mut buffer = plain_text.clone();
        let cipher = ECB::<aes::Aes256>::init(&key).expect("Key buffer is valid");

        let result = cipher.encrypt(&plain_text, &mut buffer);
        assert!(result.is_ok());
        assert_eq!(buffer, cipher_text);
        let result = cipher.decrypt(&cipher_text, &mut buffer);
        assert!(result.is_ok());
        assert_eq!(buffer, plain_text);
    }
}
