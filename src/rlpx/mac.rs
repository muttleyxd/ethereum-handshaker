use aes::{
    cipher::{BlockEncrypt, KeyInit},
    Aes256Enc, Block,
};
use alloy_primitives::{Keccak256, B128, B256};

use crate::rlpx::handshake::HandshakeError;

#[derive(Clone, Debug)]
pub struct MessageAuthenticationCode {
    pub secret: B256,
    pub hasher: Keccak256,
}

impl MessageAuthenticationCode {
    pub fn new(secret: B256) -> Self {
        Self {
            secret,
            hasher: Keccak256::new(),
        }
    }

    pub fn current_digest(&self) -> B128 {
        B128::from_slice(&self.hasher.to_owned().finalize()[0..16])
    }

    pub fn update(&mut self, bytes: impl AsRef<[u8]>) {
        self.hasher.update(bytes)
    }

    pub fn update_header(&mut self, header: &[u8]) -> Result<(), HandshakeError> {
        if header.len() != B128::len_bytes() {
            return Err(HandshakeError::InvalidHeaderLengthForMac);
        }
        self.update_data(B128::from_slice(header))
    }

    pub fn update_frame_data(&mut self, data: &[u8]) -> Result<(), HandshakeError> {
        self.hasher.update(data);
        self.update_data(self.current_digest())
    }

    fn update_data(&mut self, digest: B128) -> Result<(), HandshakeError> {
        let aes = Aes256Enc::new_from_slice(&self.secret.0)?;

        let mut encrypted_digest = self.current_digest();
        aes.encrypt_block(Block::from_mut_slice(encrypted_digest.0.as_mut()));

        let xored = encrypted_digest.bit_xor(digest);
        self.hasher.update(xored);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{B128, B256};

    use crate::transport_protocol::rlpx::mac::MessageAuthenticationCode;

    const INITIAL_DIGEST: B128 = B128::new([
        197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192,
    ]);

    #[test]
    fn test_update_header() {
        let mut mac = MessageAuthenticationCode::new(B256::default());

        let initial_digest = mac.current_digest();
        assert_eq!(initial_digest, INITIAL_DIGEST);

        let empty_header: [u8; 16] = [20; 16];
        mac.update_header(&empty_header).unwrap();

        let expected_digest = [
            38u8, 31, 224, 61, 248, 64, 175, 133, 2, 175, 232, 145, 162, 255, 123, 36,
        ];
        let final_digest = mac.current_digest();
        assert_eq!(final_digest, expected_digest);
    }

    #[test]
    fn test_update_data() {
        let mut mac = MessageAuthenticationCode::new(B256::default());

        let initial_digest = mac.current_digest();
        assert_eq!(initial_digest, INITIAL_DIGEST);

        let data: [u8; 12] = [5; 12];
        mac.update_frame_data(&data).unwrap();

        let expected_digest = [
            72u8, 92, 2, 60, 76, 164, 226, 85, 204, 36, 42, 44, 115, 96, 40, 144,
        ];
        let final_digest = mac.current_digest();
        assert_eq!(final_digest, expected_digest);
    }
}
