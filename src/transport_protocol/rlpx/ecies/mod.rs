use thiserror::Error;

mod common;
mod decrypt;
mod encrypt;

#[cfg(test)]
mod test;

pub use decrypt::decrypt;
pub use encrypt::encrypt;

#[derive(Debug, Error)]
pub enum EciesError {
    #[error("Invalid encrypted message length, expected: {0}, actual: {1}")]
    InvalidEncryptedMesssageLength(usize, usize),
    #[error("Payload signature mismatch")]
    PayloadSignatureMismatch,
    #[error("Received message is too small, expected at least: {0}, actual: {1}")]
    ReceivedMessageIsTooSmall(usize, usize),
    #[error("Received message payload length mismatch, found in header: {0}, actual: {1}")]
    ReceivedMessagePayloadLengthMismatch(usize, usize),

    #[error("Concat kdf error: `{0}`")]
    ConcatKdf(String), // concat_kdf doesn't implement std::error::Error
    #[error("Aes stream cipher error: `{0}`")]
    AesStreamCipher(String), // same here
    #[error("Secp256k1 public key deserialize error: `{0}`")]
    Secp256k1PublicKeyDeserialize(#[from] secp256k1::Error),
}
