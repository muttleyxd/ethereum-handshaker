use thiserror::Error;

#[derive(Debug, Error)]
pub enum EthereumHandshakerError {
    #[error("IO error: `{0}`")]
    IoError(#[from] std::io::Error),
    // #[error("Secp256k1 error: `{0}`")]
    // Secp256k1(#[from] secp256k1::Error),
}
