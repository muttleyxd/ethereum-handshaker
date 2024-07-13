use thiserror::Error;

#[derive(Debug, Error)]
pub enum EthereumHandshakerError {
    // #[error("Secp256k1 error: `{0}`")]
    // Secp256k1(#[from] secp256k1::Error),
}
