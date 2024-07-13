use thiserror::Error;

use crate::keypair::Keypair;

pub struct EciesEncryption {
    pub keypair: Keypair,
}

#[derive(Debug, Error)]
pub enum EciesError {
    #[error("Ecies library elliptic error: `{0}`")]
    EciesEllipticError(#[from] libsecp256k1_core::Error),
}

impl EciesEncryption {
    fn decrypt(&self, payload: &[u8]) -> Result<Vec<u8>, EciesError> {
        Ok(ecies::decrypt(
            &self.keypair.secret_key.serialize(),
            payload,
        )?)
    }

    fn encrypt(&self, payload: &[u8], receiver_public_key: &[u8]) -> Result<Vec<u8>, EciesError> {
        Ok(ecies::encrypt(receiver_public_key, payload)?)
    }
}
