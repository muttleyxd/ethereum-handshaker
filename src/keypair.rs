use secp256k1::{rand::rngs::OsRng, PublicKey, SecretKey, SECP256K1};

#[derive(Debug, Clone)]
pub struct Keypair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl Drop for Keypair {
    fn drop(&mut self) {
        self.secret_key.non_secure_erase();
    }
}

impl Keypair {
    pub fn generate_keypair() -> Self {
        let (secret_key, public_key) = SECP256K1.generate_keypair(&mut OsRng);

        Self {
            public_key,
            secret_key,
        }
    }

    pub(super) fn parse_from_secret_key(bytes: &[u8; 32]) -> Result<Self, secp256k1::Error> {
        let secret_key = SecretKey::from_slice(bytes)?;
        let public_key = PublicKey::from_secret_key(SECP256K1, &secret_key);

        Ok(Self {
            public_key,
            secret_key,
        })
    }
}
