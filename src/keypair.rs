use secp256k1::{rand::rngs::OsRng, PublicKey, Secp256k1, SecretKey};

#[derive(Clone)]
pub struct Keypair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl Keypair {
    pub fn generate_keypair() -> Self {
        let secp256k1 = Secp256k1::new();
        let (secret_key, public_key) = secp256k1.generate_keypair(&mut OsRng);

        Self {
            public_key,
            secret_key,
        }
    }

    pub(super) fn parse_from_secret_key(bytes: &[u8; 32]) -> Result<Self, secp256k1::Error> {
        let secp256k1 = Secp256k1::new();

        let secret_key = SecretKey::from_slice(bytes)?;
        let public_key = PublicKey::from_secret_key(&secp256k1, &secret_key);

        Ok(Self {
            public_key,
            secret_key,
        })
    }
}
