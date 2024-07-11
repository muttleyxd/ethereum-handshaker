use secp256k1::{rand::rngs::OsRng, PublicKey, Secp256k1, SecretKey};

pub struct Keypair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

pub(super) fn generate_keypair() -> Keypair {
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);

    Keypair {
        public_key,
        secret_key,
    }
}

pub(super) fn keypair_from_secret_key(bytes: &[u8; 32]) -> Result<Keypair, secp256k1::Error> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(bytes)?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    Ok(Keypair {
        secret_key,
        public_key,
    })
}
