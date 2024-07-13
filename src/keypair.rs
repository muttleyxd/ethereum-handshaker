use ecies::{PublicKey, SecretKey};

pub struct Keypair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

pub(super) fn generate_keypair() -> Keypair {
    let (secret_key, public_key) = ecies::utils::generate_keypair();

    Keypair {
        public_key,
        secret_key,
    }
}

pub(super) fn keypair_from_secret_key(
    bytes: &[u8; 32],
) -> Result<Keypair, libsecp256k1_core::Error> {
    let secret_key = SecretKey::parse(bytes)?;
    let public_key = PublicKey::from_secret_key(&secret_key);

    Ok(Keypair {
        public_key,
        secret_key,
    })
}
