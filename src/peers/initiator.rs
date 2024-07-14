use secp256k1::SecretKey;

use crate::keypair::Keypair;

pub struct Initiator {
    pub keypair: Keypair,
}

impl Initiator {
    fn new(keypair: Keypair) -> Self {
        Self { keypair }
    }
}
