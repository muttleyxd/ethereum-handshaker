use secp256k1::rand::random;

use crate::{keypair::Keypair, types::B256Z};

#[derive(Clone)]
pub struct Initiator {
    pub keypair: Keypair,
    pub nonce: B256Z,
}

impl Initiator {
    pub fn new(keypair: Keypair) -> Self {
        Self {
            keypair,
            nonce: B256Z::new(random::<[u8; 32]>()),
        }
    }
}
