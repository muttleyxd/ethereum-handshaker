use alloy_primitives::B256;
use secp256k1::rand::random;

use crate::keypair::Keypair;

#[derive(Clone)]
pub struct Initiator {
    pub keypair: Keypair,
    pub nonce: B256,
}

impl Initiator {
    pub fn new(keypair: Keypair) -> Self {
        Self {
            keypair,
            nonce: random::<[u8; 32]>().into(),
        }
    }
}
