use crate::encryption::Encryption;
use crate::keypair::Keypair;

pub struct Ecies {
    pub keypair: Keypair
}

impl Encryption for Ecies {
    fn decrypt(&self, payload: &[u8]) -> Vec<u8> {
        ecies::encrypt(payload)


        todo!()
    }

    fn encrypt(&self, payload: &[u8]) -> Vec<u8> {
        todo!()
    }
}