use alloy_primitives::B512;
use secp256k1::PublicKey;

pub fn public_key_to_peer_id(public_key: &PublicKey) -> B512 {
    B512::from_slice(&public_key.serialize_uncompressed()[1..65])
}

pub fn peer_id_to_public_key(peer_id: B512) -> Result<PublicKey, secp256k1::Error> {
    const PUBLIC_KEY_TAG: u8 = 4;

    let mut bytes: [u8; 65] = [0; 65];
    bytes[0] = PUBLIC_KEY_TAG;
    bytes[1..].copy_from_slice(&peer_id.0);
    PublicKey::from_slice(&bytes)
}

#[cfg(test)]
mod tests {
    use secp256k1::{rand::rngs::OsRng, SECP256K1};

    use crate::transport_protocol::rlpx::handshake::common::{
        peer_id_to_public_key, public_key_to_peer_id,
    };

    #[test]
    fn from_and_into() {
        let (_, public_key) = SECP256K1.generate_keypair(&mut OsRng);

        let peer_id = public_key_to_peer_id(&public_key);

        let public_key_from_peer_id = peer_id_to_public_key(peer_id).unwrap();
        assert_eq!(public_key, public_key_from_peer_id);
    }
}
