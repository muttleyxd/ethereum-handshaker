use alloy_primitives::{bytes::BytesMut, B512};
use alloy_rlp::{Encodable, RlpEncodable};
use secp256k1::SECP256K1;

use crate::{
    keypair::Keypair,
    peers::{initiator::Initiator, recipient::Recipient},
    rlpx::{ecies::common::create_shared_secret, handshake::common::public_key_to_peer_id},
    types::B256Z,
};

type SignatureWithRecoveryId = [u8; 65];

#[derive(Debug, RlpEncodable)]
pub struct AuthRlp {
    pub signature: SignatureWithRecoveryId,
    pub initiator_peer_id: B512,
    pub initiator_nonce: B256Z,
    pub auth_version: usize,
}

const AUTH_VERSION: usize = 4;

impl AuthRlp {
    pub fn create_rlp_bytes(
        initiator: &Initiator,
        initiator_ephemeral_key: &Keypair,
        recipient: &Recipient,
    ) -> Result<BytesMut, secp256k1::Error> {
        let static_shared_secret =
            create_shared_secret(&initiator.keypair.secret_key, &recipient.public_key)?;
        let message = initiator
            .nonce
            .bitxor(&static_shared_secret.0.secret_bytes());

        let (public_key_recovery_id, signature_bytes) = SECP256K1
            .sign_ecdsa_recoverable(
                &secp256k1::Message::from_digest(*message.0),
                &initiator_ephemeral_key.secret_key,
            )
            .serialize_compact();

        let mut signature = [0u8; 65];
        signature[..64].copy_from_slice(&signature_bytes);
        signature[64] = public_key_recovery_id.to_i32() as u8;

        let initiator_peer_id = public_key_to_peer_id(&initiator.keypair.public_key);

        let mut buf = BytesMut::new();
        let auth_rlp = Self {
            signature,
            initiator_peer_id,
            initiator_nonce: initiator.nonce.clone(),
            auth_version: AUTH_VERSION,
        };
        auth_rlp.encode(&mut buf);

        Ok(buf)
    }
}
