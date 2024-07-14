use std::ops::BitXor;

use alloy_primitives::{bytes::BytesMut, B256, B512};
use alloy_rlp::{Encodable, RlpEncodable};
use secp256k1::{ecdh::SharedSecret, SECP256K1};

use crate::{
    keypair::Keypair,
    peers::{initiator::Initiator, recipient::Recipient},
    transport_protocol::rlpx::handshake::common::public_key_to_peer_id,
};

type SignatureWithRecoveryId = [u8; 65];

#[derive(Debug, RlpEncodable)]
pub struct AuthRlp {
    signature: SignatureWithRecoveryId,
    initiator_peer_id: B512,
    initiator_nonce: B256,
    auth_version: usize,
}

impl AuthRlp {
    pub fn create_rlp_bytes(
        initiator: &Initiator,
        initiator_ephemeral_key: &Keypair,
        recipient: &Recipient,
    ) -> BytesMut {
        let static_shared_secret =
            SharedSecret::new(&recipient.public_key, &initiator.keypair.secret_key);
        let message = initiator
            .nonce
            .bitxor(static_shared_secret.secret_bytes().into());

        let (public_key_recovery_id, signature_bytes) = SECP256K1
            .sign_ecdsa_recoverable(
                &secp256k1::Message::from_digest(message.0),
                &initiator_ephemeral_key.secret_key,
            )
            .serialize_compact();

        // todo: write this better
        let mut signature = [0u8; 65];
        signature[..64].copy_from_slice(&signature_bytes);
        signature[64] = public_key_recovery_id.to_i32() as u8;

        let initiator_peer_id = public_key_to_peer_id(&initiator.keypair.public_key);

        let mut buf = BytesMut::new();
        let auth_rlp = AuthRlp {
            signature,
            initiator_peer_id,
            initiator_nonce: initiator.nonce.to_owned(),
            auth_version: 5, // todo: magic constant
        };
        auth_rlp.encode(&mut buf);

        buf
    }
}
