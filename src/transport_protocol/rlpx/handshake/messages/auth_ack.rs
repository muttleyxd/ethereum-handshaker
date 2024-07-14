use std::ops::BitXor;

use alloy_primitives::{
    bytes::{BufMut, BytesMut},
    FixedBytes, B256, B512,
};
use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};
use secp256k1::{ecdh::SharedSecret, SecretKey, SECP256K1};

use crate::{
    keypair::Keypair,
    peers::{initiator::Initiator, recipient::Recipient},
    transport_protocol::rlpx::{
        ecies,
        handshake::{common::public_key_to_peer_id, HandshakeError},
    },
};

#[derive(Debug, RlpDecodable)]
pub struct AuthAck {
    recipient_ephemeral_peer_id: B512,
    recipient_nonce: B256,
    ack_version: u8,
}
