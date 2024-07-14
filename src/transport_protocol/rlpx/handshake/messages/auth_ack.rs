
use alloy_primitives::{
    B256, B512,
};
use alloy_rlp::{Decodable, RlpDecodable};


#[derive(Debug, RlpDecodable)]
pub struct AuthAck {
    recipient_ephemeral_peer_id: B512,
    recipient_nonce: B256,
    ack_version: u8,
}
