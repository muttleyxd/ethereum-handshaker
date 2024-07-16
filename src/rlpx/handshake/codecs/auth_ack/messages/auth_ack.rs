use alloy_primitives::{B256, B512};
use alloy_rlp::RlpDecodable;

#[derive(Debug, RlpDecodable)]
pub struct AuthAck {
    pub recipient_ephemeral_peer_id: B512,
    pub recipient_nonce: B256,
    _ack_version: u8,
}
