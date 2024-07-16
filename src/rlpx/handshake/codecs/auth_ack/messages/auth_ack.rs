use alloy_primitives::B512;
use alloy_rlp::RlpDecodable;

use crate::types::B256Z;

#[derive(Debug, RlpDecodable)]
pub struct AuthAck {
    pub recipient_ephemeral_peer_id: B512,
    pub recipient_nonce: B256Z,
    _ack_version: u8,
}
