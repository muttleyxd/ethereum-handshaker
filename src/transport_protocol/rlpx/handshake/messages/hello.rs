use alloy_primitives::B512;
use alloy_rlp::{RlpDecodable, RlpEncodable};

#[derive(Debug, RlpDecodable, RlpEncodable)]
pub struct Hello {
    pub protocol_version: u8,
    pub client_id: String,
    pub capabilities: Vec<HelloCapability>,
    pub listen_port: u16,
    pub peer_id: B512,
}

#[derive(Debug, RlpDecodable, RlpEncodable)]
pub struct HelloCapability {
    pub name: String,
    pub version: usize,
}

impl Hello {
    pub fn new(peer_id: B512) -> Self {
        const PROTOCOL_VERSION: u8 = 5;
        const CLIENT_ID: &str = "handshaker_dummy_client/1.0";
        const ETH_PROTOCOL_NAME: &str = "eth";
        const ETH_PROTOCOL_VERSION: usize = 68;

        Self {
            protocol_version: PROTOCOL_VERSION,
            client_id: CLIENT_ID.to_string(),
            capabilities: vec![HelloCapability {
                name: ETH_PROTOCOL_NAME.to_string(),
                version: ETH_PROTOCOL_VERSION,
            }],
            listen_port: 0,
            peer_id,
        }
    }
}
