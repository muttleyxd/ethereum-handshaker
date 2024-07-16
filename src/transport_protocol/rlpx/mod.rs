use alloy_primitives::B512;
use thiserror::Error;

use crate::{
    peers::{initiator::Initiator, recipient::Recipient},
    transport_protocol::rlpx::handshake::HandshakeError,
};

mod ecies;
mod handshake;
mod mac;

pub struct Rlpx {
    handshake_completed: bool,
    initiator: Initiator,
    recipient: Recipient,
    stream: tokio::net::TcpStream,
}

// allowing dead code since we're using Debug to print this information to the user
#[allow(dead_code)]
#[derive(Debug)]
pub struct NodeInfo {
    pub protocol_version: u8,
    pub client_id: String,
    pub capabilities: Vec<NodeCapability>,
    pub peer_id: B512,
}

// allowing dead code since we're using Debug to print this information to the user
#[allow(dead_code)]
#[derive(Debug)]
pub struct NodeCapability {
    pub name: String,
    pub version: usize,
}

impl Rlpx {
    pub async fn new(initiator: Initiator, recipient: Recipient) -> Result<Self, RlpxError> {
        let stream = tokio::net::TcpStream::connect(recipient.address).await?;

        Ok(Self {
            handshake_completed: false,
            initiator,
            recipient,
            stream,
        })
    }

    pub async fn handshake(&mut self) -> Result<NodeInfo, RlpxError> {
        if self.handshake_completed {
            return Err(RlpxError::HandshakeAlreadyCompleted);
        }

        let recipient_hello =
            handshake::handshake(&mut self.stream, &self.initiator, &self.recipient).await?;
        self.handshake_completed = true;

        Ok(NodeInfo {
            protocol_version: recipient_hello.protocol_version,
            client_id: recipient_hello.client_id,
            capabilities: recipient_hello
                .capabilities
                .into_iter()
                .map(|capability| NodeCapability {
                    name: capability.name,
                    version: capability.version,
                })
                .collect(),
            peer_id: recipient_hello.peer_id,
        })
    }
}

#[derive(Debug, Error)]
pub enum RlpxError {
    #[error("Handshake has already been completed")]
    HandshakeAlreadyCompleted,

    #[error("Handshake error: `{0}`")]
    Handshake(#[from] HandshakeError),
    #[error("IO error: `{0}`")]
    Io(#[from] std::io::Error),
}
