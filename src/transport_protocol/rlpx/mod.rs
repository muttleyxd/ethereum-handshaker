use thiserror::Error;
use tokio_util::codec::LinesCodecError;

use crate::{
    peers::{initiator::Initiator, recipient::Recipient},
    transport_protocol::{
        rlpx::{ecies::EciesError, handshake::HandshakeError},
        TransportProtocol,
    },
};

mod ecies;
mod handshake;

pub struct Rlpx {
    handshake_completed: bool,
    initiator: Initiator,
    recipient: Recipient,
    stream: tokio::net::TcpStream,
}

#[derive(Debug)]
pub struct NodeInfo {
    pub version: u8,
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

        let node_info =
            handshake::handshake(&mut self.stream, &self.initiator, &self.recipient).await?;
        self.handshake_completed = true;

        Ok(node_info)
    }

    pub fn send(&self, message: &[u8]) -> Result<usize, std::io::Error> {
        self.stream.try_write(message)
    }
}

impl TransportProtocol for Rlpx {}

#[derive(Debug, Error)]
pub enum RlpxError {
    #[error("Handshake has already been completed")]
    HandshakeAlreadyCompleted,

    #[error("Handshake error: `{0}`")]
    Handshake(#[from] HandshakeError),

    #[error("Lines codec error: `{0}`")]
    LinesCodec(#[from] LinesCodecError),

    #[error("ECIES error: `{0}`")]
    Ecies(EciesError),
    #[error("IO error: `{0}`")]
    Io(#[from] std::io::Error),
}
