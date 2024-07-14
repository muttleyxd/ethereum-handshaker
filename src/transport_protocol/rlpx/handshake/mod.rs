
use futures::sink::SinkExt;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_stream::StreamExt;

use crate::{
    keypair::Keypair,
    peers::{initiator::Initiator, recipient::Recipient},
    transport_protocol::rlpx::{
        ecies,
        handshake::{
            codec::HandshakeCodec,
            messages::{Message, MessageType},
        },
        NodeInfo,
    },
};

mod codec;
mod common;
mod messages;

pub async fn handshake<'a>(
    stream: &mut TcpStream,
    initiator: &'a Initiator,
    recipient: &Recipient,
) -> Result<NodeInfo, HandshakeError> {
    let initiator_ephemeral_key = Keypair::generate_keypair();

    let handshake_codec = HandshakeCodec::new(initiator, initiator_ephemeral_key, recipient);
    let mut framed_stream = tokio_util::codec::Framed::new(stream, handshake_codec);

    framed_stream.send(Message::Auth).await?;

    let result = framed_stream
        .next()
        .await
        .ok_or(HandshakeError::StreamClosedUnexpectedly)??;

    if let Message::AuthAck(_) = result {
        // cos tu zrup
    } else {
        return Err(HandshakeError::InvalidMessageReceived(
            MessageType::AuthAck,
            result,
        ));
    }

    Ok(NodeInfo { version: 0 })
}

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("Invalid message received, expected: `{0}`, actual: `{1}`")]
    InvalidMessageReceived(MessageType, Message),
    #[error("Message too short")]
    MessageTooShort,
    #[error("Stream closed unexpectedly")]
    StreamClosedUnexpectedly,
    #[error("Unsupported operation")]
    UnsupportedOperation,

    #[error("alloy-rlp error: `{0}`")]
    AlloyRlp(#[from] alloy_rlp::Error),
    #[error("ECIES error: `{0}`")]
    Ecies(#[from] ecies::EciesError),
    #[error("IO error: `{0}`")]
    Io(#[from] std::io::Error),
}
