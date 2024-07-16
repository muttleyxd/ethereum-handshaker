use futures::{sink::SinkExt};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_stream::StreamExt;
use tokio_util::codec::FramedParts;

use crate::{
    keypair::Keypair,
    peers::{initiator::Initiator, recipient::Recipient},
    transport_protocol::rlpx::{
        ecies,
        handshake::{
            codecs::{auth_ack::AuthAckCodec, framed::FramedCodec},
            common::public_key_to_peer_id,
            messages::{AuthAck, Hello, Message, MessageType},
        },
        NodeInfo,
    },
};

mod codecs;
mod common;
mod messages;

#[derive(Debug, Error)]
pub enum HandshakeError {
    // todo: split between authack and framed
    #[error("Auth-Ack not completed")]
    AuthAckNotCompleted,
    #[error("Frame data ingress MAC check failed")]
    FrameDataIngressMacCheckFailed,
    #[error("Header ingress MAC check failed")]
    HeaderIngressMacCheckFailed,
    #[error("Invalid header length for MAC")]
    InvalidHeaderLengthForMac,
    #[error("Invalid message received, expected: `{0}`, actual: `{1}`")]
    InvalidMessageReceived(MessageType, Message),
    #[error("Message too big, length: `{0}`, maximum allowed length: `{1}`")]
    MessageTooBig(usize, usize),
    #[error("Message too small, length: `{0}` bytes, expected at least: `{1}` bytes")]
    MessageTooSmall(usize, usize),
    #[error("Received unknown message")]
    ReceivedUnknownMessage,
    #[error("Stream closed unexpectedly")]
    StreamClosedUnexpectedly,
    #[error("Unsupported message id: `{0}`")]
    UnsupportedMessageId(u8),
    #[error("Unsupported operation")]
    UnsupportedOperation,
    #[error("u24 should be 3 bytes long")]
    U24ShouldBe3BytesLong,
    #[error("usize.to_be_bytes() returned size < 3")]
    UsizeToBeBytesReturnedLessThan3Bytes,

    #[error("AES cipher: invalid key length")]
    AesCipherInvalidKeyLength(#[from] aes::cipher::InvalidLength),
    #[error("alloy-rlp error: `{0}`")]
    AlloyRlp(#[from] alloy_rlp::Error),
    #[error("ECIES error: `{0}`")]
    Ecies(#[from] ecies::EciesError),
    #[error("IO error: `{0}`")]
    Io(#[from] std::io::Error),
    #[error("Secp256k1 error: `{0}`")]
    Secp256k1(#[from] secp256k1::Error),
}

pub async fn handshake<'a>(
    stream: &mut TcpStream,
    initiator: &'a Initiator,
    recipient: &Recipient,
) -> Result<NodeInfo, HandshakeError> {
    let initiator_ephemeral_key = Keypair::generate_keypair();

    let auth_ack_codec =
        AuthAckCodec::new(initiator, initiator_ephemeral_key.to_owned(), recipient);
    let mut auth_ack_stream = tokio_util::codec::Framed::new(stream, auth_ack_codec);

    auth_ack_stream.send(Message::Auth).await?;

    let received = auth_ack_stream
        .next()
        .await
        .ok_or(HandshakeError::StreamClosedUnexpectedly)??;
    let auth_ack = get_auth_ack_from_message(received)?;

    let FramedParts { io, codec, .. } = auth_ack_stream.into_parts();

    let framed_codec = FramedCodec::new(
        initiator,
        initiator_ephemeral_key,
        recipient,
        auth_ack,
        codec,
    )?;
    let mut framed_stream = tokio_util::codec::Framed::new(io, framed_codec);

    let message = Hello::new(public_key_to_peer_id(&initiator.keypair.public_key));
    framed_stream.send(Message::Hello(message)).await?;

    let received_message = framed_stream
        .next()
        .await
        .ok_or(HandshakeError::StreamClosedUnexpectedly)??;

    Err(HandshakeError::InvalidHeaderLengthForMac)
    // if let Some(recipient_hello) = received_message {
    //     Ok(recipient_hello)
    // } else {
    //     Err(HandshakeError::ReceivedUnknownMessage)
    // }
}

fn get_auth_ack_from_message(received_message: Message) -> Result<AuthAck, HandshakeError> {
    match received_message {
        Message::AuthAck(value) => Ok(value),
        _ => Err(HandshakeError::InvalidMessageReceived(
            MessageType::AuthAck,
            received_message,
        )),
    }
}
