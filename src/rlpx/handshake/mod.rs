use futures::sink::SinkExt;
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_stream::StreamExt;
use tokio_util::codec::FramedParts;

use crate::{
    keypair::Keypair,
    peers::{initiator::Initiator, recipient::Recipient},
    rlpx::{
        ecies,
        handshake::{
            codecs::{
                auth_ack,
                auth_ack::{messages::auth_ack::AuthAck, AuthAckCodec},
                framed,
                framed::{messages::hello::Hello, FramedCodec},
            },
            common::public_key_to_peer_id,
        },
    },
};

mod codecs;
mod common;

pub async fn handshake<'a>(
    stream: &mut TcpStream,
    initiator: &'a Initiator,
    recipient: &Recipient,
) -> Result<Hello, Error> {
    let initiator_ephemeral_key = Keypair::generate_keypair();

    let AuthAckResult {
        auth_ack,
        incoming_message_for_hashing,
        outgoing_message_for_hashing,
        stream,
    } = auth_ack(stream, initiator, &initiator_ephemeral_key, recipient).await?;

    let framed_codec = FramedCodec::new(
        initiator,
        &initiator_ephemeral_key,
        &auth_ack,
        &incoming_message_for_hashing,
        &outgoing_message_for_hashing,
    )?;
    let mut framed_stream = tokio_util::codec::Framed::new(stream, framed_codec);

    let message = Hello::new(public_key_to_peer_id(&initiator.keypair.public_key));
    framed_stream
        .send(framed::messages::Message::Hello(message))
        .await?;

    let received_message = framed_stream
        .next()
        .await
        .ok_or(Error::StreamClosedUnexpectedly)??;

    match received_message {
        framed::messages::Message::Hello(recipient_hello) => Ok(recipient_hello),
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Auth-Ack not completed")]
    AuthAckNotCompleted,
    #[error("Invalid message received, expected: `{0}`, actual: `{1}`")]
    AuthAckInvalidMessageReceived(auth_ack::messages::MessageType, auth_ack::messages::Message),
    #[error("Frame data ingress MAC check failed")]
    FrameDataIngressMacCheckFailed,
    #[error("Header ingress MAC check failed")]
    HeaderIngressMacCheckFailed,
    #[error("Invalid header length for MAC")]
    InvalidHeaderLengthForMac,
    #[error("Message too big, length: `{0}`, maximum allowed length: `{1}`")]
    MessageTooBig(usize, usize),
    #[error("Message too small, length: `{0}` bytes, expected at least: `{1}` bytes")]
    MessageTooSmall(usize, usize),
    #[error("Received unknown message, type: `{0}`")]
    ReceivedUnknownMessage(u8),
    #[error("Stream closed unexpectedly")]
    StreamClosedUnexpectedly,
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
    Ecies(#[from] ecies::Error),
    #[error("IO error: `{0}`")]
    Io(#[from] std::io::Error),
    #[error("Secp256k1 error: `{0}`")]
    Secp256k1(#[from] secp256k1::Error),
}

struct AuthAckResult<'a> {
    auth_ack: AuthAck,
    incoming_message_for_hashing: Vec<u8>,
    outgoing_message_for_hashing: Vec<u8>,
    stream: &'a mut TcpStream,
}

async fn auth_ack<'a>(
    stream: &'a mut TcpStream,
    initiator: &'a Initiator,
    initiator_ephemeral_key: &Keypair,
    recipient: &Recipient,
) -> Result<AuthAckResult<'a>, Error> {
    let auth_ack_codec =
        AuthAckCodec::new(initiator, initiator_ephemeral_key.to_owned(), recipient);
    let mut auth_ack_stream = tokio_util::codec::Framed::new(stream, auth_ack_codec);

    auth_ack_stream
        .send(auth_ack::messages::Message::Auth)
        .await?;

    let received = auth_ack_stream
        .next()
        .await
        .ok_or(Error::StreamClosedUnexpectedly)??;
    let auth_ack = get_auth_ack_from_message(received)?;

    let FramedParts { io, codec, .. } = auth_ack_stream.into_parts();

    let (incoming_message_for_hashing, outgoing_message_for_hashing) =
        codec.into_messages_for_hashing()?;

    Ok(AuthAckResult {
        auth_ack,
        incoming_message_for_hashing,
        outgoing_message_for_hashing,
        stream: io,
    })
}

fn get_auth_ack_from_message(
    received_message: auth_ack::messages::Message,
) -> Result<AuthAck, Error> {
    match received_message {
        auth_ack::messages::Message::AuthAck(value) => Ok(value),
        _ => Err(Error::AuthAckInvalidMessageReceived(
            auth_ack::messages::MessageType::AuthAck,
            received_message,
        )),
    }
}
