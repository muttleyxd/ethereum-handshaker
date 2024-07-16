use alloy_primitives::bytes::BytesMut;
use alloy_rlp::Decodable;
use secp256k1::rand::random;
use tokio_util::codec::{Decoder, Encoder};

use crate::{
    keypair::Keypair,
    peers::{initiator::Initiator, recipient::Recipient},
    transport_protocol::rlpx::{
        ecies,
        handshake::{
            messages,
            messages::{AuthAck, Message},
            HandshakeError,
        },
    },
};

pub struct AuthAckCodec<'a> {
    initiator: &'a Initiator,
    initiator_ephemeral_key: Keypair,
    recipient: &'a Recipient,
    state: State,
}

impl<'a> AuthAckCodec<'a> {
    pub fn new(
        initiator: &'a Initiator,
        initiator_ephemeral_key: Keypair,
        recipient: &'a Recipient,
    ) -> Self {
        Self {
            initiator,
            initiator_ephemeral_key,
            recipient,
            state: State::None,
        }
    }
}

enum State {
    None,
    AuthSent,
    Complete,
}

impl Encoder<Message> for AuthAckCodec<'_> {
    type Error = HandshakeError;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            Message::Auth => {
                let mut message = messages::AuthRlp::create_rlp_bytes(
                    self.initiator,
                    &self.initiator_ephemeral_key,
                    self.recipient,
                );
                message.extend_from_slice(random::<[u8; 32]>().as_slice());

                let encrypted = ecies::encrypt(message.as_ref(), &self.recipient.public_key)?;
                dst.extend_from_slice(&encrypted);
                self.state = State::AuthSent;
                Ok(())
            }
            _ => Err(HandshakeError::UnsupportedOperation),
        }
    }
}

impl Decoder for AuthAckCodec<'_> {
    type Item = Message;
    type Error = HandshakeError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.state {
            State::AuthSent => {
                self.state = State::Complete;

                let decrypted = ecies::decrypt(src, &self.initiator.keypair.secret_key)?;
                let auth_ack = AuthAck::decode(&mut decrypted.as_slice())?;
                Ok(Some(Message::AuthAck(auth_ack)))
            }
            _ => Err(HandshakeError::UnsupportedOperation),
        }
    }
}
