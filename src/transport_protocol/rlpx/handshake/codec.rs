use std::str::FromStr;

use alloy_primitives::bytes::BytesMut;
use alloy_rlp::{Buf, Decodable};
use secp256k1::{
    rand,
    rand::{rngs::OsRng, Rng},
};
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

pub struct HandshakeCodec<'a> {
    initiator: &'a Initiator,
    initiator_ephemeral_key: Keypair,
    recipient: &'a Recipient,
    state: State,
}

impl<'a> HandshakeCodec<'a> {
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

impl Encoder<Message> for HandshakeCodec<'_> {
    type Error = HandshakeError;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            Message::Auth => {
                let mut message = messages::AuthRlp::create_rlp_bytes(
                    self.initiator,
                    &self.initiator_ephemeral_key,
                    self.recipient,
                );
                message.resize(message.len() + 222, 0);

                // todo: add padding

                let encrypted = ecies::encrypt(message.as_ref(), &self.recipient.public_key)?;
                dst.extend_from_slice(&encrypted);
                self.state = State::AuthSent;
                Ok(())
            }
            Message::AuthAck(_) => Err(HandshakeError::UnsupportedOperation),
        }
    }
}

impl Decoder for HandshakeCodec<'_> {
    type Item = Message;
    type Error = HandshakeError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.state {
            State::None => Err(HandshakeError::StreamClosedUnexpectedly),
            State::AuthSent => {
                self.state = State::Complete;

                let decrypted = ecies::decrypt(src, &self.initiator.keypair.secret_key)?;
                let auth_ack = AuthAck::decode(&mut decrypted.as_slice())?;
                Ok(Some(Message::AuthAck(auth_ack)))
            }
            State::Complete => Err(HandshakeError::UnsupportedOperation),
        }
    }
}
