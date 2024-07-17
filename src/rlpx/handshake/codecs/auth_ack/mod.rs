use alloy_primitives::bytes::BytesMut;
use alloy_rlp::Decodable;
use secp256k1::rand::random;
use tokio_util::codec::{Decoder, Encoder};

use crate::{
    keypair::Keypair,
    peers::{initiator::Initiator, recipient::Recipient},
    rlpx::{
        ecies,
        handshake::{
            codecs::auth_ack::messages::{auth::AuthRlp, auth_ack::AuthAck, Message},
            Error,
        },
    },
};

pub mod messages;

pub struct AuthAckCodec<'a> {
    initiator: &'a Initiator,
    initiator_ephemeral_key: Keypair,
    recipient: &'a Recipient,
    state: State,
    incoming_message: Option<Vec<u8>>,
    outgoing_message: Option<Vec<u8>>,
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
            incoming_message: None,
            outgoing_message: None,
        }
    }

    pub fn into_messages_for_hashing(self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        match (self.incoming_message, self.outgoing_message) {
            (Some(incoming), Some(outgoing)) => Ok((incoming, outgoing)),
            _ => Err(Error::AuthAckNotCompleted),
        }
    }
}

enum State {
    None,
    AuthSent,
    Complete,
}

impl Encoder<Message> for AuthAckCodec<'_> {
    type Error = Error;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            Message::Auth => {
                let mut message = AuthRlp::create_rlp_bytes(
                    self.initiator,
                    &self.initiator_ephemeral_key,
                    self.recipient,
                )?;
                message.extend_from_slice(random::<[u8; 32]>().as_slice());

                let encrypted = ecies::encrypt(message.as_ref(), &self.recipient.public_key)?;

                dst.extend_from_slice(&encrypted);
                self.outgoing_message = Some(encrypted);
                self.state = State::AuthSent;
                Ok(())
            }
            _ => Err(Error::UnsupportedOperation),
        }
    }
}

impl Decoder for AuthAckCodec<'_> {
    type Item = Message;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.state {
            State::AuthSent => {
                if src.len() < (i16::BITS / 8) as usize {
                    return Err(Error::StreamClosedUnexpectedly);
                }
                let length = u16::from_be_bytes([src[0], src[1]]) + 2;
                let src = src.split_to(length as usize);

                self.state = State::Complete;
                self.incoming_message = Some(src.to_vec());
                let decrypted = ecies::decrypt(&src, &self.initiator.keypair.secret_key)?;
                let auth_ack = AuthAck::decode(&mut decrypted.as_slice())?;
                Ok(Some(Message::AuthAck(auth_ack)))
            }
            _ => Err(Error::UnsupportedOperation),
        }
    }
}
