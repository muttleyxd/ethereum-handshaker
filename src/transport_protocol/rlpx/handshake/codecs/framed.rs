use alloy_primitives::{bytes::BytesMut, Keccak256, B256};
use alloy_rlp::Decodable;
use secp256k1::{ecdh::SharedSecret, rand::random, PublicKey};
use tokio_util::codec::{Decoder, Encoder};

use crate::{
    keypair::Keypair,
    peers::{initiator::Initiator, recipient::Recipient},
    transport_protocol::rlpx::{
        ecies,
        ecies::common::create_shared_secret,
        handshake::{
            common::peer_id_to_public_key,
            messages,
            messages::{AuthAck, Message},
            HandshakeError,
        },
    },
};

pub struct FramedCodec<'a> {
    ephemeral_shared_secret: SharedSecret,
    initiator: &'a Initiator,
    initiator_ephemeral_key: Keypair,
    recipient: &'a Recipient,
    recipient_data: RecipientData,
    state: State,
}

struct RecipientData {
    pub nonce: B256,
    pub ephemeral_public_key: PublicKey,
}

impl<'a> FramedCodec<'a> {
    pub fn new(
        initiator: &'a Initiator,
        initiator_ephemeral_key: Keypair,
        recipient: &'a Recipient,
        auth_ack: AuthAck,
    ) -> Result<Self, HandshakeError> {
        let ephemeral_public_key = peer_id_to_public_key(auth_ack.recipient_ephemeral_peer_id)?;
        let ephemeral_shared_secret =
            create_shared_secret(&initiator_ephemeral_key.secret_key, &ephemeral_public_key)?;

        let mut hasher = Keccak256::new();
        hasher.update(initiator.nonce);
        hasher.update(auth_ack.recipient_nonce);

        Ok(Self {
            ephemeral_shared_secret,
            initiator,
            initiator_ephemeral_key,
            recipient,
            recipient_data: RecipientData {
                nonce: auth_ack.recipient_nonce,
                ephemeral_public_key,
            },
            state: State::None,
        })
    }
}

enum State {
    None,
    AuthSent,
    Complete,
}

impl Encoder<Message> for FramedCodec<'_> {
    type Error = HandshakeError;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            Message::Hello(value) => {
                unimplemented!()
            }
            _ => Err(HandshakeError::UnsupportedOperation),
        }
    }
}

impl Decoder for FramedCodec<'_> {
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
