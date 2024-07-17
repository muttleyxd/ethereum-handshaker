use alloy_primitives::bytes::BytesMut;
use alloy_rlp::Decodable;
use secp256k1::rand::Rng;
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
                message.resize(
                    message.len() + secp256k1::rand::thread_rng().gen_range(100..200),
                    0,
                );

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

#[cfg(test)]
mod tests {
    use alloy_rlp::BytesMut;
    use tokio_util::codec::Encoder;

    use crate::{
        keypair::Keypair,
        peers::{initiator::Initiator, recipient::Recipient},
        rlpx::handshake::codecs::auth_ack::{messages::Message, AuthAckCodec},
    };

    #[ignore]
    #[test]
    fn test_decoded_auth_ack() {
        let initiator_keypair = Keypair::parse_from_secret_key(&[
            64u8, 80, 215, 109, 130, 101, 189, 95, 178, 248, 9, 178, 102, 57, 207, 228, 157, 213,
            183, 174, 156, 71, 243, 104, 250, 199, 185, 159, 238, 169, 128, 156,
        ])
        .unwrap();

        let initiator_ephemeral_keypair = initiator_keypair.clone();

        let initiator = Initiator::new(initiator_keypair);
        let recipient = Recipient::from_enode_str(
            "enode://37f31b1b98e4ee33\
            8dc4716e54bd0ab049e62446aa88ebbbdb9adea11a56817a7837fe8ad03f72d5016f8de223d4a9e144a4865\
            81a7d58810a657d966e9144ed@127.0.0.1:30303",
        )
        .unwrap();
        let mut codec = AuthAckCodec::new(&initiator, initiator_ephemeral_keypair, &recipient);

        let mut buffer = BytesMut::new();
        codec.encode(Message::Auth, &mut buffer).unwrap();

        let expected = vec![
            1, 195, 4, 68, 9, 82, 27, 253, 1, 123, 132, 51, 159, 38, 171, 76, 211, 53, 165, 36,
            102, 227, 15, 250, 25, 208, 132, 141, 97, 169, 178, 61, 131, 246, 76, 46, 25, 169, 66,
            127, 252, 119, 137, 224, 123, 220, 232, 212, 18, 161, 249, 39, 160, 47, 43, 77, 2, 205,
            140, 155, 157, 10, 162, 75, 134, 52, 124, 160, 218, 3, 18, 224, 42, 5, 107, 245, 99,
            167, 18, 217, 43, 107, 215, 134, 97, 87, 211, 147, 145, 14, 50, 154, 128, 185, 0, 56,
            194, 225, 92, 208, 248, 133, 77, 242, 109, 68, 82, 220, 74, 233, 26, 42, 39, 249, 246,
            95, 89, 29, 86, 121, 89, 151, 192, 109, 168, 7, 196, 123, 53, 171, 34, 250, 146, 152,
            191, 119, 40, 71, 20, 183, 77, 145, 219, 12, 13, 67, 28, 200, 178, 27, 208, 122, 12,
            188, 9, 147, 135, 230, 101, 120, 216, 245, 122, 167, 244, 235, 64, 188, 254, 44, 189,
            130, 86, 65, 47, 121, 13, 46, 65, 169, 2, 161, 122, 167, 152, 91, 40, 161, 6, 203, 65,
            103, 57, 236, 68, 141, 216, 201, 106, 173, 142, 202, 17, 46, 92, 9, 160, 167, 200, 114,
            95, 68, 89, 147, 2, 236, 219, 198, 46, 109, 23, 42, 230, 20, 250, 60, 200, 20, 28, 232,
            22, 88, 146, 8, 167, 35, 163, 12, 82, 169, 54, 120, 140, 251, 109, 44, 61, 186, 91,
            215, 58, 24, 96, 72, 222, 123, 0, 139, 79, 80, 61, 109, 124, 61, 158, 201, 250, 169, 8,
            103, 70, 185, 201, 146, 78, 82, 45, 75, 183, 153, 35, 198, 176, 208, 217, 11, 215, 199,
            243, 3, 198, 86, 19, 94, 123, 152, 233, 94, 230, 78, 245, 232, 158, 132, 247, 49, 17,
            237, 125, 132, 186, 49, 152, 100, 60, 173, 51, 254, 194, 226, 60, 141, 109, 210, 75,
            180, 128, 216, 23, 187, 184, 91, 187, 57, 251, 202, 62, 206, 171, 188, 195, 192, 172,
            76, 196, 96, 116, 142, 74, 215, 30, 228, 113, 29, 90, 142, 145, 0, 62, 169, 232, 55,
            57, 186, 73, 14, 40, 54, 165, 46, 123, 205, 154, 183, 49, 171, 12, 199, 211, 5, 73, 46,
            46, 57, 143, 7, 143, 217, 126, 95, 94, 70, 54, 139, 153, 55, 216, 163, 41, 80, 96, 11,
            180, 76, 169, 61, 153, 174, 61, 77, 21, 172, 254, 163, 72, 195, 108, 117, 39, 109, 250,
            229, 107, 62, 213, 197, 57, 42, 186, 24, 89, 198, 51, 78, 111, 161, 194, 101, 242, 228,
            135, 120, 86, 241, 235, 86, 146, 1, 182, 171, 127, 79, 76,
        ];
        assert_eq!(buffer, expected);
    }
}
