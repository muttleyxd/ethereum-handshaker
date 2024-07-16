use aes::{
    cipher::{KeyIvInit, StreamCipher},
    Aes256,
};
use alloy_primitives::{bytes::BytesMut, Keccak256, B128};
use alloy_rlp::{Decodable, Encodable};
use ctr::Ctr64BE;
use tokio_util::codec::{Decoder, Encoder};

use crate::{
    keypair::Keypair,
    peers::initiator::Initiator,
    rlpx::{
        ecies::common::create_shared_secret,
        handshake::{
            codecs::{
                auth_ack::messages::auth_ack::AuthAck,
                framed::messages::{hello::Hello, Message},
            },
            common::peer_id_to_public_key,
            Error,
        },
        mac::MessageAuthenticationCode,
    },
    types::B256Z,
};

pub mod messages;

const FRAME_HEADER_PART_SIZE: usize = 16;

const FRAME_HEADER_SIZE: usize = 32;
const HELLO_MESSAGE_ID: u8 = 0;
const MAC_SIZE: usize = 16;
const U24_SIZE: usize = 3;
const U24_MAX: usize = 0xFFFFFF;

pub struct FramedCodec {
    ingress_aes: Ctr64BE<Aes256>,
    egress_aes: Ctr64BE<Aes256>,

    ingress_mac: MessageAuthenticationCode,
    egress_mac: MessageAuthenticationCode,
}

impl FramedCodec {
    pub fn new(
        initiator: &Initiator,
        initiator_ephemeral_key: &Keypair,
        auth_ack: &AuthAck,
        incoming_message: &[u8],
        outgoing_message: &[u8],
    ) -> Result<Self, Error> {
        let recipient_ephemeral_public_key =
            peer_id_to_public_key(auth_ack.recipient_ephemeral_peer_id)?;
        let ephemeral_shared_secret = create_shared_secret(
            &initiator_ephemeral_key.secret_key,
            &recipient_ephemeral_public_key,
        )?;

        /*
         * todo: if we were ever to become a recipient of this transaction,
         *       then we would have to hash the nonce in reverse order
         */
        let hashed_nonces = keccak256_hash(&[
            auth_ack.recipient_nonce.0.as_slice(),
            initiator.nonce.0.as_slice(),
        ]);

        let shared_secret =
            keccak256_hash(&[ephemeral_shared_secret.0.secret_bytes(), *hashed_nonces.0]);
        let aes_secret =
            keccak256_hash(&[ephemeral_shared_secret.0.secret_bytes(), *shared_secret.0]);

        let aes_initialization_vector = B128::default();
        let ingress_aes =
            Ctr64BE::<Aes256>::new(&(*aes_secret.0).into(), &aes_initialization_vector.0.into());
        let egress_aes = ingress_aes.clone();

        let mac_secret = keccak256_hash(&[ephemeral_shared_secret.0.secret_bytes(), *aes_secret.0]);

        let mut ingress_mac = MessageAuthenticationCode::new(mac_secret.clone());
        ingress_mac.update(mac_secret.bitxor(initiator.nonce.0.as_slice()));
        ingress_mac.update(incoming_message);

        let mut egress_mac = MessageAuthenticationCode::new(mac_secret.clone());
        egress_mac.update(mac_secret.bitxor(auth_ack.recipient_nonce.0.as_slice()));
        egress_mac.update(outgoing_message);

        Ok(Self {
            ingress_aes,
            egress_aes,
            ingress_mac,
            egress_mac,
        })
    }

    fn message_to_frame(&mut self, message: BytesMut) -> Result<BytesMut, Error> {
        let mut result = BytesMut::with_capacity(9999);

        result.extend(self.create_header(message.len())?.as_ref());
        result.extend(self.create_frame_data(message)?);

        Ok(result)
    }

    fn create_header(&mut self, message_length: usize) -> Result<BytesMut, Error> {
        const HEADER_SIGNATURE_BYTES: [u8; 3] = [194, 128, 128];

        let mut header_part: [u8; FRAME_HEADER_PART_SIZE] = [0; FRAME_HEADER_PART_SIZE];
        header_part[0..3].copy_from_slice(&usize_to_u24_be(message_length)?);
        header_part[3..6].copy_from_slice(&HEADER_SIGNATURE_BYTES);

        self.egress_aes.apply_keystream(&mut header_part);
        self.egress_mac.update_header(&header_part)?;

        let mut result = BytesMut::with_capacity(FRAME_HEADER_SIZE);
        result.extend(header_part);
        result.extend(self.egress_mac.current_digest());
        Ok(result)
    }

    fn create_frame_data(&mut self, mut message: BytesMut) -> Result<BytesMut, Error> {
        let target_len = calculate_frame_data_length(message.len());
        message.resize(target_len, 0);

        self.egress_aes.apply_keystream(message.as_mut());
        self.egress_mac.update_frame_data(&message)?;

        message.extend(self.egress_mac.current_digest());

        Ok(message)
    }

    fn read_header<'a>(&mut self, frame: &'a mut BytesMut) -> Result<(&'a mut [u8], usize), Error> {
        if frame.len() < FRAME_HEADER_SIZE + 1 {
            return Err(Error::MessageTooSmall(frame.len(), FRAME_HEADER_SIZE + 1));
        }
        let (header, frame_data) = frame.split_at_mut(FRAME_HEADER_SIZE);

        let (header_part, recipient_egress_mac) = header.split_at_mut(FRAME_HEADER_PART_SIZE);

        self.ingress_mac.update_header(header_part)?;

        if self.ingress_mac.current_digest().0 != *recipient_egress_mac {
            return Err(Error::HeaderIngressMacCheckFailed);
        }

        self.ingress_aes.apply_keystream(header_part);

        let frame_data_length = u24_be_to_usize(&header_part[0..3])?;

        Ok((frame_data, frame_data_length))
    }

    fn read_frame_data<'a>(
        &mut self,
        frame_data: &'a mut [u8],
        frame_data_length: usize,
    ) -> Result<(&'a [u8], &'a [u8]), Error> {
        if frame_data.len() < frame_data_length {
            return Err(Error::MessageTooSmall(frame_data.len(), frame_data_length));
        }

        let mac_split_index = frame_data
            .len()
            .checked_sub(MAC_SIZE)
            .ok_or(Error::MessageTooSmall(frame_data.len(), MAC_SIZE))?;
        let (frame_part, recipient_egress_mac) = frame_data.split_at_mut(mac_split_index);

        self.ingress_mac.update_frame_data(frame_part)?;
        if self.ingress_mac.current_digest().0 != *recipient_egress_mac {
            return Err(Error::FrameDataIngressMacCheckFailed);
        }

        self.ingress_aes.apply_keystream(frame_part);

        let (message_id_as_rlp, message_as_rlp) = frame_part.split_at(1);
        Ok((message_id_as_rlp, message_as_rlp))
    }
}

impl Encoder<Message> for FramedCodec {
    type Error = Error;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            Message::Hello(value) => {
                let mut buffer = BytesMut::new();
                HELLO_MESSAGE_ID.encode(&mut buffer);
                value.encode(&mut buffer);
                *dst = self.message_to_frame(buffer)?;
                Ok(())
            }
        }
    }
}

impl Decoder for FramedCodec {
    type Item = Message;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let (frame_data, frame_data_length) = self.read_header(src)?;
        let (mut message_id_as_rlp, mut message_as_rlp) =
            self.read_frame_data(frame_data, frame_data_length)?;

        match u8::decode(&mut message_id_as_rlp)? {
            HELLO_MESSAGE_ID => Ok(Some(Message::Hello(Hello::decode(&mut message_as_rlp)?))),
            value => Err(Error::ReceivedUnknownMessage(value)),
        }
    }
}

fn keccak256_hash(elements: &[impl AsRef<[u8]>]) -> B256Z {
    let mut hasher = Keccak256::new();
    elements.iter().for_each(|element| hasher.update(element));
    B256Z::new(hasher.finalize().into())
}

fn usize_to_u24_be(value: usize) -> Result<[u8; 3], Error> {
    if value > U24_MAX {
        return Err(Error::MessageTooBig(value, U24_MAX));
    }

    let be_bytes = value.to_be_bytes();
    if be_bytes.len() < U24_SIZE {
        return Err(Error::UsizeToBeBytesReturnedLessThan3Bytes);
    }

    let mut result: [u8; 3] = [0; 3];
    result.copy_from_slice(&be_bytes[be_bytes.len() - U24_SIZE..]);

    Ok(result)
}

fn u24_be_to_usize(value: &[u8]) -> Result<usize, Error> {
    if value.len() != U24_SIZE {
        return Err(Error::U24ShouldBe3BytesLong);
    }

    Ok(usize::from_be_bytes([
        0, 0, 0, 0, 0, value[0], value[1], value[2],
    ]))
}

fn calculate_frame_data_length(len: usize) -> usize {
    if len % 16 == 0 {
        len
    } else {
        (len / 16 + 1) * 16
    }
}

#[cfg(test)]
mod tests {
    use crate::rlpx::handshake::{
        codecs::framed::{calculate_frame_data_length, u24_be_to_usize, usize_to_u24_be, U24_MAX},
        Error,
    };

    #[test]
    fn test_usize_to_u24_be() {
        assert_eq!([0, 0, 1], usize_to_u24_be(1).unwrap());
        assert_eq!([0, 0, 20], usize_to_u24_be(20).unwrap());
        assert_eq!([0, 1, 1], usize_to_u24_be(257).unwrap());
        assert_eq!([255, 255, 255], usize_to_u24_be(U24_MAX).unwrap());

        assert!(matches!(
            usize_to_u24_be(U24_MAX + 1),
            Err(Error::MessageTooBig(_, _))
        ));
    }

    #[test]
    fn test_u24_be_to_usize() {
        assert_eq!(1, u24_be_to_usize(&[0, 0, 1]).unwrap());
        assert_eq!(20, u24_be_to_usize(&[0, 0, 20]).unwrap());
        assert_eq!(257, u24_be_to_usize(&[0, 1, 1]).unwrap());
        assert_eq!(U24_MAX, u24_be_to_usize(&[255, 255, 255]).unwrap());

        assert!(matches!(
            u24_be_to_usize(&[0]),
            Err(Error::U24ShouldBe3BytesLong)
        ));
    }

    #[test]
    fn test_calculate_frame_data_length() {
        assert_eq!(0, calculate_frame_data_length(0));
        assert_eq!(16, calculate_frame_data_length(1));
        assert_eq!(16, calculate_frame_data_length(15));
        assert_eq!(16, calculate_frame_data_length(16));
        assert_eq!(32, calculate_frame_data_length(17));
    }
}
