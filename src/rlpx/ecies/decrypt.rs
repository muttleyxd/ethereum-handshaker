use aes::{
    cipher::{KeyIvInit, StreamCipher},
    Aes128,
};
use alloy_primitives::B256;
use ctr::Ctr64BE;
use secp256k1::{constants::UNCOMPRESSED_PUBLIC_KEY_SIZE, PublicKey, SecretKey};

use crate::{
    rlpx::ecies::{
        common::{
            calculate_signature, create_shared_secret, derive_keys_from_secret, I16_SIZE,
            INITIALIZATION_VECTOR_SIZE, MESSAGE_SIZE_WITHOUT_PAYLOAD, PAYLOAD_SIGNATURE_SIZE,
        },
        Error,
    },
    types::B128Z,
};

pub fn decrypt(message: &[u8], secret_key: &SecretKey) -> Result<Vec<u8>, Error> {
    let DecomposedMessage {
        message_length,
        public_key,
        initialization_vector,
        mut encrypted_payload,
        payload_signature,
    } = decompose_message(message)?;

    let shared_secret = create_shared_secret(secret_key, &public_key)?;
    let (encryption_key, authentication_key) = derive_keys_from_secret(&shared_secret)?;

    let signature = calculate_signature(
        &authentication_key,
        &initialization_vector,
        &encrypted_payload,
        message_length,
    );
    if signature != payload_signature {
        return Err(Error::PayloadSignatureMismatch);
    }

    let mut decryptor = Ctr64BE::<Aes128>::new(
        encryption_key.0.as_slice().into(),
        initialization_vector.0.as_slice().into(),
    );
    decryptor
        .try_apply_keystream(encrypted_payload.as_mut_slice())
        .map_err(|e| Error::AesStreamCipher(e.to_string()))?;

    Ok(encrypted_payload)
}

struct DecomposedMessage {
    pub message_length: usize,
    pub public_key: PublicKey,
    pub initialization_vector: B128Z,
    pub encrypted_payload: Vec<u8>,
    pub payload_signature: B256,
}

fn decompose_message(message: &[u8]) -> Result<DecomposedMessage, Error> {
    const MINIMAL_MESSSAGE_LENGTH: usize = MESSAGE_SIZE_WITHOUT_PAYLOAD + 1;
    if message.len() < MINIMAL_MESSSAGE_LENGTH {
        return Err(Error::ReceivedMessageIsTooSmall(
            MINIMAL_MESSSAGE_LENGTH,
            message.len(),
        ));
    }

    let expected_message_length = message.len() - I16_SIZE;

    let (message_length_bytes, message) = message.split_at(I16_SIZE);

    let message_length =
        i16::from_be_bytes([message_length_bytes[0], message_length_bytes[1]]) as usize;
    if message_length != expected_message_length {
        return Err(Error::ReceivedMessagePayloadLengthMismatch(
            message_length,
            expected_message_length,
        ));
    }

    let (public_key_bytes, message) = message.split_at(UNCOMPRESSED_PUBLIC_KEY_SIZE);
    let public_key = PublicKey::from_slice(public_key_bytes)?;

    let (initialization_vector_bytes, message) = message.split_at(INITIALIZATION_VECTOR_SIZE);
    let initialization_vector = B128Z::new(initialization_vector_bytes.try_into()?);

    let (encrypted_payload_bytes, payload_signature_bytes) =
        message.split_at(message.len() - PAYLOAD_SIGNATURE_SIZE);
    let encrypted_payload = encrypted_payload_bytes.to_vec();
    let payload_signature = B256::from_slice(payload_signature_bytes);

    Ok(DecomposedMessage {
        message_length,
        public_key,
        initialization_vector,
        encrypted_payload,
        payload_signature,
    })
}
