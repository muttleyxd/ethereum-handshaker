use aes::{
    cipher::{KeyIvInit, StreamCipher},
    Aes128,
};
use alloy_primitives::B256;
use ctr::Ctr64BE;
use secp256k1::{rand::random, PublicKey};

use crate::{
    keypair::Keypair,
    rlpx::ecies::{
        common::{
            calculate_signature, create_shared_secret, derive_keys_from_secret, I16_SIZE,
            MESSAGE_SIZE_WITHOUT_PAYLOAD,
        },
        Error,
    },
    types::B128Z,
};

pub fn encrypt(payload: &[u8], recipient_public_key: &PublicKey) -> Result<Vec<u8>, Error> {
    let temporary_keypair = Keypair::generate_keypair();
    let shared_secret = create_shared_secret(&temporary_keypair.secret_key, recipient_public_key)?;

    let (encryption_key, authentication_key) = derive_keys_from_secret(&shared_secret)?;

    let initialization_vector = B128Z::new(random::<[u8; 16]>());

    let mut encryptor = Ctr64BE::<Aes128>::new(
        encryption_key.0.as_slice().into(),
        initialization_vector.0.as_slice().into(),
    );
    let mut encrypted_payload = payload.to_vec();
    encryptor
        .try_apply_keystream(encrypted_payload.as_mut_slice())
        .map_err(|e| Error::AesStreamCipher(e.to_string()))?;

    let encrypted_message_size = MESSAGE_SIZE_WITHOUT_PAYLOAD + payload.len();

    let payload_signature = calculate_signature(
        &authentication_key,
        &initialization_vector,
        &encrypted_payload,
        encrypted_message_size,
    );

    let message = compose_message(
        encrypted_message_size,
        &temporary_keypair.public_key,
        &initialization_vector,
        encrypted_payload,
        payload_signature,
    );

    if message.len() != encrypted_message_size + I16_SIZE {
        return Err(Error::InvalidEncryptedMesssageLength(
            encrypted_message_size,
            message.len(),
        ));
    }

    Ok(message)
}

fn compose_message(
    encrypted_message_size: usize,
    temporary_public_key: &PublicKey,
    initialization_vector: &B128Z,
    encrypted_payload: Vec<u8>,
    payload_signature: B256,
) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::with_capacity(encrypted_message_size + I16_SIZE);

    let message_size_as_u16 = encrypted_message_size as u16;
    result.extend_from_slice(&message_size_as_u16.to_be_bytes());
    result.extend(temporary_public_key.serialize_uncompressed());
    result.extend(initialization_vector.0.as_slice());
    result.extend(encrypted_payload);
    result.extend(payload_signature);

    result
}
