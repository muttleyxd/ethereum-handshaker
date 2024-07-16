use std::array::TryFromSliceError;

use alloy_primitives::B256;
use secp256k1::{
    constants::UNCOMPRESSED_PUBLIC_KEY_SIZE,
    ecdh::SharedSecret,
    hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine},
    PublicKey, SecretKey,
};
use sha2::Digest;

use crate::{
    rlpx::ecies::Error,
    types::{B128Z, B256Z},
};

pub const I16_SIZE: usize = (i16::BITS / 8) as usize;
pub const INITIALIZATION_VECTOR_SIZE: usize = 16;
pub const PAYLOAD_SIGNATURE_SIZE: usize = 32;
pub const MESSAGE_SIZE_WITHOUT_PAYLOAD: usize =
    UNCOMPRESSED_PUBLIC_KEY_SIZE + INITIALIZATION_VECTOR_SIZE + PAYLOAD_SIGNATURE_SIZE;

pub fn derive_keys_from_secret(shared_secret: &SharedSecret) -> Result<(B128Z, B256Z), Error> {
    let mut concatenated = B256Z::default();
    concat_kdf::derive_key_into::<sha2::Sha256>(
        &shared_secret.secret_bytes(),
        &[],
        concatenated.0.as_mut_slice(),
    )
    .map_err(|e| Error::ConcatKdf(e.to_string()))?;

    let (encryption_key, authentication_digest) = split_b256_into_b128(&concatenated.0)?;

    // todo: sha2::Sha256 could be removed if I would implement concat-kdf traits for alloy sha256
    let authentication_key =
        B256Z::new(sha2::Sha256::digest(authentication_digest.0.as_slice())[0..32].try_into()?);

    Ok((encryption_key, authentication_key))
}

pub fn calculate_signature(
    authentication_key: &B256Z,
    initialization_vector: &B128Z,
    payload: &[u8],
    encrypted_message_size: usize,
) -> B256 {
    let mut hmac_engine = HmacEngine::new(authentication_key.0.as_ref());
    hmac_engine.input(initialization_vector.0.as_slice());
    hmac_engine.input(payload);
    hmac_engine.input(&(encrypted_message_size as u16).to_be_bytes());
    let hash = Hmac::<sha256::Hash>::from_engine(hmac_engine);
    B256::from_slice(hash.as_byte_array())
}

fn split_b256_into_b128(bytes: &[u8; 32]) -> Result<(B128Z, B128Z), TryFromSliceError> {
    Ok((
        B128Z::new(bytes[0..16].try_into()?),
        B128Z::new(bytes[16..32].try_into()?),
    ))
}

pub fn create_shared_secret(
    secret_key: &SecretKey,
    public_key: &PublicKey,
) -> Result<SharedSecret, secp256k1::Error> {
    SharedSecret::from_slice(&secp256k1::ecdh::shared_secret_point(public_key, secret_key)[0..32])
}
