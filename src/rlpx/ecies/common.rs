use alloy_primitives::{B128, B256};
use secp256k1::{
    constants::UNCOMPRESSED_PUBLIC_KEY_SIZE,
    ecdh::SharedSecret,
    hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine},
    PublicKey, SecretKey,
};
use sha2::Digest;

use crate::rlpx::ecies::EciesError;

pub const I16_SIZE: usize = (i16::BITS / 8) as usize;
pub const INITIALIZATION_VECTOR_SIZE: usize = 16;
pub const PAYLOAD_SIGNATURE_SIZE: usize = 32;
pub const MESSAGE_SIZE_WITHOUT_PAYLOAD: usize =
    UNCOMPRESSED_PUBLIC_KEY_SIZE + INITIALIZATION_VECTOR_SIZE + PAYLOAD_SIGNATURE_SIZE;

pub fn derive_keys_from_secret(shared_secret: &SharedSecret) -> Result<(B128, B256), EciesError> {
    let mut concatenated = B256::default();
    concat_kdf::derive_key_into::<sha2::Sha256>(
        &shared_secret.secret_bytes(),
        &[],
        concatenated.as_mut_slice(),
    )
    .map_err(|e| EciesError::ConcatKdf(e.to_string()))?;

    let (encryption_key, authentication_digest) = split_b256_into_b128(concatenated);

    // todo: verify if we could replace sha2 with secp256k1
    let authentication_key = B256::from_slice(&sha2::Sha256::digest(authentication_digest));

    Ok((encryption_key, authentication_key))
}

pub fn calculate_signature(
    authentication_key: &B256,
    initialization_vector: &B128,
    payload: &[u8],
    encrypted_message_size: usize,
) -> B256 {
    let mut hmac_engine = HmacEngine::new(authentication_key.as_ref());
    hmac_engine.input(initialization_vector.as_slice());
    hmac_engine.input(payload);
    hmac_engine.input(&(encrypted_message_size as u16).to_be_bytes());
    let hash = Hmac::<sha256::Hash>::from_engine(hmac_engine);
    B256::from_slice(hash.as_byte_array())
}

fn split_b256_into_b128(bytes: B256) -> (B128, B128) {
    (
        B128::from_slice(&bytes[0..16]),
        B128::from_slice(&bytes[16..32]),
    )
}

pub fn create_shared_secret(
    secret_key: &SecretKey,
    public_key: &PublicKey,
) -> Result<SharedSecret, secp256k1::Error> {
    SharedSecret::from_slice(&secp256k1::ecdh::shared_secret_point(public_key, secret_key)[0..32])
}
