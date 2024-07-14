use crate::{
    keypair::Keypair,
    transport_protocol::rlpx::ecies::{decrypt, encrypt, EciesError},
};

#[test]
fn test_encrypt_and_decrypt_success() {
    let recipient_keypair = Keypair::generate_keypair();
    let unencrypted_message = "hello";

    let encrypted = encrypt(
        unencrypted_message.as_bytes(),
        &recipient_keypair.public_key,
    )
    .unwrap();
    let decrypted = decrypt(&encrypted, &recipient_keypair.secret_key).unwrap();

    let decrypted_message = String::from_utf8(decrypted).unwrap();
    assert_eq!(decrypted_message, unencrypted_message);
}

#[test]
fn test_encrypt_and_decrypt_empty_payload() {
    let recipient_keypair = Keypair::generate_keypair();
    let unencrypted_message = "";

    let encrypted = encrypt(
        unencrypted_message.as_bytes(),
        &recipient_keypair.public_key,
    )
        .unwrap();
    let decrypted = decrypt(&encrypted, &recipient_keypair.secret_key).unwrap();

    let decrypted_message = String::from_utf8(decrypted).unwrap();
    assert_eq!(decrypted_message, unencrypted_message);
}

#[test]
fn test_encrypt_and_decrypt_failed_message_malformed() {
    let recipient_keypair = Keypair::generate_keypair();
    let unencrypted_message = "hello";

    let valid_encrypted = encrypt(
        unencrypted_message.as_bytes(),
        &recipient_keypair.public_key,
    )
    .unwrap();

    let mut malformed_public_key = valid_encrypted.to_owned();
    malformed_public_key[32] = 0;
    let result = decrypt(&malformed_public_key, &recipient_keypair.secret_key);
    assert!(matches!(
        result,
        Err(EciesError::Secp256k1PublicKeyDeserialize(_))
    ));

    let mut malformed_payload = valid_encrypted.to_owned();
    malformed_payload[67] = 0;
    let result = decrypt(&malformed_payload, &recipient_keypair.secret_key);
    assert!(matches!(result, Err(EciesError::PayloadSignatureMismatch)));
}
