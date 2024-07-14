use secp256k1::SecretKey;

use crate::{
    keypair::Keypair,
    transport_protocol::rlpx::ecies::{decrypt, encrypt, EciesError},
};

#[test]
fn test_decrypt_validate_against_external_payload() {
    let secret_key = SecretKey::from_slice(&[
        64u8, 80, 215, 109, 130, 101, 189, 95, 178, 248, 9, 178, 102, 57, 207, 228, 157, 213, 183,
        174, 156, 71, 243, 104, 250, 199, 185, 159, 238, 169, 128, 156,
    ])
    .unwrap();

    let encrypted_message = [
        0u8, 118, 4, 230, 84, 94, 60, 162, 62, 55, 210, 13, 208, 52, 149, 11, 188, 59, 123, 199,
        75, 129, 234, 179, 254, 92, 146, 190, 150, 168, 148, 236, 122, 246, 219, 223, 143, 187, 25,
        199, 191, 155, 148, 38, 253, 183, 110, 90, 160, 224, 218, 89, 58, 209, 225, 205, 44, 62,
        52, 53, 152, 73, 128, 129, 168, 232, 193, 52, 65, 66, 137, 46, 43, 25, 27, 46, 51, 135,
        197, 25, 41, 13, 116, 10, 43, 124, 122, 253, 220, 119, 42, 242, 108, 245, 134, 241, 129,
        45, 49, 45, 79, 19, 25, 185, 139, 120, 180, 122, 243, 192, 144, 73, 182, 5, 225, 216, 30,
        103, 142, 156,
    ];

    let decrypted = decrypt(&encrypted_message, &secret_key).unwrap();
    let decrypted_string = String::from_utf8(decrypted).unwrap();

    let expected = "hello";
    assert_eq!(decrypted_string, expected);
}

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
    assert!(matches!(result, Err(EciesError::Secp256k1(_))));

    let mut malformed_payload = valid_encrypted;
    malformed_payload[67] = 0;
    let result = decrypt(&malformed_payload, &recipient_keypair.secret_key);
    assert!(matches!(result, Err(EciesError::PayloadSignatureMismatch)));
}
