use std::{
    net::{AddrParseError, SocketAddr},
    str::FromStr,
};

use secp256k1::PublicKey;
use thiserror::Error;

#[derive(Debug, Eq, PartialEq)]
pub struct Recipient {
    pub address: SocketAddr,
    pub public_key: PublicKey,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to find enode prefix")]
    FailedToFindEnodePrefix,
    #[error("Missing peer id and address delimiter `@`")]
    MissingPeerIdAndAddressDelimiter,

    #[error("Address parse failure: `{0}`")]
    AddressParseFailure(#[from] AddrParseError),
    #[error("From hex parsing error: `{0}`")]
    SecP256k1PublicKeyParseFailure(#[from] secp256k1::Error),
}

impl Recipient {
    pub fn from_enode_str(value: &str) -> Result<Self, Error> {
        const PREFIX: &str = "enode://";
        const PEER_ID_AND_ADDRESS_DELIMITER: char = '@';
        const SECP256K1_TAG_PUBLIC_KEY: &str = "04";

        let peer_id_and_address = value
            .strip_prefix(PREFIX)
            .ok_or(Error::FailedToFindEnodePrefix)?;

        let (peer_id, address_str) = peer_id_and_address
            .split_once(PEER_ID_AND_ADDRESS_DELIMITER)
            .ok_or(Error::MissingPeerIdAndAddressDelimiter)?;

        let address = SocketAddr::from_str(address_str)?;

        let public_key_str = format!("{SECP256K1_TAG_PUBLIC_KEY}{peer_id}");
        let public_key = PublicKey::from_str(&public_key_str)?;

        Ok(Self {
            address,
            public_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recipient_from_enode_str_success() {
        let valid_enode_str = "enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4\
            101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67\
            :30303";

        let expected_public_key = PublicKey::from_str(
            "04d860a01f9722d78051619d1e2351aba\
            3f43f943f6f00718d1b9baa4101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203\
            eeedb1f666",
        )
        .unwrap();

        assert_eq!(
            Recipient::from_enode_str(valid_enode_str).unwrap(),
            Recipient {
                address: "18.138.108.67:30303".parse().unwrap(),
                public_key: expected_public_key,
            }
        );
    }

    #[test]
    fn test_recipient_from_enode_str_failed() {
        let empty = "";
        assert!(matches!(
            Recipient::from_enode_str(empty),
            Err(Error::FailedToFindEnodePrefix)
        ));

        let missing_prefix = "node://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa410\
            1932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:3\
            0303";
        assert!(matches!(
            Recipient::from_enode_str(missing_prefix),
            Err(Error::FailedToFindEnodePrefix)
        ));

        let malformed_peer_id = "enode://d860a01f9722d7801619d151aba3f43f943f6f00718d1b9baa410\
            1932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.108.67:3\
            0303";
        assert!(matches!(
            Recipient::from_enode_str(malformed_peer_id),
            Err(Error::SecP256k1PublicKeyParseFailure(_))
        ));

        let missing_address = "enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa4\
            101932a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666";
        assert!(matches!(
            Recipient::from_enode_str(missing_address),
            Err(Error::MissingPeerIdAndAddressDelimiter)
        ));

        let invalid_ip = "enode://d860a01f9722d78051619d1e2351aba3f43f943f6f00718d1b9baa410193\
            2a1f5011f16bb2b1bb35db20d6fe28fa0bf09636d26a87d31de9ec6203eeedb1f666@18.138.266.67:3030\
            3";
        assert!(matches!(
            Recipient::from_enode_str(invalid_ip),
            Err(Error::AddressParseFailure(_))
        ));
    }
}
