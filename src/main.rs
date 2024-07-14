// todo: zeroize all secret and public key fields when dropping them

use std::{
    net::{AddrParseError, Ipv4Addr, SocketAddr},
    process::ExitCode,
    str::FromStr,
};

use thiserror::Error;

use crate::{
    error::EthereumHandshakerError,
    keypair::Keypair,
    peers::{initiator::Initiator, recipient::Recipient},
    transport_protocol::rlpx::{NodeInfo, Rlpx},
};

mod dto;
mod error;
mod keypair;
mod peers;
mod protocol;
mod transport_protocol;

#[tokio::main]
async fn main() -> Result<(), EthereumHandshakerError> {
    let keypair = get_keypair()?;
    let initiator = Initiator::new(keypair);

    let recipient = Recipient::from_enode_str("enode://af22c29c316ad069cf48a09a4ad5cf04a251b411e45098888d114c6dd7f489a13786620d5953738762afa13711d4ffb3b19aa5de772d8af72f851f7e9c5b164a@127.0.0.1:30303")?;

    let mut transport_protocol = Rlpx::new(initiator, recipient).await?;
    match transport_protocol.handshake().await {
        Ok(node_info) => {
            println!(
                "Handshake completed, displaying recipient info:\n----\n{node_info:#?}\n----\n"
            );
            Ok(())
        }
        Err(error) => {
            eprintln!("Error during handshake: {}", error);

            // todo: work out how to not print this
            Err(error.into())
        }
    }
}

fn get_keypair() -> Result<Keypair, std::io::Error> {
    const SECRET_KEY_PATH: &str = "/tmp/handshaker_secret_key";
    if let Ok(secret_bytes) = std::fs::read(SECRET_KEY_PATH) {
        let bytes: Result<[u8; 32], _> = secret_bytes.try_into();
        if let Ok(value) = bytes {
            if let Ok(keypair) = Keypair::parse_from_secret_key(&value) {
                return Ok(keypair);
            }
        }
    }

    let keypair = Keypair::generate_keypair();
    std::fs::write(SECRET_KEY_PATH, keypair.secret_key.as_ref())?;

    Ok(keypair)
}
