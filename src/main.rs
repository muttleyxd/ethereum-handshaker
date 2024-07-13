// todo: zeroize all secret and public key fields when dropping them

#![allow(dead_code)]
#![allow(unused_imports)]

use std::{
    net::{AddrParseError, Ipv4Addr, SocketAddr},
    str::FromStr,
};

use hex::FromHexError;
use thiserror::Error;

use crate::{
    error::EthereumHandshakerError, keypair::Keypair, protocol::eth::EthProtocol,
    transport_protocol::rlpx::Rlpx,
};

// todo: remove this

pub mod dto;
pub mod error;
pub mod keypair;
mod peers;
pub mod protocol;
pub mod transport_protocol;

// todo: find proper type for this
pub type B512 = [u8; 64];

pub struct NodeInfo {
    pub address: SocketAddr,
    pub peer_id: B512,
}

#[derive(Debug, Error)]
pub enum NodeInfoCreateError {
    #[error("Address parse failure: `{0}`")]
    AddressParseFailure(#[from] AddrParseError),
    #[error("From hex parsing error: `{0}`")]
    FromHexParseFailure(#[from] FromHexError),
    #[error("PeerId incorrect length")]
    PeerIdIncorrectLength,
}

impl NodeInfo {
    fn new(address: &str, peer_id: &str) -> Result<Self, NodeInfoCreateError> {
        let address = SocketAddr::from_str(address)?;
        let peer_id = hex::decode(peer_id)?;

        Ok(Self {
            address,
            peer_id: peer_id
                .try_into()
                .map_err(|_| NodeInfoCreateError::PeerIdIncorrectLength)?,
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), EthereumHandshakerError> {
    let info = NodeInfo::new("127.0.0.1:30303", "af22c29c316ad069cf48a09a4ad5cf04a251b411e45098888d114c6dd7f489a13786620d5953738762afa13711d4ffb3b19aa5de772d8af72f851f7e9c5b164a")?;

    let stream = tokio::net::TcpStream::connect(&info.address).await?;

    let keypair = Keypair::generate_keypair();
    let transport_protocol = Rlpx::new(keypair.to_owned(), stream);
    transport_protocol.send("test".as_bytes())?;

    Ok(())
}
