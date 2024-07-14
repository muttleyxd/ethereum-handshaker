// todo: zeroize all secret and public key fields when dropping them

#![allow(dead_code)]
#![allow(unused_imports)]

use std::{
    net::{AddrParseError, Ipv4Addr, SocketAddr},
    str::FromStr,
};

use thiserror::Error;

use crate::{
    error::EthereumHandshakerError, keypair::Keypair, peers::recipient::Recipient,
    transport_protocol::rlpx::Rlpx,
};

pub mod dto;
pub mod error;
pub mod keypair;
mod peers;
pub mod protocol;
pub mod transport_protocol;

#[tokio::main]
async fn main() -> Result<(), EthereumHandshakerError> {
    let info = Recipient::from_enode_str("enode://af22c29c316ad069cf48a09a4ad5cf04a251b411e45098888d114c6dd7f489a13786620d5953738762afa13711d4ffb3b19aa5de772d8af72f851f7e9c5b164a@127.0.0.1:30303")?;

    let stream = tokio::net::TcpStream::connect(&info.address).await?;

    let keypair = Keypair::generate_keypair();
    let transport_protocol = Rlpx::new(keypair.to_owned(), stream);
    transport_protocol.send("test".as_bytes())?;

    Ok(())
}
