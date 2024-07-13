#![allow(dead_code)]
#![allow(unused_imports)]

use crate::{
    error::EthereumHandshakerError, keypair::Keypair, protocol::eth::EthProtocol,
    transport_protocol::rlpx::Rlpx,
};

// todo: remove this

pub mod dto;
pub mod encryption;
pub mod error;
pub mod keypair;
pub mod protocol;
pub mod transport_protocol;

#[tokio::main]
async fn main() -> Result<(), EthereumHandshakerError> {
    println!("Hello, world!");
    let stream = tokio::net::TcpStream::connect("127.0.0.1:2137").await?;

    let keypair = Keypair::generate_keypair();
    let transport_protocol = Rlpx::new(keypair.to_owned(), stream);
    transport_protocol.send("test".as_bytes())?;

    Ok(())
}
