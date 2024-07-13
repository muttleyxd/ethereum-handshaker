use crate::{error::EthereumHandshakerError};

// todo: remove this
#[allow(dead_code)]
mod dto;
#[allow(dead_code)]
mod encryption;
#[allow(dead_code)]
mod error;
#[allow(dead_code)]
mod keypair;
#[allow(dead_code)]
mod transport_protocol;

#[tokio::main]
async fn main() -> Result<(), EthereumHandshakerError> {
    println!("Hello, world!");

    Ok(())
}
