use crate::{dto::Status, error::EthereumHandshakerError};

mod dto;
mod error;
mod keypair;
mod transport_protocol;
mod encryption;

#[tokio::main]
async fn main() -> Result<(), EthereumHandshakerError> {
    println!("Hello, world!");

    Ok(())
}

fn create_status_message() {
    // let message = Status{
    //     version: 0,
    //     network_id: NetworkId::Olympic,
    //     total_difficulty: 0,
    //     blockhash: vec![],
    //     genesis: vec![],
    //     fork_identifier: ForkIdentifier {},
    // }
}
