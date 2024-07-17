use thiserror::Error;

use crate::{
    keypair::Keypair,
    peers::{initiator::Initiator, recipient, recipient::Recipient},
    rlpx::{NodeInfo, Rlpx},
};

mod keypair;
mod peers;
mod rlpx;
mod types;

#[tokio::main]
async fn main() -> Result<(), EthereumHandshakerError> {
    let keypair = get_keypair()?;
    let initiator = Initiator::new(keypair);

    let tasks: Vec<_> = std::env::args()
        .into_iter()
        .skip(1)
        .map(|enode| {
            let initiator = initiator.clone();
            tokio::spawn(async move {
                let result = try_handshake(initiator, enode.to_owned()).await;
                (result, enode)
            })
        })
        .collect();

    let mut results = vec![];
    for task in tasks {
        results.push(task.await?);
    }

    results
        .into_iter()
        .for_each(|(result, enode)| match result {
            Ok(node_info) => {
                println!(
                    "Handshake completed, displaying recipient info:\n----\n{node_info:#?}\n----\n"
                );
            }
            Err(error) => {
                eprintln!("Error during handshake with '{enode}': {error}");
            }
        });

    Ok(())
}

async fn try_handshake(
    initiator: Initiator,
    enode: String,
) -> Result<NodeInfo, EthereumHandshakerError> {
    let recipient = Recipient::from_enode_str(&enode)?;

    let mut transport_protocol = Rlpx::new(initiator, recipient).await?;
    Ok(transport_protocol.handshake().await?)
}

#[derive(Debug, Error)]
pub enum EthereumHandshakerError {
    #[error("IO error: `{0}`")]
    Io(#[from] std::io::Error),
    #[error("Recipient create error: `{0}`")]
    RecipientCreate(#[from] recipient::Error),
    #[error("RLPx transport protocol error: `{0}`")]
    Rlpx(#[from] rlpx::Error),
    #[error("Tokio task join error: `{0}`")]
    TokioTaskJoin(#[from] tokio::task::JoinError),
}

fn get_keypair() -> Result<Keypair, std::io::Error> {
    const SECRET_KEY_PATH: &str = "handshaker_secret_key";
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
