use thiserror::Error;

use crate::{
    keypair::Keypair,
    transport_protocol::{rlpx::ecies::EciesError, TransportProtocol},
};

mod ecies;

pub struct Rlpx {
    keypair: Keypair,
    stream: tokio::net::TcpStream,
}

impl Rlpx {
    pub fn new(keypair: Keypair, stream: tokio::net::TcpStream) -> Self {
        Self { keypair, stream }
    }

    pub fn send(&self, message: &[u8]) -> Result<usize, std::io::Error> {
        self.stream.try_write(message)
    }
}

impl TransportProtocol for Rlpx {}

#[derive(Debug, Error)]
pub enum RlpxError {
    #[error("Ecies error: `{0}`")]
    Ecies(EciesError),
}
