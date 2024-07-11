use secp256k1::{rand::rngs::OsRng, Secp256k1};
use crate::keypair::Keypair;
use crate::transport_protocol::TransportProtocol;

pub struct Rlpx {
    ecies: Arc<dyn Ecies>,
    keypair: Keypair,
    stream: tokio::net::TcpStream
}

impl Rlpx {
    fn new(keypair: Keypair, stream: tokio::net::TcpStream) -> Self {
        Self {
            keypair,
            stream
        }
    }
}

impl TransportProtocol for Rlpx {}
