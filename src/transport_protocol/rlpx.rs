use crate::{keypair::Keypair, transport_protocol::TransportProtocol};

pub struct Rlpx {
    //ecies: Arc<dyn Ecies>,
    keypair: Keypair,
    stream: tokio::net::TcpStream,
}

impl Rlpx {
    fn new(keypair: Keypair, stream: tokio::net::TcpStream) -> Self {
        Self { keypair, stream }
    }
}

impl TransportProtocol for Rlpx {}
