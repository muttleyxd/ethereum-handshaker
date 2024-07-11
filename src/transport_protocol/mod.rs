use async_trait::async_trait;

pub mod rlpx;

#[async_trait]
pub trait TransportProtocol {}
