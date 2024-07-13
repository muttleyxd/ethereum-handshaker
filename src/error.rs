use thiserror::Error;

use crate::NodeInfoCreateError;

#[derive(Debug, Error)]
pub enum EthereumHandshakerError {
    #[error("IO error: `{0}`")]
    IoError(#[from] std::io::Error),
    #[error("NodeInfo create error: `{0}`")]
    NodeInfoCreateError(#[from] NodeInfoCreateError),
}
