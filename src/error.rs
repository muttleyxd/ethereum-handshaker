use thiserror::Error;

use crate::peers::recipient::RecipientCreateError;

#[derive(Debug, Error)]
pub enum EthereumHandshakerError {
    #[error("IO error: `{0}`")]
    Io(#[from] std::io::Error),
    #[error("Recipient create error: `{0}`")]
    RecipientCreate(#[from] RecipientCreateError),
}
