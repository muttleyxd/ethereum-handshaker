use thiserror::Error;

use crate::{peers::recipient::RecipientCreateError, transport_protocol::rlpx::RlpxError};

#[derive(Debug, Error)]
pub enum EthereumHandshakerError {
    #[error("IO error: `{0}`")]
    Io(#[from] std::io::Error),
    #[error("Recipient create error: `{0}`")]
    RecipientCreate(#[from] RecipientCreateError),
    #[error("RLPx transport protocol error: `{0}`")]
    Rlpx(#[from] RlpxError),
}
