use thiserror::Error;

/// Signer Error
#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("This is not yet implemented")]
    NotImplemented,
    /// JSONRPC error
    #[error("JSONRPC error")]
    JSONRPC(#[from] jsonrpc_core::types::Error),
    /// Filecoin signer error
    #[error("Filecoin signer error")]
    Signer(#[from] fcsigner::error::SignerError),
    /// Service Request error
    #[error("Service Request error")]
    Request(#[from] reqwest::Error),
}
