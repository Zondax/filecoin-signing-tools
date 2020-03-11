use filecoin_signer::error::SignerError;
use filecoin_signer::utils::HexDecodeError;
use serde_json::error::Error;
use thiserror::Error;

/// RemoteNode Error
#[derive(Error, Debug)]
pub enum RemoteNode {
    #[error("This is not yet implemented")]
    NotImplemented,
    #[error("Could not retrieve nonce")]
    EmptyNonce,
    #[error("Could not retrieve nonce")]
    InvalidNonce,
    /// JSONRPC error
    #[error("JSONRPC error")]
    JSONRPC(#[from] jsonrpc_core::types::Error),
}

/// Signer Error
#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("This is not yet implemented")]
    NotImplemented,
    /// JSONRPC error
    #[error("JSONRPC error")]
    JSONRPC(#[from] jsonrpc_core::types::Error),
    /// Secp256k1 error
    #[error("Secp256k1 error")]
    Secp256k1(#[from] secp256k1::Error),
    /// Filecoin signer error
    #[error("Filecoin signer error")]
    Signer(#[from] SignerError),
    /// Service Request error
    #[error("Service Request error")]
    Request(#[from] reqwest::Error),
    /// Remote Node Request error
    #[error("Remote Node error")]
    RemoteNode(#[from] RemoteNode),
    /// HexDecode Error
    #[error("Error decoding hex strings")]
    HexDecode(#[from] HexDecodeError),
    /// Serde Json Error
    #[error("Error serializing serde_json")]
    Error(#[from] Error),
}
