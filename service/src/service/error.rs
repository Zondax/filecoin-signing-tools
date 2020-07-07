use filecoin_signer::error::SignerError;
use thiserror::Error;

/// RemoteNode Error
#[derive(Error, Debug)]
pub enum RemoteNode {
    #[error("Could not retrieve nonce")]
    EmptyNonce,
    #[error("Could not retrieve nonce")]
    InvalidNonce,
    #[error("Could not retrieve status")]
    InvalidStatusRequest,
    /// JSONRPC error
    #[error("RPC | {0}")]
    JSONRPC(#[from] jsonrpc_core::types::Error),
}

/// Signer Error
#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("The network information provided in the tx doesn't match the node network.")]
    WrongNetwork,
    /// JSONRPC error
    #[error("JSONRPC | {0}")]
    JSONRPC(#[from] jsonrpc_core::types::Error),
    /// Secp256k1 error
    #[error("Secp256k1 | {0}")]
    Secp256k1(#[from] secp256k1::Error),
    /// Filecoin signer error
    #[error("Signer | {0}")]
    Signer(#[from] SignerError),
    /// Service Request error
    #[error("Service | {0}")]
    Request(#[from] reqwest::Error),
    /// Remote Node Request error
    #[error("Remote node | {0}")]
    RemoteNode(#[from] RemoteNode),
    /// Hex Error
    #[error("Hex decoding error | {0}")]
    HexDecode(#[from] hex::FromHexError),
    /// Serde Json Error
    #[error("Serde JSON | {0}")]
    SerdeError(#[from] serde_json::error::Error),
    /// Generic string error
    #[cfg(feature = "cache-nonce")]
    #[error("Error | {0}")]
    ErrorStr(String),
}
