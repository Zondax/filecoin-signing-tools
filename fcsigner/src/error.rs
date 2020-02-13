use thiserror::Error;

/// Signer Error
#[derive(Error, Debug)]
pub enum SignerError {
    ///  CBOR error
    #[error("CBOR error")]
    CBOR(#[from] serde_cbor::Error),
    /// Secp256k1 error
    #[error("secp256k1 error")]
    Secp256k1(#[from] secp256k1::Error),
    /// Hex error
    #[error("Hex error")]
    Hex(#[from] hex::FromHexError),
}
