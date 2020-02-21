use hmac::crypto_mac::InvalidKeyLength;
use std::num::ParseIntError;
use thiserror::Error;

//type Something = <UnsignedMessage as TryFrom>::Error;

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
    // InvalidBigInt error
    #[error("InvalidBigInt error")]
    InvalidBigInt(#[from] num_bigint_chainsafe::ParseBigIntError),
    // Generic error message
    #[error("Error: `{0}`")]
    GenericString(String),

    /// InvalidKeyLength error
    #[error("InvalidKeyLength error")]
    InvalidKeyLength(#[from] InvalidKeyLength),

    #[error("Cannot parse integer")]
    ParseIntError(#[from] ParseIntError),
}
