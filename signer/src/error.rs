use crate::utils::HexError;
use core::{array::TryFromSliceError, num::ParseIntError};
use hmac::crypto_mac::InvalidKeyLength;
use thiserror::Error;

/// Filecoin Signer Error
#[derive(Error, Debug)]
pub enum SignerError {
    ///  CBOR error
    #[error("CBOR error: '{0}'")]
    CBOR(#[from] serde_cbor::Error),
    /// Secp256k1 error
    #[error("secp256k1 error")]
    Secp256k1(#[from] secp256k1::Error),
    /// Cannot parse hexstring
    #[error("Cannot parse hexstring")]
    HexError(#[from] HexError),
    /// InvalidBigInt error
    #[error("InvalidBigInt error")]
    InvalidBigInt(#[from] num_bigint_chainsafe::ParseBigIntError),
    /// Generic error message
    #[error("Error: `{0}`")]
    GenericString(String),
    /// Not able to parse integer
    #[error("Cannot parse integer")]
    ParseIntError(#[from] ParseIntError),
    /// BLS error
    #[error("bls error")]
    BLS(#[from] bls_signatures::Error),
    /// Invalid BIP44Path
    #[error("Invalid BIP44 path : `{0}`")]
    InvalidBIP44Path(#[from] bip44::errors::BIP44PathError),
    /// BLS error
    #[error("Couldn't convert from slice")]
    TryFromSlice(#[from] TryFromSliceError),
}

#[cfg(feature = "with-ffi-support")]
impl From<SignerError> for ffi_support::ExternError {
    fn from(e: SignerError) -> Self {
        let code = match e {
            SignerError::CBOR(_) => 1,
            SignerError::Secp256k1(_) => 2,
            SignerError::HexError(_) => 3,
            SignerError::InvalidBigInt(_) => 4,
            SignerError::GenericString(_) => 5,
            SignerError::ParseIntError(_) => 6,
            SignerError::BLS(_) => 7,
            SignerError::InvalidBIP44Path(_) => 8,
            SignerError::TryFromSlice(_) => 9,
        };
        Self::new_error(ffi_support::ErrorCode::new(code), e.to_string())
    }
}

// We need to use from because InvalidKeyLength does not implement as_dyn_err
impl From<InvalidKeyLength> for SignerError {
    fn from(err: InvalidKeyLength) -> SignerError {
        SignerError::GenericString(err.to_string())
    }
}

impl From<forest_address::Error> for SignerError {
    fn from(err: forest_address::Error) -> SignerError {
        SignerError::GenericString(err.to_string())
    }
}
