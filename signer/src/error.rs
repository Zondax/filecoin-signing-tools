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
    Secp256k1(#[from] libsecp256k1::Error),
    // Key decoding error
    #[error("key decoding error (only hex or base64 is accepted)")]
    KeyDecoding(),
    /// Hex Error
    #[error("Hex decoding error | {0}")]
    HexDecode(#[from] hex::FromHexError),
    /// Generic error message
    #[error("Error: `{0}`")]
    GenericString(String),
    /// Not able to parse integer
    #[error("Cannot parse integer")]
    ParseIntError(#[from] ParseIntError),
    /// BLS error
    #[error("BLS error | {0}")]
    BLS(#[from] bls_signatures::Error),
    /// Invalid BIP44Path
    #[error("Invalid BIP44 path : `{0}`")]
    InvalidBIP44Path(#[from] zx_bip44::errors::BIP44PathError),
    /// BLS error
    #[error("Couldn't convert from slice")]
    TryFromSlice(#[from] TryFromSliceError),
    /// Base64 decode Error
    #[error("Base64 decode error | {0}")]
    DecodeError(#[from] base64::DecodeError),
    // Deserialize error
    #[error("Cannot deserialize parameters | {0}")]
    DeserializeError(#[from] fvm_ipld_encoding::Error),
    // CID error
    #[error("Cannot read CID from string | {0}")]
    CidError(#[from] cid::Error),
}

#[cfg(feature = "with-ffi-support")]
impl From<SignerError> for ffi_support::ExternError {
    fn from(e: SignerError) -> Self {
        let code = match e {
            SignerError::CBOR(_) => 1,
            SignerError::Secp256k1(_) => 2,
            SignerError::KeyDecoding() => 3,
            SignerError::HexDecode(_) => 4,
            SignerError::GenericString(_) => 6,
            SignerError::ParseIntError(_) => 7,
            SignerError::BLS(_) => 8,
            SignerError::InvalidBIP44Path(_) => 8,
            SignerError::TryFromSlice(_) => 10,
            SignerError::DecodeError(_) => 11,
            SignerError::DeserializeError(_) => 12,
            SignerError::CidError(_) => 13,
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

impl From<fvm_shared::address::Error> for SignerError {
    fn from(err: fvm_shared::address::Error) -> SignerError {
        SignerError::GenericString(err.to_string())
    }
}

impl From<fvm_shared::bigint::ParseBigIntError> for SignerError {
    fn from(err: fvm_shared::bigint::ParseBigIntError) -> SignerError {
        SignerError::GenericString(err.to_string())
    }
}

impl From<cid::multihash::Error> for SignerError {
    fn from(err: cid::multihash::Error) -> SignerError {
        SignerError::GenericString(err.to_string())
    }
}
