use crate::utils::HexError::DecodeInvalidLength;
use blake2b_simd::Params;
use core::{array::TryFromSliceError, convert::TryInto, fmt::Write};
use thiserror::Error;

static CID_PREFIX: &[u8] = &[0x01, 0x71, 0xa0, 0xe4, 0x02, 0x20];

/// DecoderError
#[derive(Error, Debug, PartialEq)]
pub enum HexError {
    /// String length is invalid and could not be decoded
    #[error("Invalid length 0 or odd number of characters")]
    DecodeInvalidLength,
    /// hex value could not be decoded
    #[error("{0}")]
    DecodeParseInt(#[from] core::num::ParseIntError),
    /// EncodeError
    #[error("Couldn't encode to HEX: {0}")]
    EncodeError(#[from] core::fmt::Error),
}

/// convert array to hexstring
pub fn to_hex_string(data: &[u8]) -> Result<String, HexError> {
    let mut s = String::with_capacity(data.len() * 2);
    for &byte in data {
        write!(&mut s, "{:02x}", byte)?;
    }
    Ok(s)
}

/// convert hexstring to array
pub fn from_hex_string(s: &str) -> Result<Vec<u8>, HexError> {
    if s.is_empty() || s.len() % 2 != 0 {
        return Err(DecodeInvalidLength);
    }

    let mut vec = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let v = u8::from_str_radix(&s[i..i + 2], 16)?;
        vec.push(v);
    }
    Ok(vec)
}

/// transform a message into a hashed message ready to be signed and following Filecoin standard
pub fn get_digest(message: &[u8]) -> Result<[u8; 32], TryFromSliceError> {
    let message_hashed = Params::new()
        .hash_length(32)
        .to_state()
        .update(message)
        .finalize();

    let cid_hashed = Params::new()
        .hash_length(32)
        .to_state()
        .update(&CID_PREFIX)
        .update(message_hashed.as_bytes())
        .finalize();

    cid_hashed.as_bytes().try_into()
}

#[cfg(test)]
mod tests {
    use crate::utils::{from_hex_string, get_digest, HexError};
    use hex::{decode, encode};

    #[test]
    fn empty_string() {
        let result = from_hex_string("");
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), HexError::DecodeInvalidLength);
    }

    #[test]
    fn odd_string() {
        let result = from_hex_string("abc");
        assert!(result.is_err());
        assert_eq!(result, Err(HexError::DecodeInvalidLength));
    }

    #[test]
    fn invalid_character() {
        let result = from_hex_string("abcx");
        assert!(result.is_err());

        let err = result.err().unwrap();

        // weird open issue
        // https://github.com/rust-lang/rust/issues/22639#issuecomment-379490291
        assert_eq!(err.to_string(), "ParseInt error");
    }

    #[test]
    fn test_digest_message() {
        // TODO
        const EXAMPLE_CBOR_DATA: &str =
            "885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c6285501b882619d46558f3d9e316d11b48dcf211327025a0144000186a0430009c4430061a80040";

        let message_digest = get_digest(&decode(EXAMPLE_CBOR_DATA.as_bytes()).unwrap()).unwrap();

        assert_eq!(
            encode(message_digest),
            "5a51287d2e5401b75014da0f050c8db96fe0bacdad75fce964520ca063b697e1"
        );
    }

    #[test]
    fn empty() {
        // FIXME:
    }
}
