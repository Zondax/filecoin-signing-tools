use crate::utils::HexDecodeError::InvalidLength;
use blake2b_simd::Params;
use std::convert::TryInto;
use std::fmt::Write;
use thiserror::Error;

static CID_PREFIX: &[u8] = &[0x01, 0x71, 0xa0, 0xe4, 0x02, 0x20];

/// DecoderError
#[derive(Error, Debug, PartialEq)]
pub enum HexDecodeError {
    /// Invalid length 0 or odd number of characters
    #[error("Invalid length 0 or odd number of characters")]
    InvalidLength,
    /// hex value could not be decoded
    #[error("ParseInt error")]
    ParseInt(#[from] std::num::ParseIntError),
}

/// convert array to hexstring
pub fn to_hex_string(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for &byte in data {
        write!(&mut s, "{:02x}", byte).expect("ERR");
    }
    s
}

/// convert hexstring to array
pub fn from_hex_string(s: &str) -> Result<Vec<u8>, HexDecodeError> {
    if s.is_empty() || s.len() % 2 != 0 {
        return Err(InvalidLength);
    }

    let mut vec = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let v = u8::from_str_radix(&s[i..i + 2], 16)?;
        vec.push(v);
    }
    Ok(vec)
}

/// transform a message into a hashed message ready to be signed and following Filecoin standard
pub fn get_digest(message: &[u8]) -> [u8; 32] {
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

    cid_hashed.as_bytes().try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use crate::utils::HexDecodeError::InvalidLength;
    use crate::utils::{from_hex_string, get_digest, HexDecodeError};
    use hex::{decode, encode};

    #[test]
    fn empty_string() {
        let result = from_hex_string("");
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), HexDecodeError::InvalidLength);
    }

    #[test]
    fn odd_string() {
        let result = from_hex_string("abc");
        assert!(result.is_err());
        assert_eq!(result, Err(InvalidLength));
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

        let message_digest = get_digest(&decode(EXAMPLE_CBOR_DATA.as_bytes()).unwrap());

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
