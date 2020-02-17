use crate::utils::HexDecodeError::InvalidLength;
use std::fmt::Write;
use thiserror::Error;

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

#[cfg(test)]
mod tests {
    use crate::utils::HexDecodeError::InvalidLength;
    use crate::utils::{from_hex_string, HexDecodeError};

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
    fn empty() {
        // FIXME:
    }
}
