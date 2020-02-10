use std::{fmt, fmt::Write};

/// DecoderError
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// String length is invalid and could not be decoded
    InvalidLength,
    /// hex value could not be decoded
    ParseInt(std::num::ParseIntError),
}

impl From<std::num::ParseIntError> for DecodeError {
    fn from(e: std::num::ParseIntError) -> Self {
        DecodeError::ParseInt(e)
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DecodeError::InvalidLength => "Invalid length 0 or odd number of characters".fmt(f),
            DecodeError::ParseInt(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for DecodeError {}

/// convert array to hexstring
pub fn to_hex_string(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for &byte in data {
        write!(&mut s, "{:02x}", byte).expect("ERR");
    }
    s
}

/// convert hexstring to array
pub fn from_hex_string(s: &str) -> Result<Vec<u8>, DecodeError> {
    if s.is_empty() || s.len() % 2 != 0 {
        return Err(DecodeError::InvalidLength);
    }

    let mut vec = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let v = u8::from_str_radix(&s[i..i + 2], 16)?;
        vec.push(v);
    }
    Ok(vec)
}

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}
