use crate::api::UnsignedMessageUserAPI;
use forest_encoding::{from_slice, to_vec};
use forest_message::UnsignedMessage;
use hex::{decode, encode};
use thiserror::Error;

pub mod api;

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

pub fn key_generate() {
    // TODO: return keypair (pub/priv + address)
}

pub fn key_derive() {
    // TODO mnemonic + path
    // TODO: return keypair (pub/priv + address)
}

pub fn transaction_create(
    unsigned_message_api: UnsignedMessageUserAPI,
) -> Result<String, SignerError> {
    // tx params as JSON
    let message = UnsignedMessage::from(unsigned_message_api);
    let message_cbor: Vec<u8> = to_vec(&message)?;
    let message_cbor_hex = encode(message_cbor);

    // return unsigned transaction serialized as CBOR / hexstring
    Ok(message_cbor_hex)
}

pub fn transaction_parse(cbor_hexstring: String) -> Result<UnsignedMessageUserAPI, SignerError> {
    // FIXME: Extend to both unsigned and sign txs

    let cbor_buffer = decode(cbor_hexstring)?;
    let message: UnsignedMessage = from_slice(&cbor_buffer)?;
    let message_user_api = UnsignedMessageUserAPI::from(message);

    Ok(message_user_api)
}

pub fn sign_transaction() {
    // TODO: tx params, private key
    // TODO: return signed transaction as CBOR
}

pub fn sign_message() {
    // TODO: message ?
    // TODO: return signature
}

pub fn verify_signature() -> Result<bool, SignerError> {
    // TODO: receive pubkey, signature, message
    // TODO: true is valid
    Ok(false)
}

#[cfg(test)]
mod tests {
    use crate::verify_signature;

    #[test]
    fn verify_random_signature_fails() {
        assert_eq!(verify_signature().expect("error while verifying"), false)
    }
}
