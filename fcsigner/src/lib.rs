use crate::api::UnsignedMessageUserAPI;
use crate::error::SignerError;
use forest_encoding::{from_slice, to_vec};
use forest_message::UnsignedMessage;
use hex::{decode, encode, FromHex};
use std::convert::TryFrom;

use blake2b_simd::Params;
use secp256k1::{sign, verify, Message, PublicKey, PublicKeyFormat, SecretKey, Signature};

pub mod api;
pub mod error;

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
    let message = UnsignedMessage::try_from(unsigned_message_api)?;
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

pub fn sign_transaction(
    unsigned_message_api: UnsignedMessageUserAPI,
    prvkey: SecretKey,
) -> Result<Signature, SignerError> {
    // tx params as JSON
    let message = UnsignedMessage::try_from(unsigned_message_api)?;
    let message_cbor: Vec<u8> = to_vec(&message)?;

    let message_hashed = Params::new()
        .hash_length(32)
        .to_state()
        .update(&message_cbor)
        .finalize();

    let cid = Vec::from_hex("0171a0e40220")?;
    let cid_hashed = Params::new()
        .hash_length(32)
        .to_state()
        .update(&cid)
        .update(message_hashed.as_bytes())
        .finalize();

    let message_digest = Message::parse_slice(cid_hashed.as_bytes())?;

    let (signed_transaction, recovery_id) = sign(&message_digest, &prvkey);

    Ok(signed_transaction)
}

pub fn sign_message() {
    // TODO: message ?
    // TODO: return signature
}

pub fn verify_signature(
    signature_bytes: &[u8],
    message_bytes: &[u8],
    publickey_bytes: &[u8],
) -> Result<bool, SignerError> {
    let signature = Signature::parse_slice(signature_bytes)?;
    let message = Message::parse_slice(message_bytes)?;
    let publickey =
        PublicKey::parse_slice(publickey_bytes, Option::Some(PublicKeyFormat::Compressed))?;

    Ok(verify(&message, &signature, &publickey))
}
