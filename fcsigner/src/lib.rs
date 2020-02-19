use crate::api::UnsignedMessageUserAPI;
use crate::error::SignerError;
use forest_address::Address;
use forest_encoding::{from_slice, to_vec};
use forest_message::UnsignedMessage;
use hex::{decode, encode};
use std::convert::TryFrom;

use secp256k1::{recover, sign, verify, Message, RecoveryId, SecretKey, Signature};

pub mod api;
pub mod error;
pub mod utils;

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

pub fn transaction_parse(cbor_hexstring: &[u8], testnet: bool) -> Result<UnsignedMessageUserAPI, SignerError> {
    // FIXME: Extend to both unsigned and sign txs

    let cbor_buffer = decode(cbor_hexstring)?;
    let message: UnsignedMessage = from_slice(&cbor_buffer)?;
    let message_user_api = UnsignedMessageUserAPI::from(message);

    Ok(message_user_api)
}

pub fn sign_transaction(
    unsigned_message_api: UnsignedMessageUserAPI,
    privatekey_bytes: &[u8],
) -> Result<([u8; 64], u8), SignerError> {
    // tx params as JSON
    let message = UnsignedMessage::try_from(unsigned_message_api)?;
    let message_cbor: Vec<u8> = to_vec(&message)?;

    let secret_key = SecretKey::parse_slice(&privatekey_bytes)?;

    let cid_hashed = utils::get_digest(&message_cbor);

    let message_digest = Message::parse_slice(&cid_hashed)?;

    let (signed_transaction, recovery_id) = sign(&message_digest, &secret_key);

    Ok((signed_transaction.serialize(), recovery_id.serialize()))
}

pub fn sign_message() {
    // TODO: message ?
    // TODO: return signature
}

// REVIEW: We expect the CBOR transaction as an hex string... Might be confusing
pub fn verify_signature(
    signature_bytes: &[u8],
    cbor_hexstring: &[u8],
) -> Result<bool, SignerError> {
    let signature = Signature::parse_slice(&signature_bytes[..64])?;
    let recovery_id = RecoveryId::parse(signature_bytes[64])?;

    let tx = transaction_parse(&cbor_hexstring)?;

    // Decode the CBOR transaction hex string into CBOR transaction buffer
    let cbor_buffer = decode(cbor_hexstring)?;
    let message_digest = utils::get_digest(&cbor_buffer);

    let message = Message::parse_slice(&message_digest)?;

    let publickey = recover(&message, &signature, &recovery_id)?;

    let from = Address::new_secp256k1(publickey.serialize_compressed().to_vec())
        .map_err(|err| SignerError::GenericString(err.to_string()))?;

    // Compare recovered public key with the public key from the transaction
    if tx.from != from.to_string() {
        return Ok(false);
    }

    Ok(verify(&message, &signature, &publickey))
}

#[cfg(test)]
mod tests {
    use crate::api::UnsignedMessageUserAPI;
    use crate::{sign_transaction, verify_signature};
    use hex::decode;

    // NOTE: not the same transaction used in other tests.
    const EXAMPLE_UNSIGNED_MESSAGE: &str = r#"
        {
            "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
            "from": "t1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka",
            "nonce": 1,
            "value": "100000",
            "gas_price": "2500",
            "gas_limit": "25000",
            "method": 0,
            "params": ""
        }"#;

    const EXAMPLE_CBOR_DATA: &str =
        "885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855010f323f4709e8e4db0c1d4cd374f9f35201d26fb20144000186a0430009c4430061a80040";

    #[test]
    fn empty() {
        // FIXME:
    }

    #[test]
    fn verify_invalid_signature() {
        // Path 44'/461'/0/0/0
        let prvkey =
            decode("f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a").unwrap();
        let message_user_api: UnsignedMessageUserAPI =
            serde_json::from_str(EXAMPLE_UNSIGNED_MESSAGE).expect("FIXME");
        let (signature, recoveryid) = sign_transaction(message_user_api, &prvkey).unwrap();

        let mut signature_with_recovery_id = [&signature[..], &[recoveryid]].concat();

        assert!(
            verify_signature(&signature_with_recovery_id, EXAMPLE_CBOR_DATA.as_bytes()).unwrap()
        );

        // Tampered signature and look if it valid
        signature_with_recovery_id[5] = 0x01;
        signature_with_recovery_id[34] = 0x00;

        assert!(
            !verify_signature(&signature_with_recovery_id, EXAMPLE_CBOR_DATA.as_bytes()).unwrap()
        );
    }
}
