use crate::api::UnsignedMessageUserAPI;
use crate::error::SignerError;
use crate::utils::to_hex_string;
use forest_address::Address;
use forest_encoding::{from_slice, to_vec};
use forest_message::UnsignedMessage;
use hex::{decode, encode};
use std::convert::TryFrom;

use crate::bip44::{Bip44Path, ExtendedSecretKey};
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use blake2b_simd::Params;
use secp256k1::{recover, sign, verify, Message, RecoveryId, SecretKey, Signature};

pub mod api;
mod bip44;
pub mod error;
pub mod utils;

//    let privkey = secp256k1::SecretKey::random(&mut OsRng);
//    let pubkey = secp256k1::PublicKey::from_secret_key(&privkey);
//    let address = "";

pub fn key_generate_mnemonic() -> Result<String, SignerError> {
    let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
    Ok(mnemonic.to_string())
}

pub fn key_derive(mnemonic: String, path: String) -> Result<(String, String, String), SignerError> {
    let mnemonic = Mnemonic::from_phrase(&mnemonic, Language::English).expect("FIXME");

    let seed = Seed::new(&mnemonic, "");

    let master = ExtendedSecretKey::try_from(seed)?;

    let bip44Path = Bip44Path::from_string(path)?;

    let esk = master.derive_bip44(bip44Path)?;

    let prvkey = encode(esk.secret_key());
    let publickey = to_hex_string(&esk.public_key());
    let address = Address::new_secp256k1(esk.public_key().to_vec())
        .map_err(|err| SignerError::GenericString(err.to_string()))?;

    Ok((prvkey, publickey, address.to_string()))
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

pub fn transaction_parse(cbor_hexstring: &[u8]) -> Result<UnsignedMessageUserAPI, SignerError> {
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
    use crate::{key_derive, key_generate_mnemonic, sign_transaction, verify_signature};
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

    const EXAMPLE_PRIVATE_KEY: &str =
        "f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a";

    #[test]
    fn empty() {
        // FIXME:
    }

    #[test]
    fn verify_invalid_signature() {
        // Path 44'/461'/0/0/0
        let prvkey = decode(EXAMPLE_PRIVATE_KEY).unwrap();
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

    #[test]
    fn generate_mnemonic() {
        let mnemonic = key_generate_mnemonic().expect("could not generate mnemonic");
        println!("{}", mnemonic);

        let word_count = mnemonic.split_ascii_whitespace().count();
        assert_eq!(word_count, 24)
    }

    #[test]
    fn derive_child_key() {
        let mnemonic = "equip will roof matter pink blind book anxiety banner elbow sun young";
        let path = "m/44'/461'/0/0/0";
        let (prvkey, publickey, address) =
            key_derive(mnemonic.to_string(), path.to_string()).expect("FIX ME");

        println!("{}", prvkey);
        assert_eq!(prvkey, EXAMPLE_PRIVATE_KEY.to_string());
    }
}
