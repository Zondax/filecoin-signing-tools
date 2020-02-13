mod error;
mod utils;

use crate::utils::set_panic_hook;
use wasm_bindgen::prelude::*;

use fcsigner::utils::{from_hex_string, to_hex_string};
use secp256k1::SecretKey;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub fn key_generate() {
    set_panic_hook();

    // TODO: return keypair (pub/priv + address)
    fcsigner::key_generate();
}

#[wasm_bindgen]
pub fn transaction_create(unsigned_message_api: String) -> Result<String, JsValue> {
    set_panic_hook();

    match serde_json::from_str(unsigned_message_api.as_str()) {
        Ok(decode_unsigned_message_api) => {
            match fcsigner::transaction_create(decode_unsigned_message_api) {
                Ok(cbor_hexstring) => Ok(cbor_hexstring),
                Err(_) => Err(JsValue::from_str(
                    "Error converting the transaction to CBOR",
                )),
            }
        }
        Err(err) => Err(JsValue::from_str(
            format!("{}", std::io::Error::from(err)).as_str(),
        )),
    }
}

#[wasm_bindgen]
pub fn transaction_parse(cbor_hexstring: String) -> Result<String, JsValue> {
    set_panic_hook();

    match fcsigner::transaction_parse(cbor_hexstring) {
        Ok(message_parsed) => match serde_json::to_string(&message_parsed) {
            Ok(transaction) => Ok(transaction),
            Err(err) => Err(JsValue::from_str(
                format!("{}", std::io::Error::from(err)).as_str(),
            )),
        },
        Err(_) => Err(JsValue::from_str("Error parsing the CBOR transaction")),
    }
}

#[wasm_bindgen]
pub fn sign_transaction(
    unsigned_message_api: String,
    private_key: String,
) -> Result<String, JsValue> {
    set_panic_hook();

    let decode_unsigned_message_api = match serde_json::from_str(unsigned_message_api.as_str()) {
        Ok(decode_unsigned_message_api) => decode_unsigned_message_api,
        Err(err) => {
            return Err(JsValue::from_str(
                format!("{}", std::io::Error::from(err)).as_str(),
            ))
        }
    };
    let secret_key = match from_hex_string(&private_key) {
        Ok(private_key) => match SecretKey::parse_slice(&private_key) {
            Ok(secret_key) => secret_key,
            Err(_) => return Err(JsValue::from_str("Error while parsing private key")),
        },
        Err(_) => return Err(JsValue::from_str("Error while converting key from hex")),
    };

    let signed_message = match fcsigner::sign_transaction(decode_unsigned_message_api, secret_key) {
        Ok(signed_message) => signed_message,
        Err(_) => return Err(JsValue::from_str("Error signing message")),
    };

    Ok(to_hex_string(&signed_message.serialize()))
}

#[wasm_bindgen]
pub fn sign_message() {
    set_panic_hook();

    // TODO: message ?
    // TODO: return signature
}

#[wasm_bindgen]
pub fn verify_signature(
    signature_hex: String,
    message_hex: String,
    pubkey_hex: String,
) -> Result<bool, JsValue> {
    set_panic_hook();

    let signature = match from_hex_string(&signature_hex) {
        Ok(signature) => signature,
        Err(err) => return Err(JsValue::from_str("Error decoding signature")),
    };

    let pubkey = match from_hex_string(&pubkey_hex) {
        Ok(pubkey) => pubkey,
        Err(err) => return Err(JsValue::from_str("Error decoding public key")),
    };

    let message = match from_hex_string(&message_hex) {
        Ok(message) => message,
        Err(err) => return Err(JsValue::from_str("Error decoding message")),
    };

    let resp = fcsigner::verify_signature(&signature, &message, &pubkey);

    return match resp {
        Ok(_bool) => Ok(_bool),
        Err(_) => Err(JsValue::from_str("Error verifying signature")),
    };
}
