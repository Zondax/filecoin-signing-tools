mod utils;

use crate::utils::set_panic_hook;
use fcsigner;
use wasm_bindgen::prelude::*;

use secp256k1::SecretKey;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub fn hello() -> u8 {
    set_panic_hook();
    return 123;
}

#[wasm_bindgen]
pub fn key_generate() {
    // TODO: return keypair (pub/priv + address)
    fcsigner::key_generate();
}

#[wasm_bindgen]
pub fn transaction_create(unsigned_message_api: String) -> Result<String, JsValue> {
    match serde_json::from_str(unsigned_message_api.as_str()) {
        Ok(decode_unsigned_message_api) => {
            match fcsigner::transaction_create(decode_unsigned_message_api) {
                Ok(cbor_hexstring) => Ok(cbor_hexstring.into()),
                Err(_) => Err(JsValue::from_str(
                    "Error converting the transcation to CBOR",
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
    match fcsigner::transaction_parse(cbor_hexstring) {
        Ok(message_parsed) => match serde_json::to_string(&message_parsed) {
            Ok(transaction) => Ok(transaction.into()),
            Err(err) => Err(JsValue::from_str(
                format!("{}", std::io::Error::from(err)).as_str(),
            )),
        },
        Err(_) => Err(JsValue::from_str("Error parsing the CBOR transaction")),
    }
}

#[wasm_bindgen]
pub fn sign_transaction(unsigned_message_api: String, prvkey: String) -> Result<String, JsValue> {
    /*match serde_json::from_str(unsigned_message_api.as_str()) {
        Ok(decode_unsigned_message_api) => {
            // convert prvkey
            match SecretKey::parse_slice(&utils::from_hex_string(&prvkey).unwrap()) {
                Ok(secret_key) => {
                    match fcsigner::sign_transaction(decode_unsigned_message_api, secret_key) {
                        Ok(signed_message) => Ok(utils::to_hex_string(&signed_message.serialize())),
                        Err(err) => Err(JsValue::from_str("Error when signing")),
                    }

                }
                Err(err) => Err(JsValue::from_str("Error while parsing private key")),
            }

        }
        Err(err) => Err(JsValue::from_str(
            format!("{}", std::io::Error::from(err)).as_str(),
        )),
    }*/

    let decode_unsigned_message_api = match serde_json::from_str(unsigned_message_api.as_str()) {
        Ok(decode_unsigned_message_api) => decode_unsigned_message_api,
        Err(err) => {
            return Err(JsValue::from_str(
                format!("{}", std::io::Error::from(err)).as_str(),
            ))
        }
    };
    let secret_key = match utils::from_hex_string(&prvkey) {
        Ok(prvkey_bytes) => match SecretKey::parse_slice(&prvkey_bytes) {
            Ok(secret_key) => secret_key,
            Err(_) => return Err(JsValue::from_str("Error while parsing private key")),
        },
        Err(_) => return Err(JsValue::from_str("Error while converting key from hex")),
    };

    let signed_message = match fcsigner::sign_transaction(decode_unsigned_message_api, secret_key) {
        Ok(signed_message) => signed_message,
        Err(_) => return Err(JsValue::from_str("Error signing message")),
    };

    Ok(utils::to_hex_string(&signed_message.serialize()))
}

#[wasm_bindgen]
pub fn sign_message() {
    // TODO: message ?
    // TODO: return signature
}

#[wasm_bindgen]
pub fn verify_signature() -> bool {
    set_panic_hook();
    let resp = fcsigner::verify_signature();

    match resp {
        Ok(_bool) => return _bool,
        Err(_) => return false,
    }
}
