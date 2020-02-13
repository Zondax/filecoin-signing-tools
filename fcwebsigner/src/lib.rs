mod error;
mod utils;

use crate::utils::set_panic_hook;
use wasm_bindgen::prelude::*;

use fcsigner::api::UnsignedMessageUserAPI;
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
pub fn transaction_create(unsigned_message_string: String) -> Result<String, JsValue> {
    set_panic_hook();

    let unsigned_message: UnsignedMessageUserAPI =
        serde_json::from_str(&unsigned_message_string)
            .map_err(|e| JsValue::from(format!("Error parsing parameters: {}", e)))?;

    let cbor_hexstring = fcsigner::transaction_create(unsigned_message)
        .map_err(|e| JsValue::from(format!("Error converting to CBOR: {}", e)))?;

    Ok(cbor_hexstring)
}

#[wasm_bindgen]
pub fn transaction_parse(cbor_hexstring: String) -> Result<String, JsValue> {
    set_panic_hook();

    let message_parsed =
        fcsigner::transaction_parse(cbor_hexstring).map_err(|e| JsValue::from(e.to_string()))?;

    let tx = serde_json::to_string(&message_parsed).map_err(|e| JsValue::from(e.to_string()))?;

    Ok(tx)
}

#[wasm_bindgen]
pub fn sign_transaction(
    unsigned_message_api: String,
    private_key: String,
) -> Result<String, JsValue> {
    set_panic_hook();

    // FIXME

    let decode_unsigned_message_api = match serde_json::from_str(unsigned_message_api.as_str()) {
        Ok(decode_unsigned_message_api) => decode_unsigned_message_api,
        Err(err) => {
            return Err(JsValue::from_str(
                format!("{}", std::io::Error::from(err)).as_str(),
            ));
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

    let signature = from_hex_string(&signature_hex).map_err(|e| JsValue::from(e.to_string()))?;
    let pubkey = from_hex_string(&pubkey_hex).map_err(|e| JsValue::from(e.to_string()))?;
    let message = from_hex_string(&message_hex).map_err(|e| JsValue::from(e.to_string()))?;

    let resp = fcsigner::verify_signature(&signature, &message, &pubkey);

    return match resp {
        Ok(_bool) => Ok(_bool),
        Err(_) => Err(JsValue::from_str("Error verifying signature")),
    };
}
