mod error;
mod utils;

use crate::utils::set_panic_hook;
use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub fn hello() -> u8 {
    set_panic_hook();
    123
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
                Ok(cbor_hexstring) => Ok(cbor_hexstring),
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
            Ok(transaction) => Ok(transaction),
            Err(err) => Err(JsValue::from_str(
                format!("{}", std::io::Error::from(err)).as_str(),
            )),
        },
        Err(_) => Err(JsValue::from_str("Error parsing the CBOR transaction")),
    }
}

#[wasm_bindgen]
pub fn verify_signature() -> bool {
    set_panic_hook();
    let resp = fcsigner::verify_signature();

    match resp {
        Ok(_bool) => _bool,
        Err(_) => false,
    }
}
