mod error;
mod utils;

use crate::utils::set_panic_hook;
use fcsigner;
use wasm_bindgen::prelude::*;

use fcsigner::api::UnsignedMessageUserAPI;
use fcsigner::utils::{from_hex_string, to_hex_string};

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub struct Keypair {
    // hexstring of the compressed public key
    pubkey: String,
    // hexstring of the private key
    prvkey: String,
    // Address in the string format
    address: String,
}

#[wasm_bindgen]
impl Keypair {
    #[wasm_bindgen(getter)]
    pub fn pubkey(&self) -> String {
        self.pubkey.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn prvkey(&self) -> String {
        self.prvkey.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.address.clone()
    }
}

#[wasm_bindgen]
pub fn key_derive(mnemonic: String, path: String) -> Result<Keypair, JsValue> {
    set_panic_hook();

    let (prvkey, publickey, address) = fcsigner::key_derive(mnemonic, path)
        .map_err(|e| JsValue::from(format!("Error deriving key: {}", e)))?;

    let keypair = Keypair {
        pubkey: publickey,
        prvkey: prvkey,
        address: address,
    };

    Ok(keypair)
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

    let message_parsed = fcsigner::transaction_parse(cbor_hexstring.as_bytes())
        .map_err(|e| JsValue::from(e.to_string()))?;

    let tx = serde_json::to_string(&message_parsed).map_err(|e| JsValue::from(e.to_string()))?;

    Ok(tx)
}

#[wasm_bindgen]
pub fn sign_transaction(
    unsigned_message_string: String,
    private_key: String,
) -> Result<String, JsValue> {
    set_panic_hook();

    let unsigned_message: UnsignedMessageUserAPI =
        serde_json::from_str(&unsigned_message_string)
            .map_err(|e| JsValue::from(format!("Error parsing parameters: {}", e)))?;
    let privatekey_bytes =
        from_hex_string(&private_key).map_err(|e| JsValue::from(e.to_string()))?;

    let resp = fcsigner::sign_transaction(unsigned_message, &privatekey_bytes);

    return match resp {
        // Return R, S & V in one hex string
        Ok((signed_message, v)) => {
            Ok([to_hex_string(&signed_message), format!("{:02x}", &v)].concat())
        }
        Err(_) => Err(JsValue::from_str("Error signing transaction")),
    };
}

#[wasm_bindgen]
pub fn sign_message() {
    set_panic_hook();

    // TODO: message ?
    // TODO: return signature
}

#[wasm_bindgen]
pub fn verify_signature(signature_hex: String, message_hex: String) -> Result<bool, JsValue> {
    set_panic_hook();

    let signature = from_hex_string(&signature_hex).map_err(|e| JsValue::from(e.to_string()))?;

    let resp = fcsigner::verify_signature(&signature, &message_hex.as_bytes());

    return match resp {
        Ok(_bool) => Ok(_bool),
        Err(_) => Err(JsValue::from_str("Error verifying signature")),
    };
}
