mod error;

use fcsigner;
use wasm_bindgen::prelude::*;

use fcsigner::api::MessageTx::{SignedMessage, UnsignedMessage};
use fcsigner::api::UnsignedMessageUserAPI;
use fcsigner::utils::from_hex_string;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

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

#[wasm_bindgen]
pub struct Keypair {
    // hexstring of the compressed public key
    public: String,
    // hexstring of the private key
    private: String,
    // Address in the string format
    address: String,
}

#[wasm_bindgen]
impl Keypair {
    #[wasm_bindgen(getter)]
    pub fn public(&self) -> String {
        self.public.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn private(&self) -> String {
        self.private.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.address.clone()
    }
}

#[wasm_bindgen]
pub fn key_derive(mnemonic: String, path: String) -> Result<Keypair, JsValue> {
    set_panic_hook();

    let (private, public, address) = fcsigner::key_derive(mnemonic, path)
        .map_err(|e| JsValue::from(format!("Error deriving key: {}", e)))?;

    let keypair = Keypair {
        public,
        private,
        address,
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
pub fn transaction_parse(cbor_hexstring: String, network: bool) -> Result<String, JsValue> {
    set_panic_hook();

    let message_parsed = fcsigner::transaction_parse(cbor_hexstring.as_bytes(), network)
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

    let private_key_bytes =
        from_hex_string(&private_key).map_err(|e| JsValue::from(e.to_string()))?;

    let tmp = fcsigner::sign_transaction(unsigned_message, &private_key_bytes)
        .map_err(|e| JsValue::from_str(format!("Error signing transaction: {}", e).as_str()));

    let (signature, v) = tmp?;

    // SignedMessage::new()

    let json_signed_message = serde_json::to_string(signed_message)
        .map_err(|e| Err(JsValue::from_str("Error signing transaction")))?;

    Ok(json_signed_message)
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
