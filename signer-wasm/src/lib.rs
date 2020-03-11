mod error;

use filecoin_signer;
use wasm_bindgen::prelude::*;

use filecoin_signer::api::UnsignedMessageAPI;
use filecoin_signer::utils::{from_hex_string, to_hex_string};
use filecoin_signer::{CborBuffer, Mnemonic, PublicKey, SecretKey, Signature};
use std::convert::TryFrom;

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
    // compressed public key
    public_raw: PublicKey,
    // private key
    private_raw: SecretKey,
    // Address in the string format
    address: String,
}

#[wasm_bindgen]
impl Keypair {
    #[wasm_bindgen(getter)]
    pub fn public(&self) -> String {
        to_hex_string(&self.public_raw.0)
    }

    #[wasm_bindgen(getter)]
    pub fn public_raw(&self) -> Vec<u8> {
        self.public_raw.0.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn private(&self) -> String {
        to_hex_string(&self.private_raw.0[..])
    }

    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.address.clone()
    }
}

#[wasm_bindgen]
pub fn key_generate_mnemonic() -> Result<String, JsValue> {
    set_panic_hook();

    let mnemonic = fcsigner::key_generate_mnemonic()
        .map_err(|e| JsValue::from(format!("Error generating key: {}", e)))?;

    Ok(mnemonic)
}

#[wasm_bindgen]
pub fn key_derive(mnemonic: String, path: String) -> Result<Keypair, JsValue> {
    set_panic_hook();

    let (private, public, address) = filecoin_signer::key_derive(Mnemonic(mnemonic), path)
        .map_err(|e| JsValue::from(format!("Error deriving key: {}", e)))?;

    let keypair = Keypair {
        public_raw: public,
        private_raw: private,
        address,
    };

    Ok(keypair)
}

#[wasm_bindgen]
pub fn transaction_serialize(unsigned_message_string: String) -> Result<String, JsValue> {
    set_panic_hook();

    let unsigned_message: UnsignedMessageAPI = serde_json::from_str(&unsigned_message_string)
        .map_err(|e| JsValue::from(format!("Error parsing parameters: {}", e)))?;

    let cbor_buffer = filecoin_signer::transaction_serialize(unsigned_message)
        .map_err(|e| JsValue::from(format!("Error converting to CBOR: {}", e)))?;

    Ok(to_hex_string(cbor_buffer.0.as_ref()))
}

#[wasm_bindgen]
pub fn transaction_parse(cbor_hexstring: String, network: bool) -> Result<String, JsValue> {
    set_panic_hook();

    let cbor_data =
        CborBuffer(from_hex_string(&cbor_hexstring).map_err(|e| JsValue::from(e.to_string()))?);

    let message_parsed = filecoin_signer::transaction_parse(&cbor_data, network)
        .map_err(|e| JsValue::from(e.to_string()))?;

    let tx = serde_json::to_string(&message_parsed).map_err(|e| JsValue::from(e.to_string()))?;

    Ok(tx)
}

#[wasm_bindgen]
pub fn sign_transaction(
    unsigned_message_string: String,
    secret_key_string: String,
) -> Result<String, JsValue> {
    set_panic_hook();

    let unsigned_message: UnsignedMessageAPI = serde_json::from_str(&unsigned_message_string)
        .map_err(|e| JsValue::from(format!("Error parsing parameters: {}", e)))?;

    let secret_key =
        SecretKey::try_from(secret_key_string).map_err(|e| JsValue::from(e.to_string()))?;

    let tmp = filecoin_signer::sign_transaction(unsigned_message, &secret_key)
        .map_err(|e| JsValue::from_str(format!("Error signing transaction: {}", e).as_str()))?;

    // // SignedMessage::new()
    //
    // let json_signed_message = serde_json::to_string(signed_message)
    //     .map_err(|e| Err(JsValue::from_str("Error signing transaction")))?;
    //
    // Ok(json_signed_message)
    Ok(to_hex_string(&tmp.0))
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

    let signature = Signature::try_from(signature_hex).map_err(|e| JsValue::from(e.to_string()))?;

    let message =
        CborBuffer(from_hex_string(&message_hex).map_err(|e| JsValue::from(e.to_string()))?);

    let resp = filecoin_signer::verify_signature(&signature, &message)
        .map_err(|e| JsValue::from_str(format!("Error verifying signature: {}", e).as_str()));

    resp
}
