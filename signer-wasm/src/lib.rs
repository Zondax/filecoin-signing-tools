use filecoin_signer;
use wasm_bindgen::prelude::*;

use filecoin_signer::api::UnsignedMessageAPI;
use filecoin_signer::utils::{from_hex_string, to_hex_string};
use filecoin_signer::{CborBuffer, PrivateKey, Signature};
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
pub struct ExtendedKey(filecoin_signer::ExtendedKey);

#[wasm_bindgen]
impl ExtendedKey {
    #[wasm_bindgen(getter)]
    pub fn public_raw(&self) -> Vec<u8> {
        self.0.public_key.0.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn public_compressed_raw(&self) -> Vec<u8> {
        self.0.public_key_compressed.0.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn private_raw(&self) -> Vec<u8> {
        self.0.private_key.0.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn public_hexstring(&self) -> String {
        to_hex_string(&self.public_raw())
    }

    #[wasm_bindgen(getter)]
    pub fn public_compressed_hexstring(&self) -> String {
        to_hex_string(&self.public_compressed_raw())
    }

    #[wasm_bindgen(getter)]
    pub fn private_hexstring(&self) -> String {
        to_hex_string(&self.private_raw())
    }

    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.0.address.clone()
    }
}

#[wasm_bindgen]
pub fn mnemonic_generate() -> Result<String, JsValue> {
    set_panic_hook();

    let mnemonic = filecoin_signer::key_generate_mnemonic()
        .map_err(|e| JsValue::from(format!("Error generating key: {}", e)))?;

    Ok(mnemonic.0)
}

#[wasm_bindgen]
pub fn key_derive(mnemonic: String, path: String) -> Result<ExtendedKey, JsValue> {
    set_panic_hook();

    let key_address = filecoin_signer::key_derive(&mnemonic, &path)
        .map_err(|e| JsValue::from(format!("Error deriving key: {}", e)))?;

    Ok(ExtendedKey { 0: key_address })
}

#[wasm_bindgen]
pub fn key_derive_from_seed(seed_hexstring: String, path: String) -> Result<ExtendedKey, JsValue> {
    set_panic_hook();

    let seed_bytes = from_hex_string(&seed_hexstring).map_err(|e| JsValue::from(e.to_string()))?;

    let key_address = filecoin_signer::key_derive_from_seed(&seed_bytes, &path)
        .map_err(|e| JsValue::from(format!("Error deriving key: {}", e)))?;

    Ok(ExtendedKey { 0: key_address })
}

#[wasm_bindgen]
pub fn key_recover(private_key_hexstring: String, testnet: bool) -> Result<ExtendedKey, JsValue> {
    set_panic_hook();

    let private_key =
        PrivateKey::try_from(private_key_hexstring).map_err(|e| JsValue::from(e.to_string()))?;

    let key_address = filecoin_signer::key_recover(&private_key, testnet)
        .map_err(|e| JsValue::from(format!("Error deriving key: {}", e)))?;

    Ok(ExtendedKey { 0: key_address })
}

#[wasm_bindgen]
pub fn transaction_serialize(unsigned_message_string: String) -> Result<String, JsValue> {
    set_panic_hook();
    let s = transaction_serialize_raw(unsigned_message_string)?;
    Ok(to_hex_string(&s))
}

#[wasm_bindgen]
pub fn transaction_serialize_raw(unsigned_message_string: String) -> Result<Vec<u8>, JsValue> {
    set_panic_hook();

    let unsigned_message: UnsignedMessageAPI = serde_json::from_str(&unsigned_message_string)
        .map_err(|e| JsValue::from(format!("Error parsing parameters: {}", e)))?;

    let cbor_buffer = filecoin_signer::transaction_serialize(&unsigned_message)
        .map_err(|e| JsValue::from(format!("Error converting to CBOR: {}", e)))?;

    Ok(cbor_buffer.0.to_vec())
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
pub fn transaction_sign(
    unsigned_tx_js: JsValue,
    private_key_hexstring: String,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let unsigned_message = unsigned_tx_js
        .into_serde()
        .map_err(|e| JsValue::from(format!("Error parsing parameters: {}", e)))?;

    let private_key =
        PrivateKey::try_from(private_key_hexstring).map_err(|e| JsValue::from(e.to_string()))?;

    let signed_message = filecoin_signer::transaction_sign(&unsigned_message, &private_key)
        .map_err(|e| JsValue::from_str(format!("Error signing transaction: {}", e).as_str()))?;

    let signed_message_js = JsValue::from_serde(&signed_message)
        .map_err(|e| JsValue::from(format!("Error signing transaction: {}", e)))?;

    Ok(signed_message_js)
}

#[wasm_bindgen]
pub fn message_sign() {
    set_panic_hook();
    // TODO: Purpose is unclear. TBD
    // TODO: return signature
}

#[wasm_bindgen]
pub fn verify_signature(signature_hex: String, message_hex: String) -> Result<bool, JsValue> {
    set_panic_hook();

    let signature = Signature::try_from(signature_hex).map_err(|e| JsValue::from(e.to_string()))?;

    let message =
        CborBuffer(from_hex_string(&message_hex).map_err(|e| JsValue::from(e.to_string()))?);

    filecoin_signer::verify_signature(&signature, &message)
        .map_err(|e| JsValue::from_str(format!("Error verifying signature: {}", e).as_str()))
}

#[cfg(target_arch = "wasm32")]
#[cfg(test)]
mod tests {
    use crate::transaction_sign;
    use wasm_bindgen::prelude::*;

    const EXAMPLE_UNSIGNED_MESSAGE: &str = r#"
        {
            "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
            "from": "t1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka",
            "nonce": 1,
            "value": "100000",
            "gasprice": "2500",
            "gaslimit": 25000,
            "method": 0,
            "params": ""
        }"#;

    const EXAMPLE_PRIVATE_KEY: &str =
        "f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a";

    #[test]
    fn signature() {
        let signed_tx = transaction_sign(
            JsValue::from(EXAMPLE_UNSIGNED_MESSAGE),
            EXAMPLE_PRIVATE_KEY.to_string(),
        )
        .unwrap();

        println!("{:?}", signed_tx);
    }
}
