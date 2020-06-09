#![cfg_attr(
    not(test),
    deny(
        clippy::option_unwrap_used,
        clippy::option_expect_used,
        clippy::result_unwrap_used,
        clippy::result_expect_used,
    )
)]

use filecoin_signer::api::UnsignedMessageAPI;
use filecoin_signer::signature::Signature;
use filecoin_signer::{CborBuffer, PrivateKey};
use std::convert::TryFrom;
use wasm_bindgen::prelude::*;

mod utils;

#[cfg(target_arch = "wasm32")]
pub mod ledger;
#[cfg(target_arch = "wasm32")]
mod ledger_errors;

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
    pub fn private_raw(&self) -> Vec<u8> {
        self.0.private_key.0.to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn public_hexstring(&self) -> String {
        hex::encode(&self.public_raw())
    }

    #[wasm_bindgen(getter)]
    pub fn private_hexstring(&self) -> String {
        hex::encode(&self.private_raw())
    }

    #[wasm_bindgen(getter)]
    pub fn public_base64(&self) -> String {
        base64::encode(&self.public_raw())
    }

    #[wasm_bindgen(getter)]
    pub fn private_base64(&self) -> String {
        base64::encode(&self.private_raw())
    }

    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.0.address.clone()
    }
}

fn extract_private_key(private_key_js: JsValue) -> Result<PrivateKey, JsValue> {
    if let Some(s) = private_key_js.as_string() {
        return Ok(PrivateKey::try_from(s).map_err(|e| JsValue::from(e.to_string()))?);
    }

    if private_key_js.is_object() {
        let v = js_sys::Uint8Array::new(&private_key_js).to_vec();

        let result = PrivateKey::try_from(v).map_err(|e| JsValue::from(e.to_string()))?;

        return Ok(result);
    }

    Err(JsValue::from(
        "Private key must be encoded as hexstring, base64 or buffer",
    ))
}

fn extract_bytes(encoded_bytes_js: JsValue, error_message: &str) -> Result<Vec<u8>, JsValue> {
    if let Some(s) = encoded_bytes_js.as_string() {
        if let Ok(v) = hex::decode(&s) {
            return Ok(v);
        }

        if let Ok(v) = base64::decode(&s) {
            return Ok(v);
        }
    }

    if encoded_bytes_js.is_object() {
        let v = js_sys::Uint8Array::new(&encoded_bytes_js).to_vec();
        return Ok(v);
    }

    Err(JsValue::from(error_message))
}

#[wasm_bindgen(js_name = generateMnemonic)]
pub fn mnemonic_generate() -> Result<String, JsValue> {
    set_panic_hook();

    let mnemonic = filecoin_signer::key_generate_mnemonic()
        .map_err(|e| JsValue::from(format!("Error generating key: {}", e)))?;

    Ok(mnemonic.0)
}

#[wasm_bindgen(js_name = keyDerive)]
pub fn key_derive(
    mnemonic: String,
    path: String,
    password: String,
) -> Result<ExtendedKey, JsValue> {
    set_panic_hook();

    let key_address = filecoin_signer::key_derive(&mnemonic, &path, &password)
        .map_err(|e| JsValue::from(format!("Error deriving key: {}", e)))?;

    Ok(ExtendedKey { 0: key_address })
}

#[wasm_bindgen(js_name = keyDeriveFromSeed)]
pub fn key_derive_from_seed(seed: JsValue, path: String) -> Result<ExtendedKey, JsValue> {
    set_panic_hook();

    let seed_bytes = extract_bytes(seed, "Seed must be a valid hexstring, base64 or a buffer")?;

    let key_address = filecoin_signer::key_derive_from_seed(&seed_bytes, &path)
        .map_err(|e| JsValue::from(format!("Error deriving key: {}", e)))?;

    Ok(ExtendedKey { 0: key_address })
}

#[wasm_bindgen(js_name = keyRecover)]
pub fn key_recover(private_key_js: JsValue, testnet: bool) -> Result<ExtendedKey, JsValue> {
    set_panic_hook();

    let private_key_bytes = extract_private_key(private_key_js)?;

    let key_address = filecoin_signer::key_recover(&private_key_bytes, testnet)
        .map_err(|e| JsValue::from(format!("Error deriving key: {}", e)))?;

    Ok(ExtendedKey { 0: key_address })
}

#[wasm_bindgen(js_name = transactionSerialize)]
pub fn transaction_serialize(message: JsValue) -> Result<String, JsValue> {
    set_panic_hook();

    let s = transaction_serialize_raw(message)?;

    Ok(hex::encode(&s))
}

#[wasm_bindgen(js_name = transactionSerializeRaw)]
pub fn transaction_serialize_raw(unsigned_message: JsValue) -> Result<Vec<u8>, JsValue> {
    set_panic_hook();

    // FIXME: Should be MessageTxAPI because it can be unsigned message or signed message
    let unsigned_message: UnsignedMessageAPI = unsigned_message
        .into_serde()
        .map_err(|e| JsValue::from(format!("Error parsing parameters: {}", e)))?;

    let cbor_buffer = filecoin_signer::transaction_serialize(&unsigned_message)
        .map_err(|e| JsValue::from(format!("Error converting to CBOR: {}", e)))?;

    Ok(cbor_buffer.0.to_vec())
}

#[wasm_bindgen(js_name = transactionParse)]
pub fn transaction_parse(cbor_js: JsValue, testnet: bool) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let cbor_bytes = extract_bytes(
        cbor_js,
        "CBOR message must be encoded as hexstring, base64 or a buffer",
    )?;

    let message_parsed = filecoin_signer::transaction_parse(&CborBuffer(cbor_bytes), testnet)
        .map_err(|e| JsValue::from(e.to_string()))?;

    let tx = JsValue::from_serde(&message_parsed).map_err(|e| JsValue::from(e.to_string()))?;

    Ok(tx)
}

#[wasm_bindgen(js_name = transactionSign)]
pub fn transaction_sign(
    unsigned_tx_js: JsValue,
    private_key_js: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let unsigned_message = unsigned_tx_js
        .into_serde()
        .map_err(|e| JsValue::from(format!("Error parsing parameters: {}", e)))?;

    let private_key_bytes = extract_private_key(private_key_js)?;

    let signed_message =
        filecoin_signer::transaction_sign(&unsigned_message, &private_key_bytes)
            .map_err(|e| JsValue::from_str(format!("Error signing transaction: {}", e).as_str()))?;

    let signed_message_js = JsValue::from_serde(&signed_message)
        .map_err(|e| JsValue::from(format!("Error signing transaction: {}", e)))?;

    Ok(signed_message_js)
}

#[wasm_bindgen(js_name = transactionSignLotus)]
pub fn transaction_sign_lotus(
    unsigned_tx_js: JsValue,
    private_key_js: JsValue,
) -> Result<String, JsValue> {
    set_panic_hook();

    let unsigned_message = unsigned_tx_js
        .into_serde()
        .map_err(|e| JsValue::from(format!("Error parsing parameters: {}", e)))?;

    let private_key_bytes = extract_private_key(private_key_js)?;

    let signed_message =
        filecoin_signer::transaction_sign(&unsigned_message, &private_key_bytes)
            .map_err(|e| JsValue::from_str(format!("Error signing transaction: {}", e).as_str()))?;

    let signed_message_lotus = utils::convert_to_lotus_signed_message(signed_message);

    Ok(signed_message_lotus)
}

#[wasm_bindgen(js_name = transactionSignRaw)]
pub fn transaction_sign_raw(
    unsigned_tx_js: JsValue,
    private_key_js: JsValue,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let unsigned_message = unsigned_tx_js
        .into_serde()
        .map_err(|e| JsValue::from(format!("Error parsing parameters: {}", e)))?;

    let private_key = extract_private_key(private_key_js)?;

    let signed_message = filecoin_signer::transaction_sign_raw(&unsigned_message, &private_key)
        .map_err(|e| JsValue::from_str(format!("Error signing transaction: {}", e).as_str()))?;

    let signed_message_js = JsValue::from_serde(&signed_message.as_bytes())
        .map_err(|e| JsValue::from(format!("Error signing transaction: {}", e)))?;

    Ok(signed_message_js)
}

#[wasm_bindgen(js_name = verifySignature)]
pub fn verify_signature(signature_js: JsValue, message_js: JsValue) -> Result<bool, JsValue> {
    set_panic_hook();

    let signature_bytes = extract_bytes(
        signature_js,
        "Signature must be encoded as hexstring, base64 or a buffer",
    )?;

    let sig = Signature::try_from(signature_bytes).map_err(|e| JsValue::from(e.to_string()))?;

    let message_bytes = extract_bytes(
        message_js,
        "Message must be encoced as hexstring, base64 or a buffer",
    )?;

    filecoin_signer::verify_signature(&sig, &CborBuffer(message_bytes))
        .map_err(|e| JsValue::from_str(format!("Error verifying signature: {}", e).as_str()))
}

#[cfg(target_arch = "wasm32")]
#[cfg(test)]
mod tests_wasm {
    use crate::{transaction_sign, verify_signature};
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
    fn check_signature() {
        let tx = "885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855010f323f4709e8e4db0c1d4cd374f9f35201d26fb20144000186a0430009c41961a80040";
        let signature = "646fa7e159c263289b7852c88ecfbd553c2bc0ef612630f20a851226b1ef5c7f65a6699066960eaa4796594acb26c5e13bb1335ce9bacb44ad9574723ff5623f01";

        let ret = verify_signature(JsValue::from_str(signature), JsValue::from_str(tx));
        assert_eq!(ret.is_ok(), true);
        assert_eq!(ret.unwrap(), true);
    }

    #[test]
    fn signature() {
        let signed_tx = transaction_sign(
            JsValue::from(EXAMPLE_UNSIGNED_MESSAGE),
            JsValue::from_str(EXAMPLE_PRIVATE_KEY),
        )
        .unwrap();

        println!("{:?}", signed_tx);
    }
}
