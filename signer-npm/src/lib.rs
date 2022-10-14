#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used,))]

use std::convert::TryFrom;

use wasm_bindgen::prelude::*;

use filecoin_signer::api::{MessageParams, MessageTxAPI};
use filecoin_signer::{PrivateKey, ProposalHashDataAPI, SignedVoucherWrapper};
use fvm_shared::crypto::signature::Signature;

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
        self.0.public_key.to_vec()
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
        return PrivateKey::try_from(s).map_err(|e| JsValue::from(e.to_string()));
    }

    if private_key_js.is_object() {
        let v = js_sys::Uint8Array::new(&private_key_js).to_vec();

        let result = PrivateKey::try_from(v).map_err(|e| JsValue::from(e.to_string()))?;

        return Ok(result);
    }

    Err(JsValue::from(
        "Private key must be encoded as base64 string or be a buffer",
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
    language_code: Option<String>,
) -> Result<ExtendedKey, JsValue> {
    set_panic_hook();

    let lc = match language_code {
        Some(lc) => lc,
        None => "en".to_string(),
    };

    let key_address = filecoin_signer::key_derive(&mnemonic, &path, &password, &lc)
        .map_err(|e| JsValue::from(format!("Error deriving key: {}", e)))?;

    Ok(ExtendedKey(key_address))
}

#[wasm_bindgen(js_name = keyDeriveFromSeed)]
pub fn key_derive_from_seed(seed: JsValue, path: String) -> Result<ExtendedKey, JsValue> {
    set_panic_hook();

    let seed_bytes = extract_bytes(seed, "Seed must be a valid hexstring, base64 or a buffer")?;

    let key_address = filecoin_signer::key_derive_from_seed(&seed_bytes, &path)
        .map_err(|e| JsValue::from(format!("Error deriving key: {}", e)))?;

    Ok(ExtendedKey(key_address))
}

#[wasm_bindgen(js_name = keyRecover)]
pub fn key_recover(private_key_js: JsValue, testnet: bool) -> Result<ExtendedKey, JsValue> {
    set_panic_hook();

    let private_key_bytes = extract_private_key(private_key_js)?;

    let key_address = filecoin_signer::key_recover(&private_key_bytes, testnet)
        .map_err(|e| JsValue::from(format!("Error deriving key: {}", e)))?;

    Ok(ExtendedKey(key_address))
}

#[wasm_bindgen(js_name = keyRecoverBLS)]
pub fn key_recover_bls(private_key_js: JsValue, testnet: bool) -> Result<ExtendedKey, JsValue> {
    set_panic_hook();

    let private_key_bytes = extract_private_key(private_key_js)?;

    let key_address = filecoin_signer::key_recover_bls(&private_key_bytes, testnet)
        .map_err(|e| JsValue::from(format!("Error deriving key: {}", e)))?;

    Ok(ExtendedKey(key_address))
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

    let unsigned_message: MessageTxAPI = unsigned_message
        .into_serde()
        .map_err(|e| JsValue::from(format!("Error parsing parameters: {}", e)))?;

    // TODO: support SignedMessage
    let msg = match unsigned_message {
        MessageTxAPI::Message(m) => m,
        MessageTxAPI::SignedMessage(_) => {
            return Err(JsValue::from("Can't serialize SignedMessage"))
        }
    };

    let cbor_buffer = filecoin_signer::transaction_serialize(&msg)
        .map_err(|e| JsValue::from(format!("Error converting to CBOR: {}", e)))?;

    Ok(cbor_buffer)
}

#[wasm_bindgen(js_name = transactionParse)]
pub fn transaction_parse(cbor_js: JsValue, testnet: bool) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let cbor_bytes = extract_bytes(
        cbor_js,
        "CBOR message must be encoded as hexstring, base64 or a buffer",
    )?;

    let message_parsed = filecoin_signer::transaction_parse(&cbor_bytes, testnet)
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

    let msg = match unsigned_message {
        MessageTxAPI::Message(m) => m,
        MessageTxAPI::SignedMessage(_) => {
            return Err(JsValue::from("Attempting to sign a SignedMessage."))
        }
    };

    let private_key_bytes = extract_private_key(private_key_js)?;

    let signed_message = filecoin_signer::transaction_sign(&msg, &private_key_bytes)
        .map_err(|e| JsValue::from_str(format!("Error signing transaction: {}", e).as_str()))?;

    let signed_message_js = JsValue::from_serde(&MessageTxAPI::SignedMessage(signed_message))
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

    let msg = match unsigned_message {
        MessageTxAPI::Message(m) => m,
        MessageTxAPI::SignedMessage(_) => {
            return Err(JsValue::from("Attempting to sign a SignedMessage."))
        }
    };

    let private_key_bytes = extract_private_key(private_key_js)?;

    let signed_message = filecoin_signer::transaction_sign(&msg, &private_key_bytes)
        .map_err(|e| JsValue::from_str(format!("Error signing transaction: {}", e).as_str()))?;

    let signed_message_lotus = serde_json::to_string(&MessageTxAPI::SignedMessage(signed_message))
        .map_err(|e| JsValue::from_str(format!("Error converting into JSON: {}", e).as_str()))?;

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

    let msg = match unsigned_message {
        MessageTxAPI::Message(m) => m,
        MessageTxAPI::SignedMessage(_) => {
            return Err(JsValue::from("Attempting to sign a SignedMessage."))
        }
    };

    let private_key = extract_private_key(private_key_js)?;

    let signature = filecoin_signer::transaction_sign_raw(&msg, &private_key)
        .map_err(|e| JsValue::from_str(format!("Error signing transaction: {}", e).as_str()))?;

    let signature_js = JsValue::from_serde(&signature.bytes())
        .map_err(|e| JsValue::from(format!("Error signing transaction: {}", e)))?;

    Ok(signature_js)
}

#[wasm_bindgen(js_name = verifySignature)]
pub fn verify_signature(signature_js: JsValue, message_js: JsValue) -> Result<bool, JsValue> {
    set_panic_hook();

    let signature_bytes = extract_bytes(
        signature_js,
        "Signature must be encoded as hexstring, base64 or a buffer",
    )?;

    let sig = match signature_bytes.len() {
        fvm_shared::crypto::signature::BLS_SIG_LEN => Signature::new_bls(signature_bytes),
        fvm_shared::crypto::signature::SECP_SIG_LEN => Signature::new_secp256k1(signature_bytes),
        _ => {
            return Err(JsValue::from_str(
                "Signature doesn't match BLS or SECP256K length",
            ))
        }
    };

    let message_bytes = extract_bytes(
        message_js,
        "Message must be encoded as hexstring, base64 or a buffer",
    )?;

    filecoin_signer::verify_signature(&sig, &message_bytes)
        .map_err(|e| JsValue::from_str(format!("Error verifying signature: {}", e).as_str()))
}

#[wasm_bindgen(js_name = signVoucher)]
pub fn sign_voucher(voucher: String, private_key_js: JsValue) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let private_key_bytes = extract_private_key(private_key_js)?;

    let voucher = filecoin_signer::sign_voucher(voucher, &private_key_bytes)
        .map_err(|e| JsValue::from_str(format!("Error signing voucher: {}", e).as_str()))?;

    let voucher_js = JsValue::from_serde(&voucher)
        .map_err(|e| JsValue::from(format!("Error converting voucher: {}", e)))?;

    Ok(voucher_js)
}

#[wasm_bindgen(js_name = createVoucher)]
pub fn create_voucher(
    payment_channel_address: String,
    time_lock_min: String,
    time_lock_max: String,
    amount: String,
    lane: String,
    nonce: u32,
    min_settle_height: String,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let tlmin = time_lock_min
        .parse::<i64>()
        .map_err(|e| JsValue::from(format!("Error converting to i64: {}", e)))?;
    let tlmax = time_lock_max
        .parse::<i64>()
        .map_err(|e| JsValue::from(format!("Error converting to i64: {}", e)))?;

    let l = lane
        .parse::<u64>()
        .map_err(|e| JsValue::from(format!("Error converting to i64: {}", e)))?;

    let msh = min_settle_height
        .parse::<i64>()
        .map_err(|e| JsValue::from(format!("Error converting to i64: {}", e)))?;

    let voucher = filecoin_signer::create_voucher(
        payment_channel_address,
        tlmin,
        tlmax,
        amount,
        l,
        nonce as u64,
        msh,
    )
    .map_err(|e| {
        JsValue::from_str(format!("Error creating payment channel voucher: {}", e).as_str())
    })?;

    let voucher_js = JsValue::from_serde(&voucher)
        .map_err(|e| JsValue::from(format!("Error converting payment channel voucher: {}", e)))?;

    Ok(voucher_js)
}

#[wasm_bindgen(js_name = serializeParams)]
pub fn serialize_params(params_value: JsValue) -> Result<Vec<u8>, JsValue> {
    set_panic_hook();

    let params: MessageParams = params_value
        .into_serde()
        .map_err(|e| JsValue::from(format!("Error parsing parameters: {}", e)))?;

    let params_cbor = filecoin_signer::serialize_params(params)
        .map_err(|e| JsValue::from(format!("Error serializing parameters: {}", e)))?;

    Ok(params_cbor)
}

#[wasm_bindgen(js_name = deserializeParams)]
pub fn deserialize_params(
    params_base64: String,
    actor_type: String,
    method: u32,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let params = filecoin_signer::deserialize_params(params_base64, actor_type, method as u64)
        .map_err(|e| JsValue::from(format!("Error deserializing parameters: {}", e)))?;

    let params_value = JsValue::from_serde(&params)
        .map_err(|e| JsValue::from(format!("Error converting parameters to json object: {}", e)))?;

    Ok(params_value)
}

#[wasm_bindgen(js_name = deserializeConstructorParams)]
pub fn deserialize_constructor_params(
    params_base64: String,
    code_cid: String,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let params = filecoin_signer::deserialize_constructor_params(params_base64, code_cid)
        .map_err(|e| JsValue::from(format!("Error deserializing constructor parameters: {}", e)))?;

    let params_value = JsValue::from_serde(&params).map_err(|e| {
        JsValue::from(format!(
            "Error converting constructor parameters to json object: {}",
            e
        ))
    })?;

    Ok(params_value)
}

#[wasm_bindgen(js_name = verifyVoucherSignature)]
pub fn verify_voucher_signature(
    voucher_base64: String,
    address_signer: String,
) -> Result<bool, JsValue> {
    set_panic_hook();

    let result = filecoin_signer::verify_voucher_signature(voucher_base64, address_signer)
        .map_err(|e| JsValue::from(format!("Error verifying voucher signature: {}", e)))?;

    Ok(result)
}

#[wasm_bindgen(js_name = serializeVoucher)]
pub fn serialize_voucher(voucher_api: JsValue) -> Result<String, JsValue> {
    set_panic_hook();

    let voucher: SignedVoucherWrapper = voucher_api
        .into_serde()
        .map_err(|e| JsValue::from(format!("Error parsing parameters: {}", e)))?;

    let result = filecoin_signer::serialize_voucher(voucher)
        .map_err(|e| JsValue::from(format!("Couldn't serialize voucher: {}", e)))?;

    Ok(result)
}

#[wasm_bindgen(js_name = deserializeVoucher)]
pub fn deserialize_voucher(voucher_base64_string: String) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let voucher = filecoin_signer::deserialize_voucher(voucher_base64_string)
        .map_err(|e| JsValue::from(format!("Couldn't serialize voucher: {}", e)))?;

    let voucher_api = JsValue::from_serde(&voucher).map_err(|e| {
        JsValue::from(format!(
            "Error converting constructor parameters to json object: {}",
            e
        ))
    })?;

    Ok(voucher_api)
}

#[wasm_bindgen(js_name = computeProposalHash)]
pub fn compute_proposal_hash(proposal_data_api: JsValue) -> Result<String, JsValue> {
    set_panic_hook();

    let proposal_data: ProposalHashDataAPI = proposal_data_api
        .into_serde()
        .map_err(|e| JsValue::from(format!("Error parsing parameters: {}", e)))?;

    let result = filecoin_signer::compute_proposal_hash(proposal_data)
        .map_err(|e| JsValue::from(format!("Fail to compute proposal hash: {}", e)))?;

    Ok(result)
}

#[wasm_bindgen(js_name = getCid)]
pub fn get_cid(message: JsValue) -> Result<String, JsValue> {
    set_panic_hook();

    let message_api: MessageTxAPI = message
        .into_serde()
        .map_err(|e| JsValue::from(format!("Error parsing parameters: {}", e)))?;

    let result = filecoin_signer::get_cid(message_api)
        .map_err(|e| JsValue::from(format!("Error getting the cid: {}", e)))?;

    Ok(result)
}
