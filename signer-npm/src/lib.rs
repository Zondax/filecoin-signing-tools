#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used,))]

use std::convert::TryFrom;

use wasm_bindgen::prelude::*;

use filecoin_signer::api::{MessageParams, MessageTxAPI, SignedMessageAPI, UnsignedMessageAPI};
use filecoin_signer::signature::Signature;
use filecoin_signer::{CborBuffer, PrivateKey};

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
        return Ok(PrivateKey::try_from(s).map_err(|e| JsValue::from(e.to_string()))?);
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

#[wasm_bindgen(js_name = keyRecoverBLS)]
pub fn key_recover_bls(private_key_js: JsValue, testnet: bool) -> Result<ExtendedKey, JsValue> {
    set_panic_hook();

    let private_key_bytes = extract_private_key(private_key_js)?;

    let key_address = filecoin_signer::key_recover_bls(&private_key_bytes, testnet)
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

    // TODO: Should be MessageTxAPI because it can be unsigned message or signed message
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

    let signed_message_lotus = utils::convert_to_lotus_signed_message(signed_message)?;

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
        "Message must be encoded as hexstring, base64 or a buffer",
    )?;

    filecoin_signer::verify_signature(&sig, &CborBuffer(message_bytes))
        .map_err(|e| JsValue::from_str(format!("Error verifying signature: {}", e).as_str()))
}

fn signer_value_to_string(address_value: JsValue) -> Result<String, JsValue> {
    let address = address_value.as_string();

    match address {
        Some(address) => Ok(address),
        None => Err(JsValue::from_str("Not able to parse address")),
    }
}

#[wasm_bindgen(js_name = createMultisigWithFee)]
#[allow(clippy::too_many_arguments)]
pub fn create_multisig_with_fee(
    sender_address: String,
    addresses: Vec<JsValue>,
    value: String,
    required: i32,
    nonce: u32,
    duration: String,
    start_epoch: String,
    gas_limit: String,
    gas_fee_cap: String,
    gas_premium: String,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let addresses_strings_tmp: Result<Vec<String>, _> =
        addresses.into_iter().map(signer_value_to_string).collect();

    let addresses_strings = match addresses_strings_tmp {
        Ok(addresses_strings) => addresses_strings,
        Err(_) => {
            return Err(JsValue::from_str("Error while parsing addresses"));
        }
    };

    let se = i64::from_str_radix(&start_epoch, 10)
        .map_err(|e| JsValue::from(format!("Error converting to i64: {}", e)))?;
    let d = i64::from_str_radix(&duration, 10)
        .map_err(|e| JsValue::from(format!("Error converting to i64: {}", e)))?;
    let gl = i64::from_str_radix(&gas_limit, 10)
        .map_err(|e| JsValue::from(format!("Error converting to i64: {}", e)))?;

    let multisig_transaction = filecoin_signer::create_multisig(
        sender_address,
        addresses_strings,
        value,
        required as i64,
        nonce as u64,
        d,
        se,
        gl,
        gas_fee_cap,
        gas_premium,
    )
    .map_err(|e| {
        JsValue::from_str(format!("Error creating multisig transaction: {}", e).as_str())
    })?;

    let multisig_transaction_js = JsValue::from_serde(&multisig_transaction)
        .map_err(|e| JsValue::from(format!("Error creating transaction: {}", e)))?;

    Ok(multisig_transaction_js)
}

#[wasm_bindgen(js_name = createMultisig)]
pub fn create_multisig(
    sender_address: String,
    addresses: Vec<JsValue>,
    value: String,
    required: i32,
    nonce: u32,
    duration: String,
    start_epoch: String,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let addresses_strings_tmp: Result<Vec<String>, _> =
        addresses.into_iter().map(signer_value_to_string).collect();

    let addresses_strings = match addresses_strings_tmp {
        Ok(addresses_strings) => addresses_strings,
        Err(_) => {
            return Err(JsValue::from_str("Error while parsing addresses"));
        }
    };

    let se = i64::from_str_radix(&start_epoch, 10)
        .map_err(|e| JsValue::from(format!("Error converting to i64: {}", e)))?;
    let d = i64::from_str_radix(&duration, 10)
        .map_err(|e| JsValue::from(format!("Error converting to i64: {}", e)))?;

    let multisig_transaction = filecoin_signer::create_multisig(
        sender_address,
        addresses_strings,
        value,
        required as i64,
        nonce as u64,
        d,
        se,
        0,
        "0".to_string(),
        "0".to_string(),
    )
    .map_err(|e| {
        JsValue::from_str(format!("Error creating multisig transaction: {}", e).as_str())
    })?;

    let multisig_transaction_js = JsValue::from_serde(&multisig_transaction)
        .map_err(|e| JsValue::from(format!("Error creating transaction: {}", e)))?;

    Ok(multisig_transaction_js)
}

#[wasm_bindgen(js_name = proposeMultisigWithFee)]
#[allow(clippy::too_many_arguments)]
pub fn propose_multisig_with_fee(
    multisig_address: String,
    to_address: String,
    from_address: String,
    amount: String,
    nonce: u32,
    gas_limit: String,
    gas_fee_cap: String,
    gas_premium: String,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let gl = i64::from_str_radix(&gas_limit, 10)
        .map_err(|e| JsValue::from(format!("Error converting to i64: {}", e)))?;

    let multisig_transaction = filecoin_signer::proposal_multisig_message(
        multisig_address,
        to_address,
        from_address,
        amount,
        nonce as u64,
        gl,
        gas_fee_cap,
        gas_premium,
    )
    .map_err(|e| {
        JsValue::from_str(format!("Error porposing multisig transaction: {}", e).as_str())
    })?;

    let multisig_transaction_js = JsValue::from_serde(&multisig_transaction)
        .map_err(|e| JsValue::from(format!("Error porposing transaction: {}", e)))?;

    Ok(multisig_transaction_js)
}

#[wasm_bindgen(js_name = proposeMultisig)]
pub fn propose_multisig(
    multisig_address: String,
    to_address: String,
    from_address: String,
    amount: String,
    nonce: u32,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let multisig_transaction = filecoin_signer::proposal_multisig_message(
        multisig_address,
        to_address,
        from_address,
        amount,
        nonce as u64,
        0,
        "0".to_string(),
        "0".to_string(),
    )
    .map_err(|e| {
        JsValue::from_str(format!("Error porposing multisig transaction: {}", e).as_str())
    })?;

    let multisig_transaction_js = JsValue::from_serde(&multisig_transaction)
        .map_err(|e| JsValue::from(format!("Error porposing transaction: {}", e)))?;

    Ok(multisig_transaction_js)
}

#[wasm_bindgen(js_name = approveMultisigWithFee)]
#[allow(clippy::too_many_arguments)]
pub fn approve_multisig_with_fee(
    multisig_address: String,
    message_id: i32,
    proposer_address: String,
    to_address: String,
    amount: String,
    from_address: String,
    nonce: u32,
    gas_limit: String,
    gas_fee_cap: String,
    gas_premium: String,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let gl = i64::from_str_radix(&gas_limit, 10)
        .map_err(|e| JsValue::from(format!("Error converting to i64: {}", e)))?;

    let multisig_transaction = filecoin_signer::approve_multisig_message(
        multisig_address,
        message_id as i64,
        proposer_address,
        to_address,
        amount,
        from_address,
        nonce as u64,
        gl,
        gas_fee_cap,
        gas_premium,
    )
    .map_err(|e| {
        JsValue::from_str(format!("Error approving multisig transaction: {}", e).as_str())
    })?;

    let multisig_transaction_js = JsValue::from_serde(&multisig_transaction)
        .map_err(|e| JsValue::from(format!("Error approving transaction: {}", e)))?;

    Ok(multisig_transaction_js)
}

#[wasm_bindgen(js_name = approveMultisig)]
pub fn approve_multisig(
    multisig_address: String,
    message_id: i32,
    proposer_address: String,
    to_address: String,
    amount: String,
    from_address: String,
    nonce: u32,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let multisig_transaction = filecoin_signer::approve_multisig_message(
        multisig_address,
        message_id as i64,
        proposer_address,
        to_address,
        amount,
        from_address,
        nonce as u64,
        0,
        "0".to_string(),
        "0".to_string(),
    )
    .map_err(|e| {
        JsValue::from_str(format!("Error approving multisig transaction: {}", e).as_str())
    })?;

    let multisig_transaction_js = JsValue::from_serde(&multisig_transaction)
        .map_err(|e| JsValue::from(format!("Error approving transaction: {}", e)))?;

    Ok(multisig_transaction_js)
}

#[wasm_bindgen(js_name = cancelMultisigWithFee)]
#[allow(clippy::too_many_arguments)]
pub fn cancel_multisig_with_fee(
    multisig_address: String,
    message_id: i32,
    proposer_address: String,
    to_address: String,
    amount: String,
    from_address: String,
    nonce: u32,
    gas_limit: String,
    gas_fee_cap: String,
    gas_premium: String,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let gl = i64::from_str_radix(&gas_limit, 10)
        .map_err(|e| JsValue::from(format!("Error converting to i64: {}", e)))?;

    let multisig_transaction = filecoin_signer::cancel_multisig_message(
        multisig_address,
        message_id as i64,
        proposer_address,
        to_address,
        amount,
        from_address,
        nonce as u64,
        gl,
        gas_fee_cap,
        gas_premium,
    )
    .map_err(|e| {
        JsValue::from_str(format!("Error canceling multisig transaction: {}", e).as_str())
    })?;

    let multisig_transaction_js = JsValue::from_serde(&multisig_transaction)
        .map_err(|e| JsValue::from(format!("Error canceling transaction: {}", e)))?;

    Ok(multisig_transaction_js)
}

#[wasm_bindgen(js_name = cancelMultisig)]
pub fn cancel_multisig(
    multisig_address: String,
    message_id: i32,
    proposer_address: String,
    to_address: String,
    amount: String,
    from_address: String,
    nonce: u32,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let multisig_transaction = filecoin_signer::cancel_multisig_message(
        multisig_address,
        message_id as i64,
        proposer_address,
        to_address,
        amount,
        from_address,
        nonce as u64,
        0,
        "0".to_string(),
        "0".to_string(),
    )
    .map_err(|e| {
        JsValue::from_str(format!("Error canceling multisig transaction: {}", e).as_str())
    })?;

    let multisig_transaction_js = JsValue::from_serde(&multisig_transaction)
        .map_err(|e| JsValue::from(format!("Error canceling transaction: {}", e)))?;

    Ok(multisig_transaction_js)
}

#[wasm_bindgen(js_name = createPymtChanWithFee)]
pub fn create_pymtchan_with_fee(
    from_address: String,
    to_address: String,
    amount: String,
    nonce: u32,
    gas_limit: String,
    gas_fee_cap: String,
    gas_premium: String,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let gl = i64::from_str_radix(&gas_limit, 10)
        .map_err(|e| JsValue::from(format!("Error converting to i64: {}", e)))?;

    let pch_transaction = filecoin_signer::create_pymtchan(
        from_address,
        to_address,
        amount,
        nonce as u64,
        gl,
        gas_fee_cap,
        gas_premium,
    )
    .map_err(|e| JsValue::from_str(format!("Error creating payment channel: {}", e).as_str()))?;

    let pch_transaction_js = JsValue::from_serde(&pch_transaction)
        .map_err(|e| JsValue::from(format!("Error creating transaction: {}", e)))?;

    Ok(pch_transaction_js)
}

#[wasm_bindgen(js_name = createPymtChan)]
pub fn create_pymtchan(
    from_address: String,
    to_address: String,
    amount: String,
    nonce: u32,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let pch_transaction = filecoin_signer::create_pymtchan(
        from_address,
        to_address,
        amount,
        nonce as u64,
        0,
        "0".to_string(),
        "0".to_string(),
    )
    .map_err(|e| JsValue::from_str(format!("Error creating payment channel: {}", e).as_str()))?;

    let pch_transaction_js = JsValue::from_serde(&pch_transaction)
        .map_err(|e| JsValue::from(format!("Error creating transaction: {}", e)))?;

    Ok(pch_transaction_js)
}

#[wasm_bindgen(js_name = settlePymtChanWithFee)]
pub fn settle_pymtchan_with_fee(
    pch_address: String,
    from_address: String,
    nonce: u32,
    gas_limit: String,
    gas_fee_cap: String,
    gas_premium: String,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let gl = i64::from_str_radix(&gas_limit, 10)
        .map_err(|e| JsValue::from(format!("Error converting to i64: {}", e)))?;

    let pch_transaction = filecoin_signer::settle_pymtchan(
        pch_address,
        from_address,
        nonce as u64,
        gl,
        gas_fee_cap,
        gas_premium,
    )
    .map_err(|e| JsValue::from_str(format!("Error collecting payment channel: {}", e).as_str()))?;

    let pch_transaction_js = JsValue::from_serde(&pch_transaction)
        .map_err(|e| JsValue::from(format!("Error creating transaction: {}", e)))?;

    Ok(pch_transaction_js)
}

#[wasm_bindgen(js_name = settlePymtChan)]
pub fn settle_pymtchan(
    pch_address: String,
    from_address: String,
    nonce: u32,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let pch_transaction = filecoin_signer::settle_pymtchan(
        pch_address,
        from_address,
        nonce as u64,
        0,
        "0".to_string(),
        "0".to_string(),
    )
    .map_err(|e| JsValue::from_str(format!("Error collecting payment channel: {}", e).as_str()))?;

    let pch_transaction_js = JsValue::from_serde(&pch_transaction)
        .map_err(|e| JsValue::from(format!("Error creating transaction: {}", e)))?;

    Ok(pch_transaction_js)
}

#[wasm_bindgen(js_name = collectPymtChanWithFee)]
pub fn collect_pymtchan_with_fee(
    pch_address: String,
    from_address: String,
    nonce: u32,
    gas_limit: String,
    gas_fee_cap: String,
    gas_premium: String,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let gl = i64::from_str_radix(&gas_limit, 10)
        .map_err(|e| JsValue::from(format!("Error converting to i64: {}", e)))?;

    let pch_transaction = filecoin_signer::collect_pymtchan(
        pch_address,
        from_address,
        nonce as u64,
        gl,
        gas_fee_cap,
        gas_premium,
    )
    .map_err(|e| JsValue::from_str(format!("Error collecting payment channel: {}", e).as_str()))?;

    let pch_transaction_js = JsValue::from_serde(&pch_transaction)
        .map_err(|e| JsValue::from(format!("Error creating transaction: {}", e)))?;

    Ok(pch_transaction_js)
}

#[wasm_bindgen(js_name = collectPymtChan)]
pub fn collect_pymtchan(
    pch_address: String,
    from_address: String,
    nonce: u32,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    let pch_transaction = filecoin_signer::collect_pymtchan(
        pch_address,
        from_address,
        nonce as u64,
        0,
        "0".to_string(),
        "0".to_string(),
    )
    .map_err(|e| JsValue::from_str(format!("Error collecting payment channel: {}", e).as_str()))?;

    let pch_transaction_js = JsValue::from_serde(&pch_transaction)
        .map_err(|e| JsValue::from(format!("Error creating transaction: {}", e)))?;

    Ok(pch_transaction_js)
}

#[wasm_bindgen(js_name = updatePymtChanWithFee)]
pub fn update_pymtchan_with_fee(
    pch_address: String,
    from_address: String,
    signed_voucher: String,
    nonce: u32,
    gas_limit: String,
    gas_fee_cap: String,
    gas_premium: String,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    // TODO: verify if `pch_address` is an actor address. Not needed but good improvement.

    let gl = i64::from_str_radix(&gas_limit, 10)
        .map_err(|e| JsValue::from(format!("Error converting to i64: {}", e)))?;

    let pch_transaction = filecoin_signer::update_pymtchan(
        pch_address,
        from_address,
        signed_voucher,
        nonce as u64,
        gl,
        gas_fee_cap,
        gas_premium,
    )
    .map_err(|e| JsValue::from_str(format!("Error collecting payment channel: {}", e).as_str()))?;

    let pch_transaction_js = JsValue::from_serde(&pch_transaction)
        .map_err(|e| JsValue::from(format!("Error creating transaction: {}", e)))?;

    Ok(pch_transaction_js)
}

#[wasm_bindgen(js_name = updatePymtChan)]
pub fn update_pymtchan(
    pch_address: String,
    from_address: String,
    signed_voucher: String,
    nonce: u32,
) -> Result<JsValue, JsValue> {
    set_panic_hook();

    // TODO: verify if `pch_address` is an actor address. Not needed but good improvement.

    let pch_transaction = filecoin_signer::update_pymtchan(
        pch_address,
        from_address,
        signed_voucher,
        nonce as u64,
        0,
        "0".to_string(),
        "0".to_string(),
    )
    .map_err(|e| JsValue::from_str(format!("Error collecting payment channel: {}", e).as_str()))?;

    let pch_transaction_js = JsValue::from_serde(&pch_transaction)
        .map_err(|e| JsValue::from(format!("Error creating transaction: {}", e)))?;

    Ok(pch_transaction_js)
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

    let tlmin = i64::from_str_radix(&time_lock_min, 10)
        .map_err(|e| JsValue::from(format!("Error converting to i64: {}", e)))?;
    let tlmax = i64::from_str_radix(&time_lock_max, 10)
        .map_err(|e| JsValue::from(format!("Error converting to i64: {}", e)))?;

    let l = u64::from_str_radix(&lane, 10)
        .map_err(|e| JsValue::from(format!("Error converting to i64: {}", e)))?;

    let msh = i64::from_str_radix(&min_settle_height, 10)
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

    Ok(params_cbor.as_ref().to_vec())
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
