use filecoin_signer::api::SignedMessageAPI;
use serde_json::json;
use wasm_bindgen::prelude::*;

// This defines the Node.js Buffer type
#[wasm_bindgen]
extern "C" {
    pub type Buffer;

    #[wasm_bindgen(constructor)]
    fn from(buffer_array: &[u8]) -> Buffer;
}

pub fn convert_to_lotus_signed_message(
    signed_message: SignedMessageAPI,
) -> Result<String, JsValue> {
    let signed_message_lotus = json!({
        "Message": {
            "To": signed_message.message.to,
            "From": signed_message.message.from,
            "Nonce": signed_message.message.nonce,
            "Value": signed_message.message.value,
            "GasLimit":signed_message.message.gas_limit,
            "GasPremium":signed_message.message.gas_premium,
            "GasFeeCap":signed_message.message.gas_fee_cap,
            "Method": signed_message.message.method,
            "Params": signed_message.message.params,
        },
        "Signature": {
            "Type": signed_message.signature.sig_type,
            "Data": base64::encode(signed_message.signature.data),
        }
    });

    Ok(signed_message_lotus.to_string())
}
