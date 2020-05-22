use filecoin_signer_ledger;
use filecoin_signer::api::{SignatureAPI, SignedMessageAPI, UnsignedMessageAPI};
use filecoin_signer::utils::get_digest;
use js_sys::Promise;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use filecoin_signer_ledger::{APDUTransport, TransportWrapperTrait};

use bip44::BIP44Path;

use crate::utils::{address_to_object, bytes_to_buffer, signature_to_object, Buffer};

macro_rules! ok_or_ret_promise {
    ($rslt:expr, $err_msg:literal) => {
        if let Ok(r) = $rslt {
            r
        } else {
            return Promise::reject(&js_sys::Error::new($err_msg));
        }
    };
}

// lifted from the `console_log` example
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

/// FilecoinApp Error message
#[derive(Deserialize, Serialize)]
pub struct Error {
    /// Message return code
    pub return_code: u16,
    /// Error message
    pub error_message: String,
}

#[wasm_bindgen(module = "/transportWrapper.js")]
extern "C" {
    pub type TransportWrapper;

    #[wasm_bindgen(method)]
    pub fn exchange(this: &TransportWrapper, apdu_command: Buffer) -> Promise;
}

impl TransportWrapperTrait for TransportWrapper {
    fn exchange_apdu(&self, apdu_command: &[u8]) -> js_sys::Promise {
        self.exchange(bytes_to_buffer(apdu_command))
    }
}

#[wasm_bindgen(js_name = getVersion)]
pub async fn get_version(transport_wrapper: TransportWrapper) -> Promise {
    let tmp = Box::new(transport_wrapper);
    let apdu_transport = APDUTransport {
        transport_wrapper: tmp,
    };

    let app = filecoin_signer_ledger::app::FilecoinApp::new(apdu_transport);
    let v_result = app.get_version().await;

    // FIXME: Do this automatically to simplify this code
    match v_result {
        Ok(v) => Promise::resolve(&ok_or_ret_promise!(
            JsValue::from_serde(&v),
            "Error converting error message to javascript value."
        )),
        Err(err) => {
            let error = Error {
                return_code: 0x6f00,
                error_message: err.to_string(),
            };
            Promise::reject(&ok_or_ret_promise!(
                JsValue::from_serde(&error),
                "Error converting error message to javascript value."
            ))
        }
    }
}

#[wasm_bindgen(js_name = keyRetrieveFromDevice)]
pub async fn key_retrieve_from_device(
    path: String,
    transport_wrapper: TransportWrapper,
) -> Promise {
    let tmp = Box::new(transport_wrapper);
    let apdu_transport = APDUTransport {
        transport_wrapper: tmp,
    };

    let app = filecoin_signer_ledger::app::FilecoinApp::new(apdu_transport);

    // FIXME: reconcile BIP44Path different implementation
    let bip44_path = ok_or_ret_promise!(BIP44Path::from_string(&path), "Invalid BIP44 Path");

    let a_result = app.get_address(&bip44_path, false).await;

    match a_result {
        Ok(a) => {
            let address_object = address_to_object(&a);

            Promise::resolve(&address_object)
        }
        Err(err) => {
            let error = Error {
                return_code: 0x6f00,
                error_message: err.to_string(),
            };
            Promise::reject(&ok_or_ret_promise!(
                JsValue::from_serde(&error),
                "Error converting error message to javascript value."
            ))
        }
    }
}

#[wasm_bindgen(js_name = showKeyOnDevice)]
pub async fn show_key_on_device(path: String, transport_wrapper: TransportWrapper) -> Promise {
    let tmp = Box::new(transport_wrapper);
    let apdu_transport = APDUTransport {
        transport_wrapper: tmp,
    };

    let app = filecoin_signer_ledger::app::FilecoinApp::new(apdu_transport);

    let bip44_path = ok_or_ret_promise!(BIP44Path::from_string(&path), "Invalid BIP44 Path");

    let a_result = app.get_address(&bip44_path, true).await;

    match a_result {
        Ok(a) => {
            let address_object = address_to_object(&a);

            Promise::resolve(&address_object)
        }
        Err(err) => {
            let error = Error {
                return_code: 0x6f00,
                error_message: err.to_string(),
            };
            Promise::reject(&ok_or_ret_promise!(
                JsValue::from_serde(&error),
                "Error converting error message to javascript value."
            ))
        }
    }
}

#[wasm_bindgen(js_name = transactionSignRawWithDevice)]
pub async fn transaction_sign_raw_with_device(
    message: Vec<u8>,
    path: String,
    transport_wrapper: TransportWrapper,
) -> Promise {
    let tmp = Box::new(transport_wrapper);
    let apdu_transport = APDUTransport {
        transport_wrapper: tmp,
    };

    let app = filecoin_signer_ledger::app::FilecoinApp::new(apdu_transport);

    let bip44_path = ok_or_ret_promise!(BIP44Path::from_string(&path), "Invalid BIP44 Path");

    let s_result = app.sign(&bip44_path, &message).await;

    match s_result {
        Ok(s) => {
            let signature_object = signature_to_object(&s);

            Promise::resolve(&signature_object)
        }
        Err(err) => {
            let error = Error {
                return_code: 0x6f00,
                error_message: err.to_string(),
            };
            Promise::reject(&ok_or_ret_promise!(
                JsValue::from_serde(&error),
                "Error converting error message to javascript value."
            ))
        }
    }
}

#[wasm_bindgen(js_name = transactionSignWithDevice)]
pub async fn transaction_sign_with_device(
    unsigned_tx_js: JsValue,
    path: String,
    transport_wrapper: TransportWrapper,
) -> Promise {
    let tmp = Box::new(transport_wrapper);
    let apdu_transport = APDUTransport {
        transport_wrapper: tmp,
    };

    let unsigned_message : UnsignedMessageAPI = unsigned_tx_js
        .into_serde()
        .map_err(|e| {
            Promise::reject(&JsValue::from(format!("Error parsing parameters: {}", e)))
        }).unwrap();

    let cbor_message = filecoin_signer::transaction_serialize(&unsigned_message)
        .map_err(|e| {
            Promise::reject(&JsValue::from(format!("Error serializing transaction: {}", e)))
        }).unwrap();

    let message = get_digest(cbor_message.as_ref())
        .map_err(|e| {
            Promise::reject(&JsValue::from(format!("Error preparing transaction for signing: {}", e)))
        }).unwrap();

    let app = filecoin_signer_ledger::app::FilecoinApp::new(apdu_transport);

    let bip44_path = ok_or_ret_promise!(BIP44Path::from_string(&path), "Invalid BIP44 Path");

    let s_result = app.sign(&bip44_path, &message).await;

    match s_result {
        Ok(s) => {
            let signed_message = SignedMessageAPI {
                message: unsigned_message,
                signature: SignatureAPI {
                    sig_type: filecoin_signer::api::SigTypes::SigTypeSecp256k1 as u8,
                    data: s.sig.serialize().to_vec(),
                }
            };

            Promise::resolve(&ok_or_ret_promise!(
                JsValue::from_serde(&signed_message),
                "Error converting error message to javascript value."
            ))
        }
        Err(err) => {
            let error = Error {
                return_code: 0x6f00,
                error_message: err.to_string(),
            };
            Promise::reject(&ok_or_ret_promise!(
                JsValue::from_serde(&error),
                "Error converting error message to javascript value."
            ))
        }
    }
}

#[wasm_bindgen(js_name = appInfo)]
pub async fn app_info(transport_wrapper: TransportWrapper) -> Promise {
    let tmp = Box::new(transport_wrapper);
    let apdu_transport = APDUTransport {
        transport_wrapper: tmp,
    };

    let app = filecoin_signer_ledger::app::FilecoinApp::new(apdu_transport);

    let i_result = app.get_app_info().await;

    match i_result {
        Ok(i) => Promise::resolve(&ok_or_ret_promise!(
            JsValue::from_serde(&i),
            "Error converting error message to javascript value."
        )),
        Err(err) => {
            let error = Error {
                return_code: 0x6f00,
                error_message: err.to_string(),
            };
            Promise::reject(&ok_or_ret_promise!(
                JsValue::from_serde(&error),
                "Error converting error message to javascript value."
            ))
        }
    }
}

#[wasm_bindgen(js_name = deviceInfo)]
pub async fn device_info(transport_wrapper: TransportWrapper) -> Promise {
    let tmp = Box::new(transport_wrapper);
    let apdu_transport = APDUTransport {
        transport_wrapper: tmp,
    };

    let app = filecoin_signer_ledger::app::FilecoinApp::new(apdu_transport);

    let d_result = app.get_device_info().await;

    match d_result {
        Ok(d) => Promise::resolve(&ok_or_ret_promise!(
            JsValue::from_serde(&d),
            "Error converting error message to javascript value."
        )),
        Err(err) => {
            let error = Error {
                return_code: 0x6f00,
                error_message: err.to_string(),
            };
            Promise::reject(&ok_or_ret_promise!(
                JsValue::from_serde(&error),
                "Error converting error message to javascript value."
            ))
        }
    }
}
