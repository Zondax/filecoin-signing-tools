use filecoin_signer::api::{SignatureAPI, SignedMessageAPI, UnsignedMessageAPI};
use filecoin_signer::utils::get_digest;
use filecoin_signer_ledger;
use js_sys::Promise;
use wasm_bindgen::prelude::*;

use filecoin_signer_ledger::{APDUTransport, TransportWrapperTrait};

use bip44::BIP44Path;

use crate::ledger_errors::ledger_error_to_javascript_error;
use crate::utils::{address_to_object, bytes_to_buffer, signature_to_object, Buffer};

const INVALID_BIP44: &str = "Invalid BIP44 Path";

macro_rules! ok_or_reject {
    ($rslt:expr) => {
        match $rslt {
            Err(_) => return Promise::reject(&js_sys::Error::new("Error")),
            Ok(o) => o,
        }
    };
    ($rslt:expr, $err_msg:expr) => {
        match $rslt {
            Err(e) => {
                return Promise::reject(&js_sys::Error::new(&{
                    let mut s = String::with_capacity(32);
                    s.push_str($err_msg);
                    s.push_str(": ");
                    s.push_str(&e.to_string());
                    s
                }))
            }
            Ok(o) => o,
        }
    };
}

macro_rules! js_or_reject {
    ($from_serde:expr) => {
        ok_or_reject!(
            JsValue::from_serde($from_serde),
            "Error converting message to javascript value"
        )
    };
}

// lifted from the `console_log` example
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
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

    match v_result {
        Ok(v) => {
            let js_value = js_or_reject!(&v);
            Promise::resolve(&js_value)
        }
        Err(err) => {
            let js_value = js_or_reject!(&ledger_error_to_javascript_error(err));
            Promise::reject(&js_value)
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
    let bip44_path = ok_or_reject!(BIP44Path::from_string(&path), INVALID_BIP44);

    match app.get_address(&bip44_path, false).await {
        Ok(address) => {
            let obj_rslt = address_to_object(&address);
            let obj = ok_or_reject!(&obj_rslt);
            Promise::resolve(&obj)
        }
        Err(err) => {
            let js_value = js_or_reject!(&ledger_error_to_javascript_error(err));
            Promise::reject(&js_value)
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
    let bip44_path = ok_or_reject!(BIP44Path::from_string(&path), INVALID_BIP44);

    match app.get_address(&bip44_path, true).await {
        Ok(address) => {
            let obj_rslt = address_to_object(&address);
            let obj = ok_or_reject!(&obj_rslt);
            Promise::resolve(&obj)
        }
        Err(err) => {
            let js_value = js_or_reject!(&ledger_error_to_javascript_error(err));
            Promise::reject(&js_value)
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
    let bip44_path = ok_or_reject!(BIP44Path::from_string(&path), INVALID_BIP44);

    match app.sign(&bip44_path, &message).await {
        Ok(sig) => {
            let obj_rslt = signature_to_object(&sig);
            let obj = ok_or_reject!(&obj_rslt);
            Promise::resolve(&obj)
        }
        Err(err) => {
            let js_value = js_or_reject!(&ledger_error_to_javascript_error(err));
            Promise::reject(&js_value)
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

    let unsigned_message: UnsignedMessageAPI =
        ok_or_reject!(unsigned_tx_js.into_serde(), "Error parsing parameters");

    let cbor_message = ok_or_reject!(
        filecoin_signer::transaction_serialize(&unsigned_message),
        "Error serializing transaction"
    );

    let message = ok_or_reject!(
        get_digest(cbor_message.as_ref()),
        "Error preparing transaction for signing"
    );

    let app = filecoin_signer_ledger::app::FilecoinApp::new(apdu_transport);

    let bip44_path = ok_or_reject!(BIP44Path::from_string(&path), INVALID_BIP44);

    match app.sign(&bip44_path, &message).await {
        Ok(s) => Promise::resolve(&js_or_reject!(&SignedMessageAPI {
            message: unsigned_message,
            signature: SignatureAPI {
                sig_type: filecoin_signer::api::SigTypes::SigTypeSecp256k1 as u8,
                data: s.sig.serialize().to_vec(),
            },
        })),
        Err(err) => {
            let js_value = js_or_reject!(&ledger_error_to_javascript_error(err));
            Promise::reject(&js_value)
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

    match app.get_app_info().await {
        Ok(i) => {
            let js_value = js_or_reject!(&i);
            Promise::resolve(&js_value)
        }
        Err(err) => {
            let js_value = js_or_reject!(&ledger_error_to_javascript_error(err));
            Promise::reject(&js_value)
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

    match app.get_device_info().await {
        Ok(d) => {
            let js_value = js_or_reject!(&d);
            Promise::resolve(&js_value)
        }
        Err(err) => {
            let js_value = js_or_reject!(&ledger_error_to_javascript_error(err));
            Promise::reject(&js_value)
        }
    }
}
