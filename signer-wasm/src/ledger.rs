use filecoin_signer_ledger;
use js_sys::Promise;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use filecoin_signer_ledger::{APDUTransport, TransportWrapperTrait};

use bip44::BIP44Path;

use crate::utils::{address_to_object, bytes_to_buffer, signature_to_object, Buffer};

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
        Ok(v) => Promise::resolve(&JsValue::from_serde(&v).unwrap()),
        Err(err) => {
            let error = Error {
                return_code: 0x6f00,
                error_message: err.to_string(),
            };

            // FIXME: handle the error
            Promise::reject(&JsValue::from_serde(&error).unwrap())
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
    let bip44_path = BIP44Path::from_string(&path)
        .map_err(|_e| Promise::reject(&JsValue::from_str("Invalid BIP44 Path")))
        .unwrap();

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

            // FIXME: handle the error
            Promise::reject(&JsValue::from_serde(&error).unwrap())
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

    let bip44_path = BIP44Path::from_string(&path)
        .map_err(|_e| Promise::reject(&js_sys::Error::new("Invalid BIP44 Path")))
        .unwrap();

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

            // FIXME: handle the error
            Promise::reject(&JsValue::from_serde(&error).unwrap())
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

    let bip44_path = BIP44Path::from_string(&path)
        .map_err(|_e| Promise::reject(&js_sys::Error::new("Invalid BIP44 Path")))
        .unwrap();

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

            // FIXME: handle the error
            Promise::reject(&JsValue::from_serde(&error).unwrap())
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
        Ok(i) => {
            let answer = JsValue::from_serde(&i)
                .map_err(|_e| Promise::reject(&js_sys::Error::new("Error converting answer message to javascript value.")))
                .unwrap();
            Promise::resolve(&answer)
        }
        Err(err) => {
            let error = Error {
                return_code: 0x6f00,
                error_message: err.to_string(),
            };

            let error_answer = JsValue::from_serde(&error)
                .map_err(|_e| Promise::reject(&js_sys::Error::new("Error converting error message to javascript value.")))
                .unwrap();

            Promise::reject(&error_answer)
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
        Ok(d) => {
            let answer = JsValue::from_serde(&d)
                .map_err(|_e| Promise::reject(&js_sys::Error::new("Error converting answer message to javascript value.")))
                .unwrap();

            Promise::resolve(&answer)
        }
        Err(err) => {
            let error = Error {
                return_code: 0x6f00,
                error_message: err.to_string(),
            };

            let error_answer = JsValue::from_serde(&error)
                .map_err(|_e| Promise::reject(&js_sys::Error::new("Error converting error message to javascript value.")))
                .unwrap();

            Promise::reject(&error_answer)
        }
    }
}
