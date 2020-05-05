use wasm_bindgen::prelude::*;
use js_sys::Promise;
use ledger_filecoin;
use ledger_filecoin::{Transport, TransportJS};
use serde::{Deserialize, Serialize};
use secp256k1::util::COMPRESSED_PUBLIC_KEY_SIZE;

use filecoin_signer::bip44::Bip44Path;
use ledger_filecoin::BIP44Path;

// lifted from the `console_log` example
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

/// FilecoinApp App Version
#[derive(Deserialize, Serialize)]
pub struct Version {
    /// Are we in test mode ?
    pub test_mode: bool,
    /// Version Major
    pub major: u8,
    /// Version Minor
    pub minor: u8,
    /// Version Patch
    pub patch: u8,
}

/// FilecoinApp App Version
#[derive(Deserialize, Serialize)]
pub struct Error {
    /// Message return code
    pub return_code: u16,
    /// Error message
    pub error_message: String,
}

/// Address
#[derive(Deserialize, Serialize)]
pub struct Address {
    /// Public Key
    pub public_key: Vec<u8>,

    /// Address byte format
    pub addr_byte: Vec<u8>,

    /// Address string format
    pub addr_string: String,
}

/// Signature
#[derive(Deserialize, Serialize)]
pub struct Signature {
    /// Compact signature format
    pub signature_compact: Vec<u8>,
    /// DER signature format
    pub signature_der: Vec<u8>,
}

/*

Issue regarding lifetime and async!
https://github.com/rustwasm/wasm-bindgen/pull/1754

#[wasm_bindgen]
pub struct FilecoinApp {
    app: ledger_filecoin::FilecoinApp,
}

#[wasm_bindgen]
impl FilecoinApp {
    pub fn new(transport_js: TransportJS) -> FilecoinApp {
        let transport_wrapper = Transport { transportjs: transport_js };
        let app = ledger_filecoin::FilecoinApp::connect(transport_wrapper).unwrap();

        return FilecoinApp { app }
    }

    pub fn version(&self) -> Promise {
        let future = self.app.version();

        future_to_promise(async {
            let v_result = future.await;

            match v_result {
                Ok(v) => {
                    let version = Version {
                        test_mode: v.mode != 0x00,
                        major: v.major,
                        minor: v.minor,
                        patch: v.patch
                    };

                    // FIXME: handle the error
                    Ok(JsValue::from_serde(&version).unwrap())
                }
                Err(_err) => {
                    let error = Error {
                        return_code: 0x6f00,
                        error_message: "Unknown error".to_string(),
                    };

                    // FIXME: handle the error
                    Err(JsValue::from_serde(&error).unwrap())
                }
            }
        })
    }
}*/


#[wasm_bindgen]
pub async fn get_version(transport_js: TransportJS) -> Promise {

    // We are connecting every call but it is not such a big deal...
    // However having a class that can hold the transport would be best
    let transport_wrapper = Transport { transportjs: transport_js };

    // FIXME: handle the error
    let app = ledger_filecoin::FilecoinApp::connect(transport_wrapper).unwrap();

    let v_result = app.version().await;

    match v_result {
        Ok(v) => {
            let version = Version {
                test_mode: v.mode != 0x00,
                major: v.major,
                minor: v.minor,
                patch: v.patch
            };

            // FIXME: handle the error
            Promise::resolve(&JsValue::from_serde(&version).unwrap())
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

#[wasm_bindgen]
pub async fn key_retrieve_from_device(path: String, transport_js: TransportJS) -> Promise {
    let transport_wrapper = Transport { transportjs: transport_js };

    // FIXME: handle the error
    let app = ledger_filecoin::FilecoinApp::connect(transport_wrapper).unwrap();

    // FIXME: reconcile BIP44Path different implementation
    let bip44Path = Bip44Path::from_string(&path).unwrap();

    let bip44Path_bis = BIP44Path {
        purpose: bip44Path.0[0],
        coin: bip44Path.0[1],
        account: bip44Path.0[2],
        change: bip44Path.0[3],
        index: bip44Path.0[4],
    };

    let a_result = app.address(&bip44Path_bis, false).await;

    match a_result {
        Ok(a) => {
            let address = Address {
                public_key: a.public_key.serialize_compressed().to_vec(),
                addr_byte: a.addr_byte.to_vec(),
                addr_string: a.addr_string,
            };
            // FIXME: handle the error
            Promise::resolve(&JsValue::from_serde(&address).unwrap())
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

#[wasm_bindgen]
pub async fn show_key_on_device(path: String, transport_js: TransportJS) -> Promise {
    let transport_wrapper = Transport { transportjs: transport_js };

    // FIXME: handle the error
    let app = ledger_filecoin::FilecoinApp::connect(transport_wrapper).unwrap();

    // FIXME: reconcile BIP44Path different implementation
    let bip44Path = Bip44Path::from_string(&path).unwrap();

    let bip44Path_bis = BIP44Path {
        purpose: bip44Path.0[0],
        coin: bip44Path.0[1],
        account: bip44Path.0[2],
        change: bip44Path.0[3],
        index: bip44Path.0[4],
    };

    let a_result = app.address(&bip44Path_bis, true).await;

    match a_result {
        Ok(a) => {
            let address = Address {
                public_key: a.public_key.serialize_compressed().to_vec(),
                addr_byte: a.addr_byte.to_vec(),
                addr_string: a.addr_string,
            };
            // FIXME: handle the error
            Promise::resolve(&JsValue::from_serde(&address).unwrap())
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

#[wasm_bindgen]
pub async fn transaction_sign_raw_with_device(message: Vec<u8>, path: String, transport_js: TransportJS) -> Promise {
    let transport_wrapper = Transport { transportjs: transport_js };

    // FIXME: handle the error
    let app = ledger_filecoin::FilecoinApp::connect(transport_wrapper).unwrap();

    // FIXME: reconcile BIP44Path different implementation
    let bip44Path = Bip44Path::from_string(&path).unwrap();

    let bip44Path_bis = BIP44Path {
        purpose: bip44Path.0[0],
        coin: bip44Path.0[1],
        account: bip44Path.0[2],
        change: bip44Path.0[3],
        index: bip44Path.0[4],
    };

    let s_result = app.sign(&bip44Path_bis, &message).await;

    match s_result {
        Ok(s) => {
            let mut der_signature = Vec::new();

            der_signature.extend_from_slice(&s.r);
            der_signature.extend_from_slice(&s.s);
            der_signature.push(s.v);

            let signature = Signature {
                signature_compact: s.sig.serialize().to_vec(),
                signature_der: der_signature,
            };

            // FIXME: handle the error
            Promise::resolve(&JsValue::from_serde(&signature).unwrap())
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

#[wasm_bindgen]
pub async fn app_info(transport_js: TransportJS) -> Promise {
    let transport_wrapper = Transport { transportjs: transport_js };

    // FIXME: handle the error
    let app = ledger_filecoin::FilecoinApp::connect(transport_wrapper).unwrap();

    todo!()
    //let i_result = app.info().await;
}

#[wasm_bindgen]
pub async fn device_info(transport_js: TransportJS) -> Promise {
    let transport_wrapper = Transport { transportjs: transport_js };

    // FIXME: handle the error
    let app = ledger_filecoin::FilecoinApp::connect(transport_wrapper).unwrap();

    todo!()
    //let d_result = app.device().await;

}
