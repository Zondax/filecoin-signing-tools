use filecoin_signer_ledger;
use js_sys::Promise;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use filecoin_signer_ledger::{ApduTransport, TransportWrapperTrait};

use bip44::BIP44Path;

// lifted from the `console_log` example
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

/// FilecoinApp App Version
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
    pub fn exchange(this: &TransportWrapper, apdu_command: &[u8]) -> Promise;
}

impl TransportWrapperTrait for TransportWrapper {
    fn exchange_apdu(&self, apdu_command: &[u8]) -> js_sys::Promise {
        self.exchange(apdu_command)
    }
}

#[wasm_bindgen]
pub async fn get_version(transport_wrapper: TransportWrapper) -> Promise {
    let tmp = Box::new(transport_wrapper);
    let apdu_transport = ApduTransport {
        transport_wrapper: tmp,
    };

    // FIXME: handle the error
    let app = filecoin_signer_ledger::app::FilecoinApp::connect(apdu_transport).unwrap();
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

 #[wasm_bindgen]
 pub async fn key_retrieve_from_device(
     path: String,
     transport_wrapper: TransportWrapper,
 ) -> Promise {
     let tmp = Box::new(transport_wrapper);
     let apdu_transport = ApduTransport {
         transport_wrapper: tmp,
     };

     // FIXME: handle the error
     let app = filecoin_signer_ledger::app::FilecoinApp::connect(apdu_transport).unwrap();

     log("Connected");

     // FIXME: reconcile BIP44Path different implementation
     let bip44_path = BIP44Path::from_string(&path).unwrap();

     log("We have the bip44");

     let a_result = app.get_address(&bip44_path, false).await;

     match a_result {
         Ok(a) => {
             log("We have address");
             // FIXME: handle the error
             Promise::resolve(&JsValue::from_serde(&a).unwrap())
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


// #[wasm_bindgen]
// pub async fn show_key_on_device(path: String, transport_wrapper: TransportWrapper) -> Promise {
//     let apdu_transport = ApduTransport { transport_wrapper };
//
//     // FIXME: handle the error
//     let app = ledger_filecoin::FilecoinApp::connect(apdu_transport).unwrap();
//
//     // FIXME: reconcile BIP44Path different implementation
//     let bip44Path = BIP44Path::from_string(&path).unwrap();
//
//     let bip44Path_bis = BIP44Path {
//         purpose: bip44Path.0[0],
//         coin: bip44Path.0[1],
//         account: bip44Path.0[2],
//         change: bip44Path.0[3],
//         index: bip44Path.0[4],
//     };
//
//     let a_result = app.get_address(&bip44Path_bis, true).await;
//
//     match a_result {
//         Ok(a) => {
//             let address = Address {
//                 public_key: a.public_key.serialize_compressed().to_vec(),
//                 addr_byte: a.addr_byte.to_vec(),
//                 addr_string: a.addr_string,
//             };
//             // FIXME: handle the error
//             Promise::resolve(&JsValue::from_serde(&address).unwrap())
//         }
//         Err(err) => {
//             let error = Error {
//                 return_code: 0x6f00,
//                 error_message: err.to_string(),
//             };
//
//             // FIXME: handle the error
//             Promise::reject(&JsValue::from_serde(&error).unwrap())
//         }
//     }
// }
//
// #[wasm_bindgen]
// pub async fn transaction_sign_raw_with_device(
//     message: Vec<u8>,
//     path: String,
//     transport_wrapper: TransportWrapper,
// ) -> Promise {
//     let apdu_transport = ApduTransport { transport_wrapper };
//
//     // FIXME: handle the error
//     let app = ledger_filecoin::FilecoinApp::connect(apdu_transport).unwrap();
//
//     // FIXME: reconcile BIP44Path different implementation
//     let bip44Path = BIP44Path::from_string(&path).unwrap();
//
//     let bip44Path_bis = BIP44Path {
//         purpose: bip44Path.0[0],
//         coin: bip44Path.0[1],
//         account: bip44Path.0[2],
//         change: bip44Path.0[3],
//         index: bip44Path.0[4],
//     };
//
//     let s_result = app.sign(&bip44Path_bis, &message).await;
//
//     match s_result {
//         Ok(s) => {
//             let mut der_signature = Vec::new();
//
//             der_signature.extend_from_slice(&s.r);
//             der_signature.extend_from_slice(&s.s);
//             der_signature.push(s.v);
//
//             let signature = Signature {
//                 signature_compact: s.sig.serialize().to_vec(),
//                 signature_der: der_signature,
//             };
//
//             // FIXME: handle the error
//             Promise::resolve(&JsValue::from_serde(&signature).unwrap())
//         }
//         Err(err) => {
//             let error = Error {
//                 return_code: 0x6f00,
//                 error_message: err.to_string(),
//             };
//
//             // FIXME: handle the error
//             Promise::reject(&JsValue::from_serde(&error).unwrap())
//         }
//     }
// }
//
// #[wasm_bindgen]
// pub async fn app_info(transport_wrapper: TransportWrapper) -> Promise {
//     let apdu_transport = ApduTransport { transport_wrapper };
//
//     // FIXME: handle the error
//     let app = ledger_filecoin::FilecoinApp::connect(apdu_transport).unwrap();
//
//     todo!()
//     //let i_result = app.info().await;
// }
//
// #[wasm_bindgen]
// pub async fn device_info(transport_wrapper: TransportWrapper) -> Promise {
//     let apdu_transport = ApduTransport { transport_wrapper };
//
//     // FIXME: handle the error
//     let app = ledger_filecoin::FilecoinApp::connect(apdu_transport).unwrap();
//
//     todo!()
//     //let d_result = app.device().await;
// }
