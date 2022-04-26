//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

use filecoin_signer::api::MessageTxAPI;
use serde_json::json;
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn key_generate_mnemonic() {
    let answer = filecoin_signer_wasm::mnemonic_generate().expect("unexpected error");
    let word_count = answer.split_whitespace().count();
    println!("{:?}", answer);
    assert_eq!(word_count, 24);
}

#[wasm_bindgen_test]
fn key_derive() {
    let mnemonic =
        "equip will roof matter pink blind book anxiety banner elbow sun young".to_string();

    let path = "m/44'/461'/0/0/1".to_string();

    let answer =
        filecoin_signer_wasm::key_derive(mnemonic, path, "".to_string(), Some("en".to_string()))
            .expect("unexpected error");

    assert_eq!(
        answer.public_hexstring(),
        "04fc016f3d88dc7070cdd95b5754d32fd5290f850b7c2208fca0f715d35861de1841d9a342a487692a63810a6c906b443a18aa804d9d508d69facc5b06789a01b4"
    );

    assert_eq!(
        answer.private_hexstring(),
        "80c56e752ffdd06e3e0d9516e662e7ba883982404045a2c2d4cbe7c87e6c66fe"
    );

    assert_eq!(
        answer.address(),
        "f1rovwtiuo5ncslpmpjftzu5akswbgsgighjazxoi"
    )
}

#[wasm_bindgen_test]
fn sign() {
    let example_unsigned_message = JsValue::from_serde(&json!(
    {
        "To": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
        "From": "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
        "Nonce": 1,
        "Value": "100000",
        "GasLimit": 25000,
        "GasFeeCap": "1",
        "GasPremium": "1",
        "Method": 0,
        "Params": ""
    }))
    .unwrap();

    let private_key: &str = r#"8VcW07ADswS4BV2cxi5rnIadVsyTDDhY1NfDH19T8Uo="#;

    let answer = filecoin_signer_wasm::transaction_sign(
        example_unsigned_message,
        JsValue::from_str(private_key),
    )
    .expect("unexpected error");

    let expected_answer = JsValue::from_serde(&json!(
    {
        "Message" : {
        "To": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
        "From": "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
        "Nonce": 1,
        "Value": "100000",
        "GasLimit": 25000,
        "GasFeeCap": "1",
        "GasPremium": "1",
        "Method": 0,
        "Params": ""
        },
        "Signature" : {
        "Type": 1,
        "Data":"nFuTI7MxEXqTQ0QmmQTmqbUsNZfHFXlNjz+susVDkAk1SrRCdJKxlVZZrM4vUtVBSYgtMIeigNfpqdKGIFhoWQA="
        }
    }))
    .unwrap();

    let answer_str = serde_json::to_string(&answer.into_serde::<MessageTxAPI>().unwrap()).unwrap();

    let expected_answer_str =
        serde_json::to_string(&expected_answer.into_serde::<MessageTxAPI>().unwrap()).unwrap();

    assert_eq!(answer_str, expected_answer_str);
}
