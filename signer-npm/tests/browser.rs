//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

use filecoin_signer::api::SignedMessageAPI;
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
        filecoin_signer_wasm::key_derive(mnemonic, path, "".to_string()).expect("unexpected error");

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
        "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
        "from": "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
        "nonce": 1,
        "value": "100000",
        "gaslimit": 25000,
        "gasfeecap": "1",
        "gaspremium": "1",
        "method": 0,
        "params": ""
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
        "message" : {
        "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
        "from": "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
        "nonce": 1,
        "value": "100000",
        "gaslimit": 25000,
        "gasfeecap": "1",
        "gaspremium": "1",
        "method": 0,
        "params": ""
        },
        "signature" : {
        "type": 1,
        "data":"nFuTI7MxEXqTQ0QmmQTmqbUsNZfHFXlNjz+susVDkAk1SrRCdJKxlVZZrM4vUtVBSYgtMIeigNfpqdKGIFhoWQA="
        }
    }))
    .unwrap();

    let answer_str =
        serde_json::to_string(&answer.into_serde::<SignedMessageAPI>().unwrap()).unwrap();

    let expected_answer_str =
        serde_json::to_string(&expected_answer.into_serde::<SignedMessageAPI>().unwrap()).unwrap();

    assert_eq!(answer_str, expected_answer_str);
}

#[wasm_bindgen_test]
fn check_signature() {
    let tx = "8a005501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855010f323f4709e8e4db0c1d4cd374f9f35201d26fb20144000186a01961a84200014200010040";
    let signature = "9c5b9323b331117a934344269904e6a9b52c3597c715794d8f3facbac5439009354ab4427492b1955659acce2f52d54149882d3087a280d7e9a9d2862058685900";

    let ret = verify_signature(JsValue::from_str(signature), JsValue::from_str(tx));
    assert_eq!(ret.is_ok(), true);
    assert_eq!(ret.unwrap(), true);
}