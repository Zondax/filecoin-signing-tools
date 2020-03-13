//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;

use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

const EXAMPLE_UNSIGNED_MESSAGE: &str = r#"
        {
            "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
            "from": "t1xcbgdhkgkwht3hrrnui3jdopeejsoas2rujnkdi",
            "nonce": 1,
            "value": "100000",
            "gasprice": "2500",
            "gaslimit": "25000",
            "method": 0,
            "params": ""
        }"#;

const PRIVATE_KEY: &str = r#"80c56e752ffdd06e3e0d9516e662e7ba883982404045a2c2d4cbe7c87e6c66fe"#;

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

    let answer = filecoin_signer_wasm::key_derive(mnemonic, path).expect("unexpected error");

    assert_eq!(
        answer.public_compressed_hexstring(),
        "02fc016f3d88dc7070cdd95b5754d32fd5290f850b7c2208fca0f715d35861de18"
    );

    assert_eq!(
        answer.private_hexstring(),
        "80c56e752ffdd06e3e0d9516e662e7ba883982404045a2c2d4cbe7c87e6c66fe"
    );

    assert_eq!(
        answer.address(),
        "t1rovwtiuo5ncslpmpjftzu5akswbgsgighjazxoi"
    )
}

#[wasm_bindgen_test]
fn sign() {
    let answer = filecoin_signer_wasm::transaction_sign(
        EXAMPLE_UNSIGNED_MESSAGE.to_string(),
        PRIVATE_KEY.to_string(),
    )
    .expect("unexpected error");

    assert_eq!(
        answer,
        "{\"message\":{\"to\":\"t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy\",\"from\":\"t1xcbgdhkgkwht3hrrnui3jdopeejsoas2rujnkdi\",\"nonce\":1,\"value\":\"100000\",\"gasprice\":\"2500\",\"gaslimit\":\"25000\",\"method\":0,\"params\":\"\"},\"signature\":{\"type\":\"secp256k1\",\"data\":\"TBB0Z+np2Cw8/YwIPGQfD1aHIM6iMoP7+pdrJujXS0EhvD3gOlHfDzBs86QBx2LhqudUm41Lb+YdEtaEe6pu9QA=\"}}"
    );
}
