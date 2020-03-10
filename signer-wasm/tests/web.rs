//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;

use fcwasmsigner::key_derive;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

mod tests {
    use fcwasmsigner::{key_derive, sign_transaction};

    #[wasm_bindgen_test]
    fn derive() {
        let mnemonic =
            "equip will roof matter pink blind book anxiety banner elbow sun young".to_string();

        let path = "m/44'/461'/0/0/1".to_string();

        let answer = key_derive(mnemonic, path).expect("unexpected error");

        assert_eq!(
            answer.public(),
            "02fc016f3d88dc7070cdd95b5754d32fd5290f850b7c2208fca0f715d35861de18"
        );

        assert_eq!(
            answer.private(),
            "80c56e752ffdd06e3e0d9516e662e7ba883982404045a2c2d4cbe7c87e6c66fe"
        );

        assert_eq!(
            answer.address(),
            "t1oqorxpyo4oj4tyfinkwxyh6zxorbquaqrg65rcy"
        )
    }

    const EXAMPLE_UNSIGNED_MESSAGE: &str = r#"
        {
            "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
            "from": "t1xcbgdhkgkwht3hrrnui3jdopeejsoas2rujnkdi",
            "nonce": 1,
            "value": "100000",
            "gas_price": "2500",
            "gas_limit": "25000",
            "method": 0,
            "params": ""
        }"#;

    const PRIVATE_KEY: &str = r#"80c56e752ffdd06e3e0d9516e662e7ba883982404045a2c2d4cbe7c87e6c66fe"#;

    #[wasm_bindgen_test]
    fn sign() {
        let answer = sign_transaction(
            EXAMPLE_UNSIGNED_MESSAGE.to_string(),
            PRIVATE_KEY.to_string(),
        )
        .expect("unexpected error");

        assert_eq!(
            answer.public(),
            "02fc016f3d88dc7070cdd95b5754d32fd5290f850b7c2208fca0f715d35861de18"
        );

        assert_eq!(
            answer.private(),
            "80c56e752ffdd06e3e0d9516e662e7ba883982404045a2c2d4cbe7c87e6c66fe"
        );

        assert_eq!(
            answer.address(),
            "t1oqorxpyo4oj4tyfinkwxyh6zxorbquaqrg65rcy"
        )
    }
}
