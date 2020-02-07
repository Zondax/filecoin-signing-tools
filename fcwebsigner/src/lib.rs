mod utils;

use crate::utils::set_panic_hook;
use wasm_bindgen::prelude::*;
use fcsigner;

use bip39::{Mnemonic, Language, Seed};
use secp256k1::{SecretKey, PublicKey};

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub struct Keypair {
    // hexstring of the compressed public key
    pubkey: String,
    // hexstring of the private key
    prvkey: String,
    // Address in the string format
    address: String
}

#[wasm_bindgen]
impl Keypair {
    #[wasm_bindgen(getter)]
    pub fn pubkey(&self) -> String {
        self.pubkey.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn prvkey(&self) -> String {
        self.prvkey.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.address.clone()
    }
}

#[wasm_bindgen]
pub fn hello() -> u8 {
    set_panic_hook();
    return 123;
}

#[wasm_bindgen]
pub fn key_generate() -> Keypair {
    // TODO: return keypair (pub/priv + address)
    // fcsigner::key_generate();

    set_panic_hook();

    let keypair = Keypair {
        pubkey: String::from("Public key!"),
        prvkey: String::from("Private key!"),
        address: String::from("Address!")
    };

    return keypair;
}

#[wasm_bindgen]
pub fn key_derive(_mnemonic: String, _path: String) -> Keypair {
    // TODO mnemonic + path
    // TODO: return keypair (pub/priv + address)

    set_panic_hook();

    let result_mnemonic = Mnemonic::from_phrase(_mnemonic.as_str(), Language::English);

    match result_mnemonic {
        Ok(mnemonic) => {
            let seed = Seed::new(&mnemonic, "");

            let keypair = Keypair {
                pubkey: String::from("We only have seed!"),
                prvkey: String::from("We only have seed!"),
                address: String::from("We only have seed!")
            };

            return keypair;

        }

        Err(err) => {
            let keypair = Keypair {
                pubkey: String::from("Error!"),
                prvkey: String::from("Error!"),
                address: String::from("Error!")
            };

            return keypair;
        }
    }
}

#[wasm_bindgen]
pub fn verify_signature() -> bool {
    set_panic_hook();
    let resp  = fcsigner::verify_signature();

    match resp {
        Ok(_bool) => return _bool,
        Err(_) => return false,
    }
}
