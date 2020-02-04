mod utils;

use crate::utils::set_panic_hook;
use wasm_bindgen::prelude::*;
use fcsigner;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub struct Keypair {
    pubkey: u8[32],
    prvkey: u8[44],
}

#[wasm_bindgen]
pub fn hello() -> u8 {
    set_panic_hook();
    return 123;
}

#[wasm_bindgen]
pub fn key_generate() {
    // TODO: return keypair (pub/priv + address)
    fcsigner::key_generate();
}

#[wasm_bindgen]
pub fn verify_signature() -> bool {
    set_panic_hook();
    let resp  = fcsigner::verify_signature();

    match resp {
        Ok(_bool) => return _bool,
        Err(()) => return false,
    }
}
