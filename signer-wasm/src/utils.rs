use filecoin_signer::utils::to_hex_string;
use filecoin_signer_ledger::app::{Address, Signature};
use js_sys::Object;
use wasm_bindgen::prelude::*;

// This defines the Node.js Buffer type
#[wasm_bindgen]
extern "C" {
    pub type Buffer;

    #[wasm_bindgen(constructor)]
    fn from(buffer_array: &[u8]) -> Buffer;
}

/// Convert an address answer into a javascript object with proper buffer field
pub fn address_to_object(address: &Address) -> Object {
    let obj = js_sys::Object::new();

    js_sys::Reflect::set(
        &obj,
        &"compressed_pk".into(),
        &Buffer::from(&address.public_key.serialize().to_vec()),
    )
    .unwrap();
    js_sys::Reflect::set(
        &obj,
        &"addrString".into(),
        &JsValue::from_str(&address.addr_string),
    )
    .unwrap();
    js_sys::Reflect::set(
        &obj,
        &"addrByte".into(),
        &Buffer::from(&address.addr_byte.to_vec()),
    )
    .unwrap();

    obj
}

/// Convert a signature answer into a javascript object with proper buffer field
pub fn signature_to_object(signature: &Signature) -> Object {
    let obj = js_sys::Object::new();

    js_sys::Reflect::set(
        &obj,
        &"signature_compact".into(),
        &Buffer::from(&signature.sig.serialize().to_vec()),
    )
    .unwrap();
    js_sys::Reflect::set(
        &obj,
        &"signature_der".into(),
        &Buffer::from(&signature.sig.serialize_der().as_ref().to_vec()),
    )
    .unwrap();
    js_sys::Reflect::set(&obj, &"r".into(), &Buffer::from(&signature.r)).unwrap();
    js_sys::Reflect::set(&obj, &"s".into(), &Buffer::from(&signature.s)).unwrap();

    obj
}

pub fn bytes_to_buffer(b: &[u8]) -> Buffer {
    Buffer::from(b)
}
