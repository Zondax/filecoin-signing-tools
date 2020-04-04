use ffi_support::FfiStr;
use crate::{
    filecoin_signer_error_code,
    filecoin_signer_error_free,
    filecoin_signer_error_message,
    filecoin_signer_error_new,
    filecoin_signer_extended_key_free,
    filecoin_signer_extended_key_private_key,
    filecoin_signer_key_derive,
    filecoin_signer_string_free,
};
use std::{
    ffi::CStr,
    os::raw::c_char
};

fn from_ptr<'a, T>(t: *mut T) -> &'a mut T {
    unsafe { &mut *t }
}

fn str_from_ptr<'a>(p: *const c_char) -> &'a str {
    unsafe { FfiStr::from_raw(p).as_str() }
}

#[test]
fn key_derive() {
    let error = filecoin_signer_error_new();
    let extended_key = filecoin_signer_key_derive(
        FfiStr::from_cstr(CStr::from_bytes_with_nul(b"equip will roof matter pink blind book anxiety banner elbow sun young\0").unwrap()),
        FfiStr::from_cstr(CStr::from_bytes_with_nul(b"m/44'/461'/0/0/0\0").unwrap()),
        from_ptr(error)
    );
    if filecoin_signer_error_code(from_ptr(error)) != 0 {
        panic!("{}", str_from_ptr(filecoin_signer_error_message(from_ptr(error))));
    }
    else {
        let private_key = filecoin_signer_extended_key_private_key(from_ptr(extended_key));
        assert!(str_from_ptr(private_key) == "f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a");
        unsafe { filecoin_signer_string_free(private_key); }
    }
    filecoin_signer_extended_key_free(extended_key);
    filecoin_signer_error_free(error);
}