#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used,))]

#[macro_use]
mod macros;

mod error;
mod extended_key;

use ffi_support::{call_with_result, ExternError};
use filecoin_signer::{key_derive, ExtendedKey};

create_fn!(filecoin_signer_key_derive|Java_ch_zondax_FilecoinSigner_keyDerive: (
    mnemonic: str_arg_ty!(),
    path: str_arg_ty!(),
    password: str_arg_ty!(),
    language_code: str_arg_ty!(),
    error: &mut ExternError
) -> ptr!(ExtendedKey), |etc| {
    call_with_result(error, || -> Result<ExtendedKey, ExternError> {
        let mnemonic = get_string!(etc, mnemonic)?;
        let path = get_string!(etc, path)?;
        let password = get_string!(etc, password)?;
        Ok(key_derive(
            get_string_ref(&mnemonic),
            get_string_ref(&path),
            get_string_ref(&password),
            get_string_ref(&language_code),
        )?)
    })
});

#[cfg(not(feature = "with-jni"))]
ffi_support::define_string_destructor!(filecoin_signer_string_free);

#[cfg(feature = "with-jni")]
fn get_string_ref(s: &std::ffi::CStr) -> &str {
    ffi_support::FfiStr::from_cstr(s).as_str()
}
#[cfg(not(feature = "with-jni"))]
fn get_string_ref<'a>(s: &'a ffi_support::FfiStr) -> &'a str {
    s.as_str()
}
