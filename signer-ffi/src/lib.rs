#[macro_use]
mod macros;

use ffi_support::{call_with_result, ExternError};
use filecoin_signer::{key_derive, ExtendedKey};

create_fn!(filecoin_signer_error_new|Java_ch_zondax_FilecoinSigner_errorNew: () -> ptr!(ExternError), |_| {
    Box::into_raw(Box::new(ExternError::default()))
});

create_fn!(filecoin_signer_error_free|Java_ch_zondax_FilecoinSigner_errorFree: (error: ptr!(ExternError)) -> (), |_| {
    let p = (error) as *mut ExternError;
    if  !p.is_null() {
        let _box = unsafe { Box::from_raw(p) };
    }
});

create_fn!(filecoin_signer_key_derive|Java_ch_zondax_FilecoinSigner_keyDerive: (
    mnemonic: str_ty!(),
    path: str_ty!(),
    error: &mut ExternError
) -> ptr!(ExtendedKey), |etc| {
    call_with_result(error, || -> Result<ExtendedKey, ExternError> {
        Ok(key_derive(get_str!(etc, mnemonic), get_str!(etc, path))?.into())
    })
});

create_fn_destructor!(ExtendedKey, filecoin_signer_key_derive_free|Java_ch_zondax_FilecoinSigner_keyDeriveFree);

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "with-jni"))]
    use {
        ffi_support::FfiStr,
        crate::{filecoin_signer_key_derive, filecoin_signer_error_new, filecoin_signer_error_free, filecoin_signer_key_derive_free},
        std::ffi::CStr,
    };

    #[cfg(not(feature = "with-jni"))]
    #[test]
    fn key_derive() {
        let mut error = filecoin_signer_error_new();
        let ptr = filecoin_signer_key_derive(
            FfiStr::from_cstr(CStr::from_bytes_with_nul(b"a\0").unwrap()),
            FfiStr::from_cstr(CStr::from_bytes_with_nul(b"a\0").unwrap()),
            &mut error
        );
        filecoin_signer_key_derive_free(ptr);
        filecoin_signer_error_free(error);
    }
}