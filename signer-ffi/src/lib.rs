#[macro_use]
mod macros;

use ffi_support::{call_with_result, ExternError, FfiStr};
use filecoin_signer::{key_derive, ExtendedKey};

create_fn!(filecoin_error_new|Java_Filecoin_errorNew: () -> ExternError {
    ExternError::default()
});

create_fn!(filecoin_error_free|Java_Filecoin_errorFree: (error: ExternError) -> () {
    unsafe { error.manually_release() }
});

create_fn!(filecoin_key_derive|Java_Filecoin_keyDeriveNew: (
    mnemonic: FfiStr<'_>,
    path: FfiStr<'_>,
    error: &mut ExternError
) -> ptr!(ExtendedKey) {
    call_with_result(error, || -> Result<ExtendedKey, ExternError> {
        Ok(key_derive(mnemonic.as_str(), path.as_str())?.into())
    })
});

create_fn_destructor!(ExtendedKey, filecoin_key_derive_free|Java_Filecoin_keyDeriveFree);

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "with-jni"))]
    use {
        ffi_support::{FfiStr},
        crate::{filecoin_key_derive, filecoin_error_new, filecoin_error_free, filecoin_key_derive_free},
        std::ffi::CStr,
    };

    #[cfg(not(feature = "with-jni"))]
    #[test]
    fn key_derive() {
        let mut error = filecoin_error_new();
        let ptr = filecoin_key_derive(
            FfiStr::from_cstr(CStr::from_bytes_with_nul(b"a\0").unwrap()),
            FfiStr::from_cstr(CStr::from_bytes_with_nul(b"a\0").unwrap()),
            &mut error
        );
        filecoin_key_derive_free(ptr);
        filecoin_error_free(error);
    }
}