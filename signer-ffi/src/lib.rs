#[macro_use]
mod macros;

mod error;
mod extended_key;

use ffi_support::{call_with_result, ExternError};
use filecoin_signer::{key_derive, ExtendedKey};

create_fn!(filecoin_signer_key_derive|Java_ch_zondax_FilecoinSigner_keyDerive: (
    mnemonic: str_arg_ty!(),
    path: str_arg_ty!(),
    error: &mut ExternError
) -> ptr!(ExtendedKey), |etc| {
    call_with_result(error, || -> Result<ExtendedKey, ExternError> {
        Ok(key_derive(get_str!(etc, mnemonic), get_str!(etc, path))?.into())
    })
});

#[cfg(not(feature = "with-jni"))]
ffi_support::define_string_destructor!(filecoin_signer_string_free);
