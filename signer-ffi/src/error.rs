use ffi_support::ExternError;

create_fn!(filecoin_signer_error_new|Java_ch_zondax_FilecoinSigner_errorNew: () -> ptr!(ExternError), |_| {
    Box::into_raw(Box::new(ExternError::default()))
});

create_fn!(filecoin_signer_error_code|Java_ch_zondax_FilecoinSigner_errorCode: (error: &ExternError) -> i32, |_| {
    error.get_code().code()
});

create_fn!(filecoin_signer_error_message|Java_ch_zondax_FilecoinSigner_errorMessage: (error: &ExternError) -> str_ret_ty!(), |_| {
    error.get_raw_message()
});

create_fn!(filecoin_signer_error_free|Java_ch_zondax_FilecoinSigner_errorFree: (error: *mut ExternError) -> (), |_| {
    unsafe { Box::from_raw(error).manually_release() }
});