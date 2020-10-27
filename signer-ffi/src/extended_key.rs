use ffi_support::{call_with_result, ExternError};
use filecoin_signer::ExtendedKey;

create_fn!(filecoin_signer_extended_key_private_key|Java_ch_zondax_FilecoinSigner_extendedKeyPrivateKey: (
    ek: &mut ExtendedKey,
    error: &mut ExternError
) -> str_ret_ty!(), |etc| {
    call_with_result(error, || -> Result<str_ret_ty!(), ExternError> {
        create_string!(etc, hex::encode(&ek.private_key.0))
    })
});

create_fn!(filecoin_signer_extended_key_public_key|Java_ch_zondax_FilecoinSigner_extendedKeyPublicKey: (
    ek: &mut ExtendedKey,
    error: &mut ExternError
) -> str_ret_ty!(), |etc| {
    call_with_result(error, || -> Result<str_ret_ty!(), ExternError> {
        create_string!(etc, hex::encode(&ek.public_key.to_vec()))
    })
});

create_fn_destructor!(
    ExtendedKey,
    filecoin_signer_extended_key_free | Java_ch_zondax_FilecoinSigner_extendedKeyFree
);
