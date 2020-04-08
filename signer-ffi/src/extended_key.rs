use filecoin_signer::{utils::to_hex_string, ExtendedKey};

create_fn!(filecoin_signer_extended_key_private_key|Java_ch_zondax_FilecoinSigner_extendedKeyPrivateKey: (ek: &mut ExtendedKey) -> str_ret_ty!(), |etc| {
    create_str!(etc, to_hex_string(&ek.private_key.0))
});

create_fn!(filecoin_signer_extended_key_public_key|Java_ch_zondax_FilecoinSigner_extendedKeyPublicKey: (ek: &mut ExtendedKey) -> str_ret_ty!(), |etc| {
    create_str!(etc, to_hex_string(&ek.public_key.0))
});

create_fn!(filecoin_signer_extended_key_public_key_compressed|Java_ch_zondax_FilecoinSigner_extendedKeyPublicKeyCompressed: (ek: &mut ExtendedKey) -> str_ret_ty!(), |etc| {
    create_str!(etc, to_hex_string(&ek.public_key_compressed.0))
});

create_fn_destructor!(
    ExtendedKey,
    filecoin_signer_extended_key_free | Java_ch_zondax_FilecoinSigner_extendedKeyFree
);
