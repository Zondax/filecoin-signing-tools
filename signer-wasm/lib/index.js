import {
  mnemonic_generate,
  key_derive,
  key_derive_from_seed,
  key_recover,
  transaction_serialize,
  transaction_serialize_raw,
  transaction_parse,
  transaction_sign,
  verify_signature,
  get_version,
  key_retrieve_from_device,
  show_key_on_device,
  transaction_sign_raw_with_device
} from '@zondax/filecoin-signer-wasm'

// Renaming functions to fit with camelCase standard
export {
  transaction_serialize as transactionSerialize,
  transaction_serialize_raw as transactionSerializeRaw,
  transaction_parse as transactionParse,
  verify_signature as verifySignature,
  mnemonic_generate as generateMnemonic,
  key_derive as keyDerive,
  key_derive_from_seed as keyDeriveFromSeed,
  key_recover as keyRecover,
  transaction_sign as transactionSign,
  key_retrieve_from_device as keyRetrieveFromDevice,
  transaction_sign_raw_with_device as transactionSignRawWithDevice,
  get_version as getVersionFromDevice,
  show_key_on_device as showKeyOnDevice,
  /*appInfo,
  deviceInfo*/
};
