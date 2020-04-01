import DeviceSession from './session';
import { NotASession } from './errors';
import {
  mnemonic_generate,
  key_derive,
  key_derive_from_seed,
  key_recover,
  transaction_serialize,
  transaction_serialize_raw,
  transaction_parse,
  transaction_sign,
  verify_signature
} from '@zondax/filecoin-signer-wasm'


function keyRetrieveFromDevice (path, session) {
  let pubkeys;

  if (!session instanceof DeviceSession) throw new NotASession();

  // TODO

  return pubkeys;
}

function transactionSignWithDevice (transaction, session) {
  let signedTransaction;

  if (!session instanceof DeviceSession) throw new NotASession();

  // TODO

  return signedTransaction;
}

function transactionSignRawWithDevice (transaction, session) {
  let signature;

  if (!session instanceof DeviceSession) throw new NotASession();

  // TODO

  return signature;
}

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
  //transactionSignRaw,
  keyRetrieveFromDevice,
  transactionSignWithDevice,
  transactionSignRawWithDevice
};
