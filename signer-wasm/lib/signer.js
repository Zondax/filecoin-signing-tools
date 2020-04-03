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


async function keyRetrieveFromDevice (path, session) {
  if (!session instanceof DeviceSession) throw new NotASession();

  const pubkeys = resp = await session.device.getAddressAndPubKey(path);

  return pubkeys;
}

async function transactionSignWithDevice (transaction, path, session) {
  if (!session instanceof DeviceSession) throw new NotASession();

  // REVIEW: I am guessing transaction is an object and not the cbor_message
  const message = transaction_serialize_raw(transaction);

  const signature = await session.device.sign(path, message);

  const signedTransaction = {
    message: transaction,
    signature: {
      sig_type: "secp256k1",
      data: signature
    }
  }

  return signedTransaction;
}

async function transactionSignRawWithDevice (transaction, session) {
  if (!session instanceof DeviceSession) throw new NotASession();

  const message = transaction_serialize_raw(transaction);

  const signature = await session.device.sign(path, message);

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
