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

  const pubkeys = await session.app.getAddressAndPubKey(path);

  return pubkeys;
}

async function transactionSignWithDevice (transaction, path, session) {
  if (!session instanceof DeviceSession) throw new NotASession();

  let message = transaction;
  if (!transaction instanceof String) {
    // we serialize
    message = transaction_serialize_raw(transaction);
  }

  const signature = await session.app.sign(path, message);

  const signedTransaction = {
    message: transaction,
    signature: {
      sig_type: "secp256k1",
      data: signature
    }
  }

  return signedTransaction;
}

async function transactionSignRawWithDevice (transaction, path, session) {
  if (!session instanceof DeviceSession) throw new NotASession();

  let message = transaction;
  if (!transaction instanceof String) {
    // we serialize
    message = transaction_serialize_raw(transaction);
  }

  const signature = await session.app.sign(path, message);

  return signature;
}

async function getVersionFromDevice (session) {
  if (!session instanceof DeviceSession) throw new NotASession();

  const version = await session.app.getVersion();

  return version;
}

async function showKeyOnDevice (path, session) {
  if (!session instanceof DeviceSession) throw new NotASession();

  const keys = await session.app.showAddressAndPubKey(path);

  return keys;
}

async function appInfo (session) {
  if (!session instanceof DeviceSession) throw new NotASession();

  const info = await session.app.appInfo();

  return info;
}

async function deviceInfo (session) {
  if (!session instanceof DeviceSession) throw new NotASession();

  const info = await session.app.deviceInfo();

  return info;
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
  transactionSignRawWithDevice,
  getVersionFromDevice,
  showKeyOnDevice,
  appInfo,
  deviceInfo
};
