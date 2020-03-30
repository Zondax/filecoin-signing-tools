import DeviceSession from './session';
import { NotASession } from './errors';

function transactionSerialize (transaction) {
  let cborTransaction;

    // TODO

  return cborTransaction;
}

function transactionSerializeRaw (transaction) {
  let cborTransactionBuffer;

  // TODO

  return cborTransactionBuffer;
}

function transactionParse (cborTransaction, testnet = false) {
  let transaction;

  // TODO

  return transaction;
}

function verifySignature (signature, cborTransaction) {
  let result = false;

  // TODO

  return result;
}

function generateMnemonic () {
  let mnemonic;

  // TODO

  return mnemonic;
}

function keyDerive (path, mnemonic) {
  let extendedKey;

  // TODO

  return extendedKey;
}

function keyDeriveFromSeed (path, seed) {
  let extendedKey;

  // TODO

  return extendedKey;
}

function keyRecover (privateKey, testnet = false) {
  let extendedKey;

  // TODO

  return extendedKey;
}

function transactionSign (transaction, privateKey, scheme = 'secp256k1') {
  let signedTransaction;

  // TODO

  return signedTransaction;
}

function transactionSignRaw (transaction, privateKey, scheme = 'secp256k1') {
  let signature;

  // TODO

  return signature;
}

function keyRetrieve (path, session) {
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


export default {
  transactionSerialize,
  transactionSerializeRaw,
  transactionParse,
  verifySignature,
  generateMnemonic,
  keyDerive,
  keyDeriveFromSeed,
  keyRecover,
  transactionSign,
  transactionSignRaw,
  keyRetrieve,
  transactionSignWithDevice,
  transactionSignRawWithDevice
};
