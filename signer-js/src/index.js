const bip39 = require('bip39');
const bip32 = require('bip32');
const cbor = require('cbor');
const base32Encode = require('base32-encode');
const blake2 = require('blake2');
const secp256k1 = require('secp256k1');

const ExtendedKey = require('./extendedkey');
const { getDigest, getAccountFromPath } = require('./utils');

function generateMnemonic() {
  // 256 so it generate 24 words
  return bip39.generateMnemonic(256);
}

function keyDeriveFromSeed(seed, path) {
  if (typeof seed === 'string') { seed = Buffer.from(seed, 'hex'); }

  const masterKey = bip32.fromSeed(seed);

  const childKey = masterKey.derivePath(path);

  let testnet = false;
  if (getAccountFromPath(path) === '1') {
    testnet = true;
  }

  return new ExtendedKey(childKey.privateKey, testnet);
}

function keyDerive(mnemonic, path, password) {
  const seed = bip39.mnemonicToSeedSync(mnemonic, password);
  return keyDeriveFromSeed(seed, path);
}

function keyRecover(privateKey, testnet) {
  if (typeof privateKey === 'string') { privateKey = Buffer.from(privateKey, 'hex'); }

  return new ExtendedKey(privateKey, testnet);
}

function transactionSerialize(message) {

}

function transactionSerializeRaw(message) {

}

function transactionParse(cborMessage, testnet) {

}

function transactionSign(unsignedMessage, privateKey) {

}

function transactionSignLotus(unsignedMessage, privateKey) {

}

function transactionSignRaw(unsignedMessage, privateKey) {

}

function verifySignature(signature, message) {

}

module.exports = {
  generateMnemonic,
  keyDerive,
  keyDeriveFromSeed,
  keyRecover,
  transactionSerialize,
  transactionSerializeRaw,
  transactionParse,
  transactionSign,
  transactionSignLotus,
  transactionSignRaw,
  verifySignature
}
