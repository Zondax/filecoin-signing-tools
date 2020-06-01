const bip39 = require('bip39');
const bip32 = require('bip32');
const ExtendedKey = require('./extendedkey');
const cbor = require('cbor');

function generateMnemonic() {
  // 256 so it generate 24 words
  return bip39.generateMnemonic(256);
}

function keyDerive(mnemonic, path, password) {
  const seed = bip39.mnemonicToSeedSync(mnemonic);
  const masterKey = bip32.fromSeed(seed);

  const childKey = masterKey.derivePath(path);

  // Need to get address from public key
  return new ExtendedKey(childKey.privateKey, childKey.publicKey, "");
}

function keyDeriveFromSeed(seed, path) {

  return new ExtendedKey();
}

function keyRecover(privateKey, testnet) {

  return new ExtendedKey();
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
