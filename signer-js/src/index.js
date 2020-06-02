const bip39 = require('bip39');
const bip32 = require('bip32');
const cbor = require('cbor');
const base32Encode = require('base32-encode');
const blake2 = require('blake2');
const secp256k1 = require('secp256k1');

const ExtendedKey = require('./extendedkey');
const { getDigest, getPayloadSECP256K1, getChecksum } = require('./utils');

function generateMnemonic() {
  // 256 so it generate 24 words
  return bip39.generateMnemonic(256);
}

function keyDeriveFromSeed(seed, path) {
  const masterKey = bip32.fromSeed(seed);

  const childKey = masterKey.derivePath(path);
  var uncompressedPublicKey = new Uint8Array(65);
  secp256k1.publicKeyConvert(childKey.publicKey, false, uncompressedPublicKey);
  uncompressedPublicKey = Buffer.from(uncompressedPublicKey);

  const payload = getPayloadSECP256K1(uncompressedPublicKey);
  const checksum = getChecksum(Buffer.concat([Buffer.from('01', 'hex'), payload]));

  const address = "f1" + base32Encode(Buffer.concat([payload,checksum]), 'RFC4648', { padding: false }).toLowerCase();

  return new ExtendedKey(childKey.privateKey, uncompressedPublicKey, address);
}

function keyDerive(mnemonic, path, password) {
  const seed = bip39.mnemonicToSeedSync(mnemonic, password);
  return keyDeriveFromSeed(seed, path);
}

function keyRecover(privateKey, testnet) {
  var uncompressedPublicKey = new Uint8Array(65);
  secp256k1.publicKeyCreate(privateKey, false, uncompressedPublicKey);
  uncompressedPublicKey = Buffer.from(uncompressedPublicKey);

  const payload = getPayloadSECP256K1(uncompressedPublicKey);
  const checksum = getChecksum(Buffer.concat([Buffer.from('01', 'hex'), payload]));

  const address = "f1" + base32.encode(Buffer.concat([payload,checksum]));

  return new ExtendedKey(privateKey, uncompressedPublicKey, address);
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
