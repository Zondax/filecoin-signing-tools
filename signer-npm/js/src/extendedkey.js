const secp256k1 = require("secp256k1");
const Address = require('@openworklabs/filecoin-address');
const { getPayloadSECP256K1 } = require('./utils')

class ExtendedKey {
  constructor(privateKey, testnet) {
    const pubKey = secp256k1.publicKeyCreate(privateKey);

    let uncompressedPublicKey = new Uint8Array(65);
    secp256k1.publicKeyConvert(pubKey, false, uncompressedPublicKey);
    uncompressedPublicKey = Buffer.from(uncompressedPublicKey);

    const address = Address.newAddress(1, getPayloadSECP256K1(uncompressedPublicKey))

    this.publicKey = uncompressedPublicKey; // Buffer
    this.privateKey = privateKey; // Buffer
    this.address = Address.encode(testnet ? 't' : 'f', address); // String
  }

  get public_raw() {
    return new Uint8Array(this.publicKey);
  }

  get private_raw() {
    return new Uint8Array(this.privateKey);
  }

  get public_hexstring() {
    return this.publicKey.toString("hex");
  }

  get private_hexstring() {
    return this.privateKey.toString("hex");
  }

  get public_base64() {
    // REVIEW: will this work in browser ?
    return this.publicKey.toString("base64");
  }

  get private_base64() {
    // REVIEW: will this work in browser ?
    return this.privateKey.toString("base64");
  }
}

module.exports = ExtendedKey;
