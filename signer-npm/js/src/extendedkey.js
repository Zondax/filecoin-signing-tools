const base32Encode = require("base32-encode");
const secp256k1 = require("secp256k1");
const { getPayloadSECP256K1, getChecksum } = require("./utils");

class ExtendedKey {
  constructor(privateKey, testnet) {
    const pubKey = secp256k1.publicKeyCreate(privateKey);

    let uncompressedPublicKey = new Uint8Array(65);
    secp256k1.publicKeyConvert(pubKey, false, uncompressedPublicKey);
    uncompressedPublicKey = Buffer.from(uncompressedPublicKey);

    const payload = getPayloadSECP256K1(uncompressedPublicKey);
    const checksum = getChecksum(
      Buffer.concat([Buffer.from("01", "hex"), payload])
    );

    let prefix = "f1";
    if (testnet) {
      prefix = "t1";
    }

    const address =
      prefix +
      base32Encode(Buffer.concat([payload, checksum]), "RFC4648", {
        padding: false,
      }).toLowerCase();

    this.publicKey = uncompressedPublicKey; // Buffer
    this.privateKey = privateKey; // Buffer
    this.address = address; // String
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
    return this.publicKey.toString("base64");
  }

  get private_base64() {
    return this.privateKey.toString("base64");
  }
}

module.exports = ExtendedKey;
