const bip39 = require("bip39");
const bip32 = require("bip32");
const cbor = require("ipld-dag-cbor").util;
const secp256k1 = require("secp256k1");
const BN = require('bn.js');

const ExtendedKey = require("./extendedkey");
const {
  getDigest,
  getAccountFromPath,
  addressAsBytes,
  bytesToAddress,
  tryToPrivateKeyBuffer,
} = require("./utils");
const { ProtocolIndicator } = require("./constants");

function generateMnemonic() {
  // 256 so it generate 24 words
  return bip39.generateMnemonic(256);
}

function keyDeriveFromSeed(seed, path) {
  if (typeof seed === "string") {
    seed = Buffer.from(seed, "hex");
  }

  const masterKey = bip32.fromSeed(seed);

  const childKey = masterKey.derivePath(path);

  let testnet = false;
  if (getAccountFromPath(path) === "1") {
    testnet = true;
  }

  return new ExtendedKey(childKey.privateKey, testnet);
}

function keyDerive(mnemonic, path, password) {
  if (password === undefined) {
    throw new Error(
      "'password' argument must be of type string or an instance of Buffer or ArrayBuffer. Received undefined"
    );
  }

  const seed = bip39.mnemonicToSeedSync(mnemonic, password);
  return keyDeriveFromSeed(seed, path);
}

function keyRecover(privateKey, testnet) {
  // verify format and convert to buffer if needed
  privateKey = tryToPrivateKeyBuffer(privateKey);
  console.log(privateKey)
  return new ExtendedKey(privateKey, testnet);
}

function transactionSerializeRaw(message) {
  if (!"to" in message || typeof message.to !== "string") {
    throw new Error("'to' is a required field and has to be a 'string'");
  }
  if (!"from" in message || typeof message.from !== "string") {
    throw new Error("'from' is a required field and has to be a 'string'");
  }
  if (!"nonce" in message || typeof message.nonce !== "number") {
    throw new Error("'nonce' is a required field and has to be a 'number'");
  }
  if (
    !"value" in message ||
    typeof message.value !== "string" ||
    message.value === "" ||
    message.value.includes("-")
  ) {
    throw new Error(
      "'value' is a required field and has to be a 'string' but not empty or negative"
    );
  }
  if (!"gasprice" in message || typeof message.gasprice !== "string") {
    throw new Error("'gasprice' is a required field and has to be a 'string'");
  }
  if (!"gaslimit" in message || typeof message.gaslimit !== "number") {
    throw new Error("'gaslimit' is a required field and has to be a 'number'");
  }
  if (!"method" in message || typeof message.method !== "number") {
    throw new Error("'method' is a required field and has to be a 'number'");
  }

  const to = addressAsBytes(message.to);
  const from = addressAsBytes(message.from);

  const valueBigInt = new BN(message.value, 10);
  const valueBuffer = valueBigInt.toArrayLike(Buffer, 'be', valueBigInt.byteLength());
  const value = Buffer.concat([Buffer.from('00', 'hex'), valueBuffer]);

  const gaspriceBigInt = new BN(message.gasprice, 10);
  const gaspriceBuffer = gaspriceBigInt.toArrayLike(Buffer, 'be', gaspriceBigInt.byteLength());
  let gasprice = Buffer.concat([Buffer.from('00', 'hex'), gaspriceBuffer]);

  if (message.gasprice === "0") {
    gasprice = Buffer.from("")
  }

  const message_to_encode = [
    0,
    to,
    from,
    message.nonce,
    value,
    gasprice,
    message.gaslimit,
    message.method,
    Buffer.from(message.params),
  ];

  return cbor.serialize(message_to_encode);
}

function transactionSerialize(message) {
  const raw_cbor = transactionSerializeRaw(message);
  return Buffer.from(raw_cbor).toString("hex");
}

function transactionParse(cborMessage, testnet) {
  // FIXME: Check buffer size and extra bytes
  // https://github.com/dignifiedquire/borc/issues/47
  const decoded = cbor.deserialize(Buffer.from(cborMessage, "hex"));

  if (decoded[0] !== 0) {
    throw new Error("Unsupported version");
  }
  if (decoded.length < 9) {
    throw new Error(
      "The cbor is missing some fields... please verify you 9 fields."
    );
  }

  const message = {};

  message.to = bytesToAddress(decoded[1], testnet);
  message.from = bytesToAddress(decoded[2], testnet);
  message.nonce = decoded[3];
  if (decoded[4][0] === 0x01) {
    throw new Error("Value cant be negative");
  }
  message.value = new BN(decoded[4].toString('hex'), 16).toString(10);
  message.gasprice = new BN(decoded[5].toString('hex'), 16).toString(10);
  message.gaslimit = decoded[6];
  message.method = decoded[7];
  message.params = decoded[8].toString();

  return message;
}

function transactionSignRaw(unsignedMessage, privateKey) {
  if (typeof unsignedMessage === "object") {
    unsignedMessage = transactionSerializeRaw(unsignedMessage);
  }
  if (typeof unsignedMessage === "string") {
    unsignedMessage = Buffer.from(unsignedMessage, "hex");
  }

  // verify format and convert to buffer if needed
  privateKey = tryToPrivateKeyBuffer(privateKey);

  const messageDigest = getDigest(unsignedMessage);
  const signature = secp256k1.ecdsaSign(messageDigest, privateKey);

  return Buffer.concat([Buffer.from(signature.signature), Buffer.from([signature.recid])]);
}

function transactionSign(unsignedMessage, privateKey) {
  if (typeof unsignedMessage !== "object") {
    throw new Error(
      "'message' need to be an object. Cannot be under CBOR format."
    );
  }
  const signature = transactionSignRaw(unsignedMessage, privateKey);

  const signedMessage = {};

  signedMessage.message = unsignedMessage;

  // FIXME: only support secp256k1
  signedMessage.signature = {
    data: signature.toString("base64"),
    type: ProtocolIndicator.SECP256K1,
  };

  return signedMessage;
}

function transactionSignLotus(unsignedMessage, privateKey) {
  const signedMessage = transactionSign(unsignedMessage, privateKey);

  return JSON.stringify({
    Message: {
      From: signedMessage.message.from,
      GasLimit: signedMessage.message.gaslimit,
      GasPrice: signedMessage.message.gasprice,
      Method: signedMessage.message.method,
      Nonce: signedMessage.message.nonce,
      Params: Buffer.from(signedMessage.message.params, "hex").toString("base64"),
      To: signedMessage.message.to,
      Value: signedMessage.message.value,
    },
    Signature: {
      Data: signedMessage.signature.data,
      Type: signedMessage.signature.type,
    },
  });
}

// TODO: new function 'verifySignature(signedMessage)'; Makes more sense ?
function verifySignature(signature, message) {
  if (typeof message === "object") {
    message = transactionSerializeRaw(message);
  }
  if (typeof message === "string") {
    message = Buffer.from(message, "hex");
  }

  if (typeof signature === "string") {
    // We should have a padding!
    if (signature.slice(-1) === "=") {
      signature = Buffer.from(signature, "base64");
    } else {
      signature = Buffer.from(signature, "hex");
    }
  }

  const messageDigest = getDigest(message);

  const publicKey = secp256k1.ecdsaRecover(
    signature.slice(0, -1),
    signature[64],
    messageDigest,
    false
  );
  return secp256k1.ecdsaVerify(
    signature.slice(0, -1),
    messageDigest,
    publicKey
  );
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
  verifySignature,
  addressAsBytes,
  bytesToAddress,
};
