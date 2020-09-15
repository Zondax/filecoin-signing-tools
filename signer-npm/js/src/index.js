const bip39 = require("bip39");
const bip32 = require("bip32");
const cbor = require("ipld-dag-cbor").util;
const secp256k1 = require("secp256k1");
const BN = require("bn.js");
const { MethodInit, MethodPaych } = require("./methods");

const ExtendedKey = require("./extendedkey");
const {
  getDigest,
  getCoinTypeFromPath,
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
  if (getCoinTypeFromPath(path) === "1") {
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
  return new ExtendedKey(privateKey, testnet);
}

function serializeBigNum(gasprice) {
  if (gasprice == "0") {
    return Buffer.from("");
  }
  const gaspriceBigInt = new BN(gasprice, 10);
  const gaspriceBuffer = gaspriceBigInt.toArrayLike(
    Buffer,
    "be",
    gaspriceBigInt.byteLength()
  );
  return Buffer.concat([Buffer.from("00", "hex"), gaspriceBuffer]);
}

function transactionSerializeRaw(message) {
  if (!("to" in message) || typeof message.to !== "string") {
    throw new Error("'to' is a required field and has to be a 'string'");
  }
  if (!("from" in message) || typeof message.from !== "string") {
    throw new Error("'from' is a required field and has to be a 'string'");
  }
  if (!("nonce" in message) || typeof message.nonce !== "number") {
    throw new Error("'nonce' is a required field and has to be a 'number'");
  }
  if (
    !("value" in message) ||
    typeof message.value !== "string" ||
    message.value === "" ||
    message.value.includes("-")
  ) {
    throw new Error(
      "'value' is a required field and has to be a 'string' but not empty or negative"
    );
  }
  if (!("gasfeecap" in message) || typeof message.gasfeecap !== "string") {
    throw new Error("'gasfeecap' is a required field and has to be a 'string'");
  }
  if (!("gaspremium" in message) || typeof message.gaspremium !== "string") {
    throw new Error(
      "'gaspremium' is a required field and has to be a 'string'"
    );
  }
  if (!("gaslimit" in message) || typeof message.gaslimit !== "number") {
    throw new Error("'gaslimit' is a required field and has to be a 'number'");
  }
  if (!("method" in message) || typeof message.method !== "number") {
    throw new Error("'method' is a required field and has to be a 'number'");
  }
  if (!("params" in message) || typeof message.params !== "string") {
    throw new Error("'params' is a required field and has to be a 'string'");
  }

  const to = addressAsBytes(message.to);
  const from = addressAsBytes(message.from);

  const value = serializeBigNum(message.value);
  const gasfeecap = serializeBigNum(message.gasfeecap);
  const gaspremium = serializeBigNum(message.gaspremium);

  const message_to_encode = [
    0,
    to,
    from,
    message.nonce,
    value,
    message.gaslimit,
    gasfeecap,
    gaspremium,
    message.method,
    Buffer.from(message.params, "base64"),
  ];

  return cbor.serialize(message_to_encode);
}

function transactionSerialize(message) {
  const raw_cbor = transactionSerializeRaw(message);
  return Buffer.from(raw_cbor).toString("hex");
}

function transactionParse(cborMessage, testnet) {
  const decoded = cbor.deserialize(Buffer.from(cborMessage, "hex"));

  if (decoded[0] !== 0) {
    throw new Error("Unsupported version");
  }
  if (decoded.length < 10) {
    throw new Error(
      "The cbor is missing some fields... please verify you have 9 fields."
    );
  }

  const message = {};

  message.to = bytesToAddress(decoded[1], testnet);
  message.from = bytesToAddress(decoded[2], testnet);
  message.nonce = decoded[3];
  if (decoded[4][0] === 0x01) {
    throw new Error("Value cant be negative");
  }
  message.value = new BN(decoded[4].toString("hex"), 16).toString(10);
  message.gaslimit = decoded[5];
  message.gasfeecap = new BN(decoded[6].toString("hex"), 16).toString(10);
  message.gaspremium = new BN(decoded[7].toString("hex"), 16).toString(10);
  message.method = decoded[8];
  message.params = decoded[9].toString();

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

  return Buffer.concat([
    Buffer.from(signature.signature),
    Buffer.from([signature.recid]),
  ]);
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

  // TODO: support BLS scheme
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
      GasFeeCap: signedMessage.message.gasfeecap,
      GasPremium: signedMessage.message.gaspremium,
      Method: signedMessage.message.method,
      Nonce: signedMessage.message.nonce,
      Params: Buffer.from(signedMessage.message.params, "hex").toString(
        "base64"
      ),
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

// eslint-disable-next-line no-unused-vars
function createPymtChan(from, to, amount, nonce) {
  if (typeof from !== "string") {
    throw new Error("`from` address has to be a string.");
  }
  if (typeof to !== "string") {
    throw new Error("`to` address has to be a string.");
  }
  if (typeof amount !== "string") {
    throw new Error("`amount` address has to be a string.");
  }
  let constructorParams = [to, from];
  let serializedConstructorParams = cbor.serialize(constructorParams);

  let execParams = [
    {
      42: Buffer.from(
        "000155001466696C2F312F7061796D656E746368616E6E656C",
        "hex"
      ),
    },
    serializedConstructorParams,
  ];
  let serializedParams = cbor.serialize(execParams);
  let message = {
    from: from,
    to: "t01",
    nonce: nonce,
    value: new BN(amount).toString(10),
    gasprice: new BN("100").toString(10),
    gaslimit: 200000000,
    method: MethodInit.Exec,
    params: serializedParams.toString("base64"),
  };

  return message;
}

// eslint-disable-next-line no-unused-vars
function settlePymtChan(pch, from, nonce) {
  if (typeof pch !== "string") {
    throw new Error("`pch` address has to be a string.");
  }
  if (typeof from !== "string") {
    throw new Error("`from` address has to be a string.");
  }
  let message = {
    from: from,
    to: pch,
    nonce: nonce,
    value: new BN("0".toString("hex"), 16).toString(10),
    gasprice: new BN("100".toString("hex"), 16).toString(10),
    gaslimit: 200000000,
    method: MethodPaych.Settle,
    params: "",
  };
  return message;
}

// eslint-disable-next-line no-unused-vars
function collectPymtChan(pch, from, nonce) {
  if (typeof pch !== "string") {
    throw new Error("`pch` address has to be a string.");
  }
  if (typeof from !== "string") {
    throw new Error("`from` address has to be a string.");
  }
  let message = {
    from: from,
    to: pch,
    nonce: nonce,
    value: new BN("0".toString("hex"), 16).toString(10),
    gasprice: new BN("100".toString("hex"), 16).toString(10),
    gaslimit: 200000000,
    method: MethodPaych.Collect,
    params: "",
  };
  return message;
}

// eslint-disable-next-line no-unused-vars
function updatePymtChan(pch, from, signedVoucherBase64, nonce) {
  if (typeof pch !== "string") {
    throw new Error("`pch` address has to be a string.");
  }
  if (typeof from !== "string") {
    throw new Error("`from` address has to be a string.");
  }
  if (typeof signedVoucherBase64 !== "string") {
    throw new Error("`signedVoucher` has to be a base64 string.");
  }
  let cborSignedVoucher = Buffer.from(signedVoucherBase64, "base64");
  let signedVoucher = cbor.deserialize(cborSignedVoucher);
  let updateChannelStateParams = [
    signedVoucher,
    Buffer.alloc(0),
    Buffer.alloc(0),
  ];
  let serializedParams = cbor.serialize(updateChannelStateParams);
  let message = {
    from: from,
    to: pch,
    nonce: nonce,
    value: new BN("0".toString("hex"), 16).toString(10),
    gasprice: new BN("100".toString("hex"), 16).toString(10),
    gaslimit: 200000000,
    method: MethodPaych.UpdateChannelState,
    params: serializedParams.toSTring("base64"),
  };
  return message;
}

// eslint-disable-next-line no-unused-vars
function signVoucher(unsignedVoucherBase64, privateKey) {
  if (typeof unsignedVoucherBase64 !== "string") {
    throw new Error("`unsignedVoucher` has to be a base64 string.");
  }
  if (typeof privateKey !== "string") {
    throw new Error("`privateKey` has to be a base64 string.");
  }
  let cborUnsignedVoucher = Buffer.from(unsignedVoucherBase64, "base64");

  // verify format and convert to buffer if needed
  privateKey = tryToPrivateKeyBuffer(privateKey);

  const messageDigest = getDigest(cborUnsignedVoucher);
  const signature = secp256k1.ecdsaSign(messageDigest, privateKey);

  let unsignedVoucher = cbor.deserialize(cborUnsignedVoucher);

  unsignedVoucher[9] = signature;

  const signedVoucher = cbor.serialize(unsignedVoucher);

  return signedVoucher.toString("base64");
}

// eslint-disable-next-line no-unused-vars
function createVoucher(
  timeLockMin,
  timeLockMax,
  amount,
  lane,
  nonce,
  minSettleHeight
) {
  let voucher = [
    timeLockMin,
    timeLockMax,
    Buffer.alloc(0),
    null,
    lane,
    nonce,
    amount,
    minSettleHeight,
    [],
    Buffer.alloc(0),
  ];

  let serializedVoucher = cbor.serialize(voucher);

  return serializedVoucher.toString("base64");
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
