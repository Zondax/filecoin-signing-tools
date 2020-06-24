const blake2 = require("@nomadic-labs/blake2-js");
const base32Decode = require("base32-decode");
const base32Encode = require("base32-encode");

const assert = require("assert");
const {
  UnknownProtocolIndicator,
  InvalidPayloadLength,
  ProtocolNotSupported,
} = require("./errors");

const { ProtocolIndicator } = require("./constants");

const CID_PREFIX = Buffer.from([0x01, 0x71, 0xa0, 0xe4, 0x02, 0x20]);

function getCID(message) {
  const hasher = blake2.createHash("blake2b", { digestLength: 32 });
  hasher.update(message);
  return Buffer.concat([CID_PREFIX, hasher.digest()]);
}

function getDigest(message) {
  // digest = blake2-256( prefix + blake2b-256(tx) )

  const hasher = blake2.createHash("blake2b", { digestLength: 32 });
  hasher.update(getCID(message));
  return hasher.digest();
}

function getPayloadSECP256K1(uncompressedPublicKey) {
  // blake2b-160
  const hasher = blake2.createHash("blake2b", { digestLength: 20 });
  hasher.update(uncompressedPublicKey);
  return hasher.digest();
}

function getChecksum(payload) {
  const hasher = blake2.createHash("blake2b", { digestLength: 4 });
  hasher.update(payload);
  return hasher.digest();
}

function getAccountFromPath(path) {
  return path.split("/")[2].slice(0, -1);
}

function addressAsBytes(address) {
  let payload;
  const protocolIndicator = address[1];

  switch (Number(protocolIndicator)) {
    case ProtocolIndicator.ID:
      // if (payload.length > 16) { throw new InvalidPayloadLength(); };
      throw new ProtocolNotSupported("ID");
    case ProtocolIndicator.SECP256K1:
      payload = base32Decode(address.slice(2).toUpperCase(), "RFC4648").slice(
        0,
        -4
      );
      if (payload.byteLength !== 20) {
        throw new InvalidPayloadLength();
      }
      break;
    case ProtocolIndicator.ACTOR:
      payload = base32Decode(address.slice(2).toUpperCase(), "RFC4648").slice(
        0,
        -4
      );
      if (payload.byteLength !== 32) {
        throw new InvalidPayloadLength();
      }
      break;
    case ProtocolIndicator.BLS:
      // if (payload.length > 52) { throw new InvalidPayloadLength(); };
      throw new ProtocolNotSupported("BLS");
    default:
      throw new UnknownProtocolIndicator();
  }

  const protocolIndicatorByte = `0${protocolIndicator}`;

  // TODO: check checksum!
  return Buffer.concat([
    Buffer.from(protocolIndicatorByte, "hex"),
    Buffer.from(payload),
  ]);
}

function bytesToAddress(payload, testnet) {
  const protocolIndicator = payload[0];

  switch (Number(protocolIndicator)) {
    case ProtocolIndicator.ID:
      // if (payload.length > 16) { throw new InvalidPayloadLength(); };
      throw new ProtocolNotSupported("ID");
    case ProtocolIndicator.SECP256K1:
      if (payload.slice(1).length !== 20) {
        throw new InvalidPayloadLength();
      }
      break;
    case ProtocolIndicator.ACTOR:
      if (payload.slice(1).length !== 32) {
        throw new InvalidPayloadLength();
      }
      break;
    case ProtocolIndicator.BLS:
      throw new ProtocolNotSupported("BLS");
    default:
      throw new UnknownProtocolIndicator();
  }

  const checksum = getChecksum(payload);

  let prefix = "f";
  if (testnet) {
    prefix = "t";
  }

  prefix += protocolIndicator;

  return (
    prefix +
    base32Encode(Buffer.concat([payload.slice(1), checksum]), "RFC4648", {
      padding: false,
    }).toLowerCase()
  );
}

function trimBuffer(buf) {
  let indexStart = 0;
  for (let i = 0; i < buf.length; i += 1) {
    if (buf[i] === 0x00) {
      indexStart += 1;
    }
  }
  return buf.slice(indexStart - 1);
}

function tryToPrivateKeyBuffer(privateKey) {
  if (typeof privateKey === "string") {
    // We should have a padding!
    if (privateKey.slice(-1) === "=") {
      privateKey = Buffer.from(privateKey, "base64");
    } else {
      privateKey = Buffer.from(privateKey, "hex");
    }
  }

  assert(privateKey.length === 32);

  return privateKey;
}

module.exports = {
  getCID,
  getDigest,
  getPayloadSECP256K1,
  getChecksum,
  getAccountFromPath,
  addressAsBytes,
  bytesToAddress,
  trimBuffer,
  tryToPrivateKeyBuffer,
};
