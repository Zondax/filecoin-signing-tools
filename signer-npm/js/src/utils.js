const blake = require("blakejs");
const base32Decode = require("base32-decode");
const base32Encode = require("base32-encode");
const leb = require("leb128");

const assert = require("assert");
const {
  UnknownProtocolIndicator,
  InvalidPayloadLength,
  ProtocolNotSupported,
  InvalidChecksumAddress,
} = require("./errors");

const { ProtocolIndicator } = require("./constants");

const CID_PREFIX = Buffer.from([0x01, 0x71, 0xa0, 0xe4, 0x02, 0x20]);

function getCID(message) {
  const blakeCtx = blake.blake2bInit(32);
  blake.blake2bUpdate(blakeCtx, message);
  const hash = Buffer.from(blake.blake2bFinal(blakeCtx));
  return Buffer.concat([CID_PREFIX, hash]);
}

function getDigest(message) {
  // digest = blake2-256( prefix + blake2b-256(tx) )

  const blakeCtx = blake.blake2bInit(32);
  blake.blake2bUpdate(blakeCtx, getCID(message));
  return Buffer.from(blake.blake2bFinal(blakeCtx));
}

function getPayloadSECP256K1(uncompressedPublicKey) {
  // blake2b-160
  const blakeCtx = blake.blake2bInit(20);
  blake.blake2bUpdate(blakeCtx, uncompressedPublicKey);
  return Buffer.from(blake.blake2bFinal(blakeCtx));
}

function getChecksum(payload) {
  const blakeCtx = blake.blake2bInit(4);
  blake.blake2bUpdate(blakeCtx, payload);
  return Buffer.from(blake.blake2bFinal(blakeCtx));
}

function getCoinTypeFromPath(path) {
  return path.split("/")[2].slice(0, -1);
}

function addressAsBytes(address) {
  let address_decoded, payload, checksum;
  const protocolIndicator = address[1];
  const protocolIndicatorByte = `0${protocolIndicator}`;

  switch (Number(protocolIndicator)) {
    case ProtocolIndicator.ID:
      if (address.length > 18) {
        throw new InvalidPayloadLength();
      }
      return Buffer.concat([
        Buffer.from(protocolIndicatorByte, "hex"),
        Buffer.from(leb.unsigned.encode(address.substr(2))),
      ]);
    case ProtocolIndicator.SECP256K1:
      address_decoded = base32Decode(address.slice(2).toUpperCase(), "RFC4648");

      payload = address_decoded.slice(0, -4);
      checksum = Buffer.from(address_decoded.slice(-4));

      if (payload.byteLength !== 20) {
        throw new InvalidPayloadLength();
      }
      break;
    case ProtocolIndicator.ACTOR:
      address_decoded = base32Decode(address.slice(2).toUpperCase(), "RFC4648");

      payload = address_decoded.slice(0, -4);
      checksum = Buffer.from(address_decoded.slice(-4));

      if (payload.byteLength !== 20) {
        throw new InvalidPayloadLength();
      }
      break;
    case ProtocolIndicator.BLS:
      throw new ProtocolNotSupported("BLS");
    default:
      throw new UnknownProtocolIndicator();
  }

  const bytes_address = Buffer.concat([
    Buffer.from(protocolIndicatorByte, "hex"),
    Buffer.from(payload),
  ]);

  if (getChecksum(bytes_address).toString("hex") !== checksum.toString("hex")) {
    throw new InvalidChecksumAddress();
  }

  return bytes_address;
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
      if (payload.slice(1).length !== 20) {
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
  getCoinTypeFromPath,
  addressAsBytes,
  bytesToAddress,
  tryToPrivateKeyBuffer,
};
