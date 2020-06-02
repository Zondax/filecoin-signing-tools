const blake2 = require("blake2");

const CID_PREFIX = Buffer.from([0x01, 0x71, 0xa0, 0xe4, 0x02, 0x20]);

function getCID(message) {
    const hasher = blake2.createHash("blake2b", {digestLength: 32});
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
  const hasher = blake2.createHash("blake2b", {digestLength: 20});
  hasher.update(uncompressedPublicKey);
  const payload = hasher.digest();
  return payload
}

function getChecksum(payload) {
  const hasher = blake2.createHash("blake2b", {digestLength: 4});
  hasher.update(payload);
  const checksum = hasher.digest();
  return checksum;
}

module.exports = { getCID, getDigest, getPayloadSECP256K1, getChecksum }
