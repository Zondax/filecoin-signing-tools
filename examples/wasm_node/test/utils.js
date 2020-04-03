const blake2 = require("blake2");

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

module.exports = { getCID, getDigest }
