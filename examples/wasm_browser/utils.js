import blake2b from "blake2b";

const CID_PREFIX = Buffer.from([0x01, 0x71, 0xa0, 0xe4, 0x02, 0x20]);

export function getCID(message) {
  const hasher = blake2b(32).update(message);
  return Buffer.concat([CID_PREFIX, Buffer.from(hasher.digest())]);
}

export function getDigest(message) {
  const hasher = blake2b(32).update(getCID(message));
  return Buffer.from(hasher.digest());
}
