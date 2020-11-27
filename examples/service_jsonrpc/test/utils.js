import blake from "blakejs";

const CID_PREFIX = Buffer.from([0x01, 0x71, 0xa0, 0xe4, 0x02, 0x20]);

export function getCID(message) {
  const blakeCtx = blake.blake2bInit(32);
  blake.blake2bUpdate(blakeCtx, message);
  const hash = blake.blake2bFinal(blakeCtx);
  return Buffer.concat([CID_PREFIX, hash]);
}

export function getDigest(message) {
  // digest = blake2-256( prefix + blake2b-256(tx) )

  const blakeCtx = blake.blake2bInit(32);
  blake.blake2bUpdate(blakeCtx, getCID(message));
  return blake.blake2bFinal(blakeCtx);
}

module.exports = { getCID, getDigest };
