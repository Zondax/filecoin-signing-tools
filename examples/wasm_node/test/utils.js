import blake from 'blakejs'

const CID_PREFIX = Buffer.from([0x01, 0x71, 0xa0, 0xe4, 0x02, 0x20])

function getCID(message) {
  const blakeCtx = blake.blake2bInit(32)
  blake.blake2bUpdate(blakeCtx, message)
  const hash = blake.blake2bFinal(blakeCtx)
  return Buffer.concat([CID_PREFIX, hash])
}

function getDigest(message) {
  const blakeCtx = blake.blake2bInit(32)
  blake.blake2bUpdate(blakeCtx, getCID(message))
  // We want a buffer
  return Buffer.from(blake.blake2bFinal(blakeCtx))
}

function getDigestVoucher(message) {
  const blakeCtx = blake.blake2bInit(32)
  blake.blake2bUpdate(blakeCtx, message)
  return Buffer.from(blake.blake2bFinal(blakeCtx))
}

function blake2b256(message) {
  const blakeCtx = blake.blake2bInit(32)
  blake.blake2bUpdate(blakeCtx, message)
  return blake.blake2bFinal(blakeCtx)
}

export { getCID, getDigest, getDigestVoucher, blake2b256 }
