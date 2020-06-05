const blake2 = require("blake2");
const base32Decode = require('base32-decode');
const base32Encode = require('base32-encode');


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

function getAccountFromPath(path) {
  const account = path.split('/')[2].slice(0,-1);
  return account;
}

function addressAsBytes(address) {
  const payload = base32Decode(address.slice(2).toUpperCase(), 'RFC4648');
  // TODO: check checksum!
  return Buffer.concat([Buffer.from('01','hex'),Buffer.from(payload.slice(0,-4))]);
}

function bytesToAddress(payload, testnet) {
  const checksum = getChecksum(payload);

  let prefix = "f1";
  if (testnet) {
    prefix = "t1";
  }

  const address = prefix + base32Encode(Buffer.concat([payload.slice(1),checksum]), 'RFC4648', { padding: false }).toLowerCase();

  return address;
}

function trimBuffer(buf) {
  indexStart = 0;
  for (let i = 0; i<buf.length; i++) {
    if (buf[i] === 0x00) {
      indexStart = indexStart + 1;
    }
  }
  return buf.slice(indexStart-1);
}

module.exports = {
  getCID,
  getDigest,
  getPayloadSECP256K1,
  getChecksum,
  getAccountFromPath,
  addressAsBytes,
  bytesToAddress,
  trimBuffer
}
