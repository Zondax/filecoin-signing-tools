import base32Encode from 'base32-encode'
import secp256k1 from 'secp256k1'
import { getPayloadSECP256K1, getChecksum } from './utils.js'

export default class ExtendedKey {
  publicKey: Buffer
  privateKey: Buffer
  address: string

  constructor(privateKey: Buffer, testnet: boolean) {
    const pubKey = secp256k1.publicKeyCreate(privateKey)

    const uncompressedPublicKey = new Uint8Array(65)
    secp256k1.publicKeyConvert(pubKey, false, uncompressedPublicKey)
    const uncompressedPublicKeyBuf = Buffer.from(uncompressedPublicKey)

    const payload = getPayloadSECP256K1(uncompressedPublicKey)
    const checksum = getChecksum(Buffer.concat([Buffer.from('01', 'hex'), payload]))

    let prefix = 'f1'
    if (testnet) {
      prefix = 't1'
    }

    const address =
      prefix +
      base32Encode(Buffer.concat([payload, checksum]), 'RFC4648', {
        padding: false,
      }).toLowerCase()

    this.publicKey = uncompressedPublicKeyBuf // Buffer
    this.privateKey = privateKey // Buffer
    this.address = address // String
  }

  get public_raw() {
    return new Uint8Array(this.publicKey)
  }

  get private_raw() {
    return new Uint8Array(this.privateKey)
  }

  get public_hexstring() {
    return this.publicKey.toString('hex')
  }

  get private_hexstring() {
    return this.privateKey.toString('hex')
  }

  get public_base64() {
    return this.publicKey.toString('base64')
  }

  get private_base64() {
    return this.privateKey.toString('base64')
  }
}
