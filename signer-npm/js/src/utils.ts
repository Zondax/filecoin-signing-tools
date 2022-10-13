import blake from 'blakejs'
import base32Decode from 'base32-decode'
import base32Encode from 'base32-encode'
// @ts-ignore
import leb from 'leb128'

import assert from 'assert'
import {
  UnknownProtocolIndicator,
  InvalidPayloadLength,
  ProtocolNotSupported,
  InvalidChecksumAddress,
  InvalidPrivateKeyFormat,
} from './errors.js'

import { ProtocolIndicator } from './constants.js'

const CID_PREFIX = Buffer.from([0x01, 0x71, 0xa0, 0xe4, 0x02, 0x20])

export function getCID(message: Buffer): Buffer {
  const blakeCtx = blake.blake2bInit(32)
  blake.blake2bUpdate(blakeCtx, message)
  const hash = Buffer.from(blake.blake2bFinal(blakeCtx))
  return Buffer.concat([CID_PREFIX, hash])
}

export function getDigest(message: Buffer): Buffer {
  // digest = blake2-256( prefix + blake2b-256(tx) )

  const blakeCtx = blake.blake2bInit(32)
  blake.blake2bUpdate(blakeCtx, getCID(message))
  return Buffer.from(blake.blake2bFinal(blakeCtx))
}

export function getPayloadSECP256K1(uncompressedPublicKey: Uint8Array): Buffer {
  // blake2b-160
  const blakeCtx = blake.blake2bInit(20)
  blake.blake2bUpdate(blakeCtx, uncompressedPublicKey)
  return Buffer.from(blake.blake2bFinal(blakeCtx))
}

export function getChecksum(payload: Buffer): Buffer {
  const blakeCtx = blake.blake2bInit(4)
  blake.blake2bUpdate(blakeCtx, payload)
  return Buffer.from(blake.blake2bFinal(blakeCtx))
}

export function getCoinTypeFromPath(path: string): string {
  return path.split('/')[2].slice(0, -1)
}

export function addressAsBytes(address: string): Buffer {
  let address_decoded, payload, checksum
  const protocolIndicator = address[1]
  const protocolIndicatorByte = `0${protocolIndicator}`

  switch (Number(protocolIndicator)) {
    case ProtocolIndicator.ID:
      if (address.length > 18) {
        throw new InvalidPayloadLength()
      }
      return Buffer.concat([Buffer.from(protocolIndicatorByte, 'hex'), Buffer.from(leb.unsigned.encode(address.substr(2)))])
    case ProtocolIndicator.SECP256K1:
      address_decoded = base32Decode(address.slice(2).toUpperCase(), 'RFC4648')

      payload = address_decoded.slice(0, -4)
      checksum = Buffer.from(address_decoded.slice(-4))

      if (payload.byteLength !== 20) {
        throw new InvalidPayloadLength()
      }
      break
    case ProtocolIndicator.ACTOR:
      address_decoded = base32Decode(address.slice(2).toUpperCase(), 'RFC4648')

      payload = address_decoded.slice(0, -4)
      checksum = Buffer.from(address_decoded.slice(-4))

      if (payload.byteLength !== 20) {
        throw new InvalidPayloadLength()
      }
      break
    case ProtocolIndicator.BLS:
      address_decoded = base32Decode(address.slice(2).toUpperCase(), 'RFC4648')

      payload = address_decoded.slice(0, -4)
      checksum = Buffer.from(address_decoded.slice(-4))

      if (payload.byteLength !== 48) {
        throw new InvalidPayloadLength()
      }
      break
    default:
      throw new UnknownProtocolIndicator()
  }

  const bytes_address = Buffer.concat([Buffer.from(protocolIndicatorByte, 'hex'), Buffer.from(payload)])

  if (getChecksum(bytes_address).toString('hex') !== checksum.toString('hex')) {
    throw new InvalidChecksumAddress()
  }

  return bytes_address
}

export function bytesToAddress(payload: Buffer, testnet: boolean): string {
  const protocolIndicator = payload[0]

  switch (Number(protocolIndicator)) {
    case ProtocolIndicator.ID:
      // if (payload.length > 16) { throw new InvalidPayloadLength(); };
      throw new ProtocolNotSupported('ID')
    case ProtocolIndicator.SECP256K1:
      if (payload.slice(1).length !== 20) {
        throw new InvalidPayloadLength()
      }
      break
    case ProtocolIndicator.ACTOR:
      if (payload.slice(1).length !== 20) {
        throw new InvalidPayloadLength()
      }
      break
    case ProtocolIndicator.BLS:
      if (payload.slice(1).length !== 48) {
        throw new InvalidPayloadLength()
      }
      break
    default:
      throw new UnknownProtocolIndicator()
  }

  const checksum = getChecksum(payload)

  let prefix = 'f'
  if (testnet) {
    prefix = 't'
  }

  prefix += protocolIndicator

  return (
    prefix +
    base32Encode(Buffer.concat([payload.slice(1), checksum]), 'RFC4648', {
      padding: false,
    }).toLowerCase()
  )
}

export function tryToPrivateKeyBuffer(privateKey: string | Buffer): Buffer {
  if (typeof privateKey === 'string') {
    // We should have a padding!
    if (privateKey.slice(-1) === '=') {
      privateKey = Buffer.from(privateKey, 'base64')
    } else {
      throw new InvalidPrivateKeyFormat()
    }
  }

  assert(privateKey.length === 32)

  return privateKey
}
