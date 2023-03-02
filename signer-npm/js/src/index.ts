import bip39 from 'bip39'
import * as bip32Default from 'bip32'
import * as ecc from 'tiny-secp256k1'
import * as cbor from '@ipld/dag-cbor'
import secp256k1 from 'secp256k1'
import BN from 'bn.js'

import ExtendedKey from './extendedkey.js'
import { getDigest, getCoinTypeFromPath, addressAsBytes, bytesToAddress, tryToPrivateKeyBuffer, getPayloadSECP256K1 } from './utils.js'
import { ProtocolIndicator } from './constants.js'
import { SignedMessage, TransactionRaw } from './types'

// You must wrap a tiny-secp256k1 compatible implementation
const bip32 = bip32Default.BIP32Factory(ecc)

export function generateMnemonic(): string {
  // 256 so it generate 24 words
  return bip39.generateMnemonic(256)
}

export function validateAddressAsString(address: string): boolean {
  try {
    addressAsBytes(address)
    return true
  } catch (error) {
    return false
  }
}

export function validateAddressAsBytes(bytes: Buffer): boolean {
  try {
    bytesToAddress(bytes, false)
    return true
  } catch (error) {
    return false
  }
}

export function parseAddress(address: string): Buffer {
  return addressAsBytes(address)
}

export function encodeAddress(bytes: Buffer, isTestnet: boolean): string {
  return bytesToAddress(bytes, isTestnet)
}

export function keyDeriveFromSeed(seed: string | Buffer, path: string): ExtendedKey {
  if (typeof seed === 'string') {
    seed = Buffer.from(seed, 'hex')
  }

  const masterKey = bip32.fromSeed(seed)

  const childKey = masterKey.derivePath(path)

  if (!childKey.privateKey) {
    throw new Error('privateKey not generated')
  }

  let testnet = false
  if (getCoinTypeFromPath(path) === '1') {
    testnet = true
  }

  return new ExtendedKey(childKey.privateKey, testnet)
}

export function keyDerive(mnemonic: string, path: string, password: string | undefined): ExtendedKey {
  if (password === undefined) {
    throw new Error("'password' argument must be of type string or an instance of Buffer or ArrayBuffer. Received undefined")
  }

  const seed = bip39.mnemonicToSeedSync(mnemonic, password)
  return keyDeriveFromSeed(seed, path)
}

export function keyRecover(privateKey: Buffer, testnet: boolean): ExtendedKey {
  privateKey = tryToPrivateKeyBuffer(privateKey)
  return new ExtendedKey(privateKey, testnet)
}

export function serializeBigNum(gasprice: string): Buffer {
  if (gasprice == '0') {
    return Buffer.from('')
  }
  const gaspriceBigInt = new BN(gasprice, 10)
  const gaspriceBuffer = gaspriceBigInt.toArrayLike(Buffer, 'be', gaspriceBigInt.byteLength())
  return Buffer.concat([Buffer.from('00', 'hex'), gaspriceBuffer])
}

export function transactionSerializeRaw(message: TransactionRaw): Buffer {
  if (!('To' in message) || typeof message['To'] !== 'string') {
    throw new Error("'To' is a required field and has to be a 'string'")
  }
  if (!('From' in message) || typeof message['From'] !== 'string') {
    throw new Error("'From' is a required field and has to be a 'string'")
  }
  if (!('Nonce' in message) || typeof message['Nonce'] !== 'number') {
    throw new Error("'Nonce' is a required field and has to be a 'number'")
  }
  if (!('Value' in message) || typeof message['Value'] !== 'string' || message['Value'] === '' || message['Value'].includes('-')) {
    throw new Error("'Value' is a required field and has to be a 'string' but not empty or negative")
  }
  if (!('GasFeeCap' in message) || typeof message['GasFeeCap'] !== 'string') {
    throw new Error("'GasFeeCap' is a required field and has to be a 'string'")
  }
  if (!('GasPremium' in message) || typeof message['GasPremium'] !== 'string') {
    throw new Error("'GasPremium' is a required field and has to be a 'string'")
  }
  if (!('GasLimit' in message) || typeof message['GasLimit'] !== 'number') {
    throw new Error("'GasLimit' is a required field and has to be a 'number'")
  }
  if (!('Method' in message) || typeof message['Method'] !== 'number') {
    throw new Error("'Method' is a required field and has to be a 'number'")
  }
  if (!('Params' in message) || typeof message['Params'] !== 'string') {
    throw new Error("'Params' is a required field and has to be a 'string'")
  }

  const to = addressAsBytes(message['To'])
  const from = addressAsBytes(message['From'])

  const value = serializeBigNum(message['Value'])
  const gasfeecap = serializeBigNum(message['GasFeeCap'])
  const gaspremium = serializeBigNum(message['GasPremium'])

  const message_to_encode = [
    0,
    to,
    from,
    message['Nonce'],
    value,
    message['GasLimit'],
    gasfeecap,
    gaspremium,
    message['Method'],
    Buffer.from(message['Params'], 'base64'),
  ]

  return Buffer.from(cbor.encode(message_to_encode))
}

export function transactionSerialize(message: TransactionRaw): string {
  const raw_cbor = transactionSerializeRaw(message)
  return Buffer.from(raw_cbor).toString('hex')
}

export function transactionParse(cborMessage: string, testnet: boolean): TransactionRaw {
  const decoded: any = cbor.decode(Buffer.from(cborMessage, 'hex'))

  if (decoded[0] !== 0) {
    throw new Error('Unsupported version')
  }
  if (decoded.length < 10) {
    throw new Error('The cbor is missing some fields... please verify you have 9 fields.')
  }

  if (decoded[4][0] === 0x01) {
    throw new Error('Value cant be negative')
  }

  const message: TransactionRaw = {
    To: bytesToAddress(decoded[1], testnet),
    From: bytesToAddress(decoded[2], testnet),
    Nonce: decoded[3],
    Value: new BN(Buffer.from(decoded[4]).toString('hex'), 16).toString(10),
    GasLimit: decoded[5],
    GasFeeCap: new BN(Buffer.from(decoded[6]).toString('hex'), 16).toString(10),
    GasPremium: new BN(Buffer.from(decoded[7]).toString('hex'), 16).toString(10),
    Method: decoded[8],
    Params: decoded[9].toString(),
  }
  return message
}

export function transactionSignRaw(unsignedMessage: TransactionRaw | string, privateKey: string | Buffer): Buffer {
  let parsedMessage: ArrayLike<number>

  if (typeof unsignedMessage === 'string') parsedMessage = Buffer.from(unsignedMessage, 'hex')
  else if (typeof unsignedMessage === 'object') parsedMessage = transactionSerializeRaw(unsignedMessage)
  else throw new Error('message must be TransactionRaw or hex string')

  // verify format and convert to buffer if needed
  privateKey = tryToPrivateKeyBuffer(privateKey)

  const messageDigest = getDigest(parsedMessage)
  const signature = secp256k1.ecdsaSign(messageDigest, privateKey)

  return Buffer.concat([Buffer.from(signature.signature), Buffer.from([signature.recid])])
}

export function transactionSign(unsignedMessage: TransactionRaw, privateKey: string | Buffer): any {
  if (typeof unsignedMessage !== 'object') throw new Error("'message' need to be an object. Cannot be under CBOR format.")

  const signature = transactionSignRaw(unsignedMessage, privateKey)

  // TODO: support BLS scheme
  const signedMessage: SignedMessage = {
    Signature: {
      Data: signature.toString('base64'),
      Type: ProtocolIndicator.SECP256K1,
    },
  }

  return signedMessage
}

// TODO: new function 'verifySignature(signedMessage)'; Makes more sense ?
export function verifySignature(signature: string | Buffer, message: TransactionRaw | string): boolean {
  let messageBuf: Buffer
  if (typeof message === 'object') messageBuf = transactionSerializeRaw(message)
  else if (typeof message === 'string') messageBuf = Buffer.from(message, 'hex')
  else throw new Error('message must be TransactionRaw or hex string')

  let signatureBuf: Buffer
  if (typeof signature === 'string') {
    // We should have a padding!
    if (signature.slice(-1) === '=') {
      signatureBuf = Buffer.from(signature, 'base64')
    } else {
      signatureBuf = Buffer.from(signature, 'hex')
    }
  } else {
    signatureBuf = signature
  }

  const messageDigest = getDigest(messageBuf)

  const publicKey = secp256k1.ecdsaRecover(signatureBuf.slice(0, -1), signatureBuf[64], messageDigest, false)
  if (!secp256k1.ecdsaVerify(signatureBuf.slice(0, -1), messageDigest, publicKey)) {
    return false
  }

  const addrBytes = Buffer.concat([Buffer.from([ProtocolIndicator.SECP256K1]), getPayloadSECP256K1(publicKey)])
  const messageParsed = transactionParse(messageBuf.toString('hex'), false)

  if (bytesToAddress(addrBytes, false) != messageParsed.From) {
    return false
  }

  return true
}

// eslint-disable-next-line no-unused-vars
export function signVoucher(unsignedVoucherBase64: string, privateKey: string): string {
  if (typeof unsignedVoucherBase64 !== 'string') {
    throw new Error('`unsignedVoucher` has to be a base64 string.')
  }
  if (typeof privateKey !== 'string') {
    throw new Error('`privateKey` has to be a base64 string.')
  }
  let cborUnsignedVoucher = Buffer.from(unsignedVoucherBase64, 'base64')

  // verify format and convert to buffer if needed
  const privateKeyBuff = tryToPrivateKeyBuffer(privateKey)

  const messageDigest = getDigest(cborUnsignedVoucher)
  const signature = secp256k1.ecdsaSign(messageDigest, privateKeyBuff)

  let unsignedVoucher: any = cbor.decode(cborUnsignedVoucher)

  unsignedVoucher[9] = signature

  const signedVoucher = cbor.encode(unsignedVoucher)

  return Buffer.from(signedVoucher).toString('base64')
}

// eslint-disable-next-line no-unused-vars
export function createVoucher(
  timeLockMin: string,
  timeLockMax: string,
  amount: string,
  lane: string,
  nonce: string,
  minSettleHeight: string,
): string {
  let voucher = [timeLockMin, timeLockMax, Buffer.alloc(0), null, lane, nonce, amount, minSettleHeight, [], Buffer.alloc(0)]

  let serializedVoucher = cbor.encode(voucher)

  return Buffer.from(serializedVoucher).toString('base64')
}
