import bip39 from 'bip39'
import bip32 from 'bip32'
import * as cbor from '@ipld/dag-cbor'
import secp256k1 from 'secp256k1'
import BN from 'bn.js'

import ExtendedKey from './extendedkey.js'
import { getDigest, getCoinTypeFromPath, addressAsBytes, bytesToAddress, tryToPrivateKeyBuffer } from './utils.js'
import { ProtocolIndicator } from './constants.js'

export function generateMnemonic(): string {
  // 256 so it generate 24 words
  return bip39.generateMnemonic(256)
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

export function transactionSerializeRaw(message: any) {
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

  return cbor.encode(message_to_encode)
}

export function transactionSerialize(message: any): string {
  const raw_cbor = transactionSerializeRaw(message)
  return Buffer.from(raw_cbor).toString('hex')
}

export function transactionParse(cborMessage: string, testnet: boolean): any {
  const decoded: any = cbor.decode(Buffer.from(cborMessage, 'hex'))

  if (decoded[0] !== 0) {
    throw new Error('Unsupported version')
  }
  if (decoded.length < 10) {
    throw new Error('The cbor is missing some fields... please verify you have 9 fields.')
  }

  const message: any = {}

  message['To'] = bytesToAddress(decoded[1], testnet)
  message['From'] = bytesToAddress(decoded[2], testnet)
  message['Nonce'] = decoded[3]
  if (decoded[4][0] === 0x01) {
    throw new Error('Value cant be negative')
  }
  message['Value'] = new BN(Buffer.from(decoded[4]).toString('hex'), 16).toString(10)
  message['GasLimit'] = decoded[5]
  message['GasFeeCap'] = new BN(Buffer.from(decoded[6]).toString('hex'), 16).toString(10)
  message['GasPremium'] = new BN(Buffer.from(decoded[7]).toString('hex'), 16).toString(10)
  message['Method'] = decoded[8]
  message['Params'] = decoded[9].toString()

  return message
}

export function transactionSignRaw(unsignedMessage: any, privateKey: string | Buffer): Buffer {
  if (typeof unsignedMessage === 'object') {
    unsignedMessage = transactionSerializeRaw(unsignedMessage)
  }
  if (typeof unsignedMessage === 'string') {
    unsignedMessage = Buffer.from(unsignedMessage, 'hex')
  }

  // verify format and convert to buffer if needed
  privateKey = tryToPrivateKeyBuffer(privateKey)

  const messageDigest = getDigest(unsignedMessage)
  const signature = secp256k1.ecdsaSign(messageDigest, privateKey)

  return Buffer.concat([Buffer.from(signature.signature), Buffer.from([signature.recid])])
}

export function transactionSign(unsignedMessage: any, privateKey: string | Buffer): any {
  if (typeof unsignedMessage !== 'object') {
    throw new Error("'message' need to be an object. Cannot be under CBOR format.")
  }
  const signature = transactionSignRaw(unsignedMessage, privateKey)

  const signedMessage: any = {}

  // TODO: support BLS scheme
  signedMessage['Signature'] = {
    Data: signature.toString('base64'),
    Type: ProtocolIndicator.SECP256K1,
  }

  return signedMessage
}

// TODO: new function 'verifySignature(signedMessage)'; Makes more sense ?
export function verifySignature(signature: string | Buffer, message: any): boolean {
  if (typeof message === 'object') {
    message = transactionSerializeRaw(message)
  }
  if (typeof message === 'string') {
    message = Buffer.from(message, 'hex')
  }

  if (typeof signature === 'string') {
    // We should have a padding!
    if (signature.slice(-1) === '=') {
      signature = Buffer.from(signature, 'base64')
    } else {
      signature = Buffer.from(signature, 'hex')
    }
  }

  const messageDigest = getDigest(message)

  const publicKey = secp256k1.ecdsaRecover(signature.slice(0, -1), signature[64], messageDigest, false)
  return secp256k1.ecdsaVerify(signature.slice(0, -1), messageDigest, publicKey)
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
