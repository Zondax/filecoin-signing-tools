const bip39 = require('bip39')
const bip32 = require('bip32')
const cbor = require('@ipld/dag-cbor')
const secp256k1 = require('secp256k1')
const BN = require('bn.js')
const { MethodInit, MethodPaych } = require('./methods')

const ExtendedKey = require('./extendedkey')
const { getDigest, getCoinTypeFromPath, addressAsBytes, bytesToAddress, tryToPrivateKeyBuffer } = require('./utils')
const { ProtocolIndicator } = require('./constants')

function generateMnemonic() {
  // 256 so it generate 24 words
  return bip39.generateMnemonic(256)
}

function keyDeriveFromSeed(seed, path) {
  if (typeof seed === 'string') {
    seed = Buffer.from(seed, 'hex')
  }

  const masterKey = bip32.fromSeed(seed)

  const childKey = masterKey.derivePath(path)

  let testnet = false
  if (getCoinTypeFromPath(path) === '1') {
    testnet = true
  }

  return new ExtendedKey(childKey.privateKey, testnet)
}

function keyDerive(mnemonic, path, password) {
  if (password === undefined) {
    throw new Error("'password' argument must be of type string or an instance of Buffer or ArrayBuffer. Received undefined")
  }

  const seed = bip39.mnemonicToSeedSync(mnemonic, password)
  return keyDeriveFromSeed(seed, path)
}

function keyRecover(privateKey, testnet) {
  privateKey = tryToPrivateKeyBuffer(privateKey)
  return new ExtendedKey(privateKey, testnet)
}

function serializeBigNum(gasprice) {
  if (gasprice == '0') {
    return Buffer.from('')
  }
  const gaspriceBigInt = new BN(gasprice, 10)
  const gaspriceBuffer = gaspriceBigInt.toArrayLike(Buffer, 'be', gaspriceBigInt.byteLength())
  return Buffer.concat([Buffer.from('00', 'hex'), gaspriceBuffer])
}

function transactionSerializeRaw(message) {
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

function transactionSerialize(message) {
  const raw_cbor = transactionSerializeRaw(message)
  return Buffer.from(raw_cbor).toString('hex')
}

function transactionParse(cborMessage, testnet) {
  const decoded = cbor.decode(Buffer.from(cborMessage, 'hex'))

  if (decoded[0] !== 0) {
    throw new Error('Unsupported version')
  }
  if (decoded.length < 10) {
    throw new Error('The cbor is missing some fields... please verify you have 9 fields.')
  }

  const message = {}

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

function transactionSignRaw(message, privateKey) {
  if (typeof message !== 'object') {
    throw new Error("'message' need to be an object. Cannot be under CBOR format.")
  }

  const serializedMessage = transactionSerializeRaw(message)
  const from = message.From

  switch (from[1]) {
    case '1':
      // Protocol 1 - SECP256K1
      return signSecpk256k1(serializedMessage, privateKey)
    case '3':
      // Protocol 1 - BLS
      return signBLS(serializedMessage, privateKey)
    default:
      throw new Error("Unknown protocol. Can't sign transaction.")
  }
}

function signSecpk256k1(message, privateKey) {
  // verify format and convert to buffer if needed
  privateKey = tryToPrivateKeyBuffer(privateKey)

  const digest = getDigest(message)
  const signature = secp256k1.ecdsaSign(digest, privateKey)

  return Buffer.concat([Buffer.from(signature.signature), Buffer.from([signature.recid])])
}

function signBLS(message, privateKey) {
  const sk = SecretKey.fromBytes(privateKey)
  const digest = getDigest(message)

  const signature = sk.sign(digest)

  return Buffer.from(signature.toBytes())
}

function transactionSign(unsignedMessage, privateKey) {
  if (typeof unsignedMessage !== 'object') {
    throw new Error("'message' need to be an object. Cannot be under CBOR format.")
  }
  const signature = transactionSignRaw(unsignedMessage, privateKey)

  const signedMessage = {}

  // TODO: support BLS scheme
  signedMessage['Signature'] = {
    Data: signature.toString('base64'),
    Type: ProtocolIndicator.SECP256K1,
  }

  return signedMessage
}

// TODO: new function 'verifySignature(signedMessage)'; Makes more sense ?
function verifySignature(signature, message) {
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
function createPymtChan(from, to, amount, nonce) {
  if (typeof from !== 'string') {
    throw new Error('`From` address has to be a string.')
  }
  if (typeof to !== 'string') {
    throw new Error('`To` address has to be a string.')
  }
  if (typeof amount !== 'string') {
    throw new Error('`Value` address has to be a string.')
  }
  let constructorParams = [to, from]
  let serializedConstructorParams = cbor.encode(constructorParams)

  let execParams = [
    {
      42: Buffer.from('000155001466696C2F312F7061796D656E746368616E6E656C', 'hex'),
    },
    serializedConstructorParams,
  ]
  let serializedParams = cbor.encode(execParams)
  let message = {
    From: from,
    To: 't01',
    Nonce: nonce,
    Value: new BN(amount).toString(10),
    GasPrice: new BN('100').toString(10),
    GasLimit: 200000000,
    Method: MethodInit.Exec,
    Params: serializedParams.toString('base64'),
  }

  return message
}

// eslint-disable-next-line no-unused-vars
function settlePymtChan(pch, from, nonce) {
  if (typeof pch !== 'string') {
    throw new Error('`pch` address has to be a string.')
  }
  if (typeof from !== 'string') {
    throw new Error('`from` address has to be a string.')
  }
  let message = {
    From: from,
    To: pch,
    Nonce: nonce,
    Value: new BN('0'.toString('hex'), 16).toString(10),
    GasPrice: new BN('100'.toString('hex'), 16).toString(10),
    GasLimit: 200000000,
    Method: MethodPaych.Settle,
    Params: '',
  }
  return message
}

// eslint-disable-next-line no-unused-vars
function collectPymtChan(pch, from, nonce) {
  if (typeof pch !== 'string') {
    throw new Error('`pch` address has to be a string.')
  }
  if (typeof from !== 'string') {
    throw new Error('`from` address has to be a string.')
  }
  let message = {
    From: from,
    To: pch,
    Nonce: nonce,
    Value: new BN('0'.toString('hex'), 16).toString(10),
    GasPrice: new BN('100'.toString('hex'), 16).toString(10),
    GasLimit: 200000000,
    Method: MethodPaych.Collect,
    Params: '',
  }
  return message
}

// eslint-disable-next-line no-unused-vars
function updatePymtChan(pch, from, signedVoucherBase64, nonce) {
  if (typeof pch !== 'string') {
    throw new Error('`pch` address has to be a string.')
  }
  if (typeof from !== 'string') {
    throw new Error('`from` address has to be a string.')
  }
  if (typeof signedVoucherBase64 !== 'string') {
    throw new Error('`signedVoucher` has to be a base64 string.')
  }
  let cborSignedVoucher = Buffer.from(signedVoucherBase64, 'base64')
  let signedVoucher = cbor.decode(cborSignedVoucher)
  let updateChannelStateParams = [signedVoucher, Buffer.alloc(0), Buffer.alloc(0)]
  let serializedParams = cbor.encode(updateChannelStateParams)
  let message = {
    From: from,
    To: pch,
    Nonce: nonce,
    Value: new BN('0'.toString('hex'), 16).toString(10),
    GasPrice: new BN('100'.toString('hex'), 16).toString(10),
    GasLimit: 200000000,
    Method: MethodPaych.UpdateChannelState,
    Params: serializedParams.toSTring('base64'),
  }
  return message
}

// eslint-disable-next-line no-unused-vars
function signVoucher(unsignedVoucherBase64, privateKey) {
  if (typeof unsignedVoucherBase64 !== 'string') {
    throw new Error('`unsignedVoucher` has to be a base64 string.')
  }
  if (typeof privateKey !== 'string') {
    throw new Error('`privateKey` has to be a base64 string.')
  }
  let cborUnsignedVoucher = Buffer.from(unsignedVoucherBase64, 'base64')

  // verify format and convert to buffer if needed
  privateKey = tryToPrivateKeyBuffer(privateKey)

  const messageDigest = getDigest(cborUnsignedVoucher)
  const signature = secp256k1.ecdsaSign(messageDigest, privateKey)

  let unsignedVoucher = cbor.decode(cborUnsignedVoucher)

  unsignedVoucher[9] = signature

  const signedVoucher = cbor.encode(unsignedVoucher)

  return signedVoucher.toString('base64')
}

// eslint-disable-next-line no-unused-vars
function createVoucher(timeLockMin, timeLockMax, amount, lane, nonce, minSettleHeight) {
  let voucher = [timeLockMin, timeLockMax, Buffer.alloc(0), null, lane, nonce, amount, minSettleHeight, [], Buffer.alloc(0)]

  let serializedVoucher = cbor.encode(voucher)

  return serializedVoucher.toString('base64')
}

module.exports = {
  generateMnemonic,
  keyDerive,
  keyDeriveFromSeed,
  keyRecover,
  transactionSerialize,
  transactionSerializeRaw,
  transactionParse,
  transactionSign,
  transactionSignRaw,
  verifySignature,
  addressAsBytes,
  bytesToAddress,
}
