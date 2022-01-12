const bip39 = require('bip39')
const bip32 = require('bip32')
const { getDigest, getDigestVoucher, blake2b256 } = require('./utils')
const secp256k1 = require('secp256k1')
const fs = require('fs')
const assert = require('assert')
const cbor = require('ipld-dag-cbor').util

// Test twice for wasm version and pure js version
if (process.env.PURE_JS) {
  var filecoin_signer = require('@zondax/filecoin-signing-tools/js')
} else {
  var filecoin_signer = require('@zondax/filecoin-signing-tools')
}

/* Load Txs test data */
let rawdataTxs = fs.readFileSync('../../test_vectors/txs.json')
let dataTxs = JSON.parse(rawdataTxs)

/* Load wallet test data */
let rawdataWallet = fs.readFileSync('../../test_vectors/wallet.json')
let dataWallet = JSON.parse(rawdataWallet)

const MASTER_NODE = bip32.fromBase58(dataWallet.master_key)

let describeCall = describe
if (process.env.PURE_JS) {
  describeCall = describe.skip
}

describe('generateMnemonic', function() {
  it('should generate a 24 words mnemonic', function() {
    const mnemonic = filecoin_signer.generateMnemonic()
    assert.strictEqual(mnemonic.split(' ').length, 24)
  })
})

describeCall('keyDerive', function() {
  it('should derive key from mnemonic', function() {
    const child = dataWallet.childs[0]

    const keypair = filecoin_signer.keyDerive(dataWallet.mnemonic, child.path, child.password)

    console.log('Public Key Raw         :', keypair.public_raw)
    console.log('Public Key             :', keypair.public_hexstring)
    console.log('Private                :', keypair.private_hexstring)
    console.log('Address                :', keypair.address)

    const expected_keys = MASTER_NODE.derivePath(child.path)
    assert.strictEqual(keypair.private_hexstring, expected_keys.privateKey.toString('hex'))
    assert.strictEqual(keypair.address, child.address)
  })

  it('should derive key from mnemonic and return a testnet address', function() {
    const child = dataWallet.childs[1]

    assert(child.testnet)

    const keypair = filecoin_signer.keyDerive(dataWallet.mnemonic, child.path, child.password)

    console.log('Public Key Raw         :', keypair.public_raw)
    console.log('Public Key             :', keypair.public_hexstring)
    console.log('Private                :', keypair.private_hexstring)
    console.log('Address                :', keypair.address)

    const expected_keys = MASTER_NODE.derivePath(child.path)
    assert.strictEqual(keypair.private_hexstring, expected_keys.privateKey.toString('hex'))
    assert(keypair.address.startsWith('t'))
  })

  it('should not work without password', function() {
    assert.throws(() => {
        filecoin_signer.keyDerive(dataWallet.mnemonic, 'm/44\'/461\'/0/0/1')
      },
      "TypeError: Cannot read properties of undefined (reading 'length')",
    )
  })

  it('should throw an error because of invalid path', function() {
    assert.throws(
      () => filecoin_signer.keyDerive(dataWallet.mnemonic, 'm/44\'/461\'/a/0/1', ''),
      /Expected BIP32Path, got String | Invalid BIP44 path/,
    )
  })

  it('should derive key with the password', function() {
    const password = 'password'
    const keypair = filecoin_signer.keyDerive(dataWallet.mnemonic, 'm/44\'/461\'/0/0/1', password)

    console.log('Public Key Raw         :', keypair.public_raw)
    console.log('Public Key             :', keypair.public_hexstring)
    console.log('Private                :', keypair.private_hexstring)
    console.log('Address                :', keypair.address)

    const seed = bip39.mnemonicToSeedSync(dataWallet.mnemonic, password)
    const node = bip32.fromSeed(seed)

    const expected_keys = node.derivePath('m/44\'/461\'/0/0/1')
    assert.strictEqual(keypair.private_hexstring, expected_keys.privateKey.toString('hex'))
  })

  it('should not match the key with the different password', function() {
    const keypair = filecoin_signer.keyDerive(dataWallet.mnemonic, 'm/44\'/461\'/0/0/1', 'password')

    console.log('Public Key Raw         :', keypair.public_raw)
    console.log('Public Key             :', keypair.public_hexstring)
    console.log('Private                :', keypair.private_hexstring)
    console.log('Address                :', keypair.address)

    const seed = bip39.mnemonicToSeedSync(dataWallet.mnemonic, 'lol')
    const node = bip32.fromSeed(seed)

    const expected_keys = node.derivePath('m/44\'/461\'/0/0/1')
    assert.notEqual(keypair.private_hexstring, expected_keys.privateKey.toString('hex'))
  })


  it('fail if incorrect language_code', function() {
    assert.throws(
      () => filecoin_signer.keyDerive(dataWallet.mnemonic, 'm/44\'/461\'/0/0/1', '', 'fr'),
      /invalid word in phrase/,
    )
  })

  it('fail if unknown language_code', function() {
    assert.throws(
      () => filecoin_signer.keyDerive(dataWallet.mnemonic, 'm/44\'/461\'/0/0/1', '', 'be'),
      /Unknown language code/,
    )
  })

  /* Load mnemonics test data */
  let raw = fs.readFileSync('../../test_vectors/mnemonics.json')
  let data = JSON.parse(raw)

  for (let tc of data) {
    it(tc.description, function() {

      let key = filecoin_signer.keyDerive(tc.mnemonic, 'm/44\'/461\'/0/0/1', '', tc.language_code)

      assert(key)
    })
  }

})

describe('keyDeriveFromSeed', function() {
  it('should derive key from seed', function() {
    const child = dataWallet.childs[0]
    const seed = bip39.mnemonicToSeedSync(dataWallet.mnemonic).toString('hex')

    const keypair = filecoin_signer.keyDeriveFromSeed(seed, child.path)

    console.log('Public Key Raw         :', keypair.public_raw)
    console.log('Public Key             :', keypair.public_hexstring)
    console.log('Private                :', keypair.private_hexstring)
    console.log('Address                :', keypair.address)

    const expected_keys = MASTER_NODE.derivePath(child.path)
    assert.strictEqual(keypair.private_hexstring, expected_keys.privateKey.toString('hex'))
    assert.strictEqual(keypair.address, child.address)
  })

  it('should be able to derive from seed buffer', function() {
    const child = dataWallet.childs[0]
    const seed = bip39.mnemonicToSeedSync(dataWallet.mnemonic)

    const keypair = filecoin_signer.keyDeriveFromSeed(seed, child.path)

    console.log('Public Key Raw         :', keypair.public_raw)
    console.log('Public Key             :', keypair.public_hexstring)
    console.log('Private                :', keypair.private_hexstring)
    console.log('Address                :', keypair.address)

    const expected_keys = MASTER_NODE.derivePath(child.path)
    assert.strictEqual(keypair.private_hexstring, expected_keys.privateKey.toString('hex'))
    assert.strictEqual(keypair.address, child.address)
  })
})

describe('keyRecover', function() {
  it('should recover testnet key (buffer private key)', function() {
    let child = dataWallet.childs[2]
    let expected_keys = MASTER_NODE.derivePath(child.path)

    assert(child.testnet)

    let recoveredKey = filecoin_signer.keyRecover(expected_keys.privateKey, true)

    console.log('Public Key Raw         :', recoveredKey.public_raw)
    console.log('Public Key             :', recoveredKey.public_hexstring)
    console.log('Private                :', recoveredKey.private_hexstring)
    console.log('Private Key (base64)   :', recoveredKey.private_base64)
    console.log('Address                :', recoveredKey.address)

    assert.strictEqual(recoveredKey.private_hexstring, expected_keys.privateKey.toString('hex'))
    assert.strictEqual(recoveredKey.address, child.address)
  })

  it('key recover mainnet base64', () => {
    let child = dataWallet.childs[3]
    let expected_keys = MASTER_NODE.derivePath(child.path)

    let recoveredKey = filecoin_signer.keyRecover(expected_keys.privateKey.toString('base64'), false)

    console.log('Public Key Raw         :', recoveredKey.public_raw)
    console.log('Public Key (hex)       :', recoveredKey.public_hexstring)
    console.log('Private Key (hex)      :', recoveredKey.private_hexstring)
    console.log('Public Key (base64)    :', recoveredKey.public_base64)
    console.log('Private Key (base64)   :', recoveredKey.private_base64)
    console.log('Address                :', recoveredKey.address)

    assert.strictEqual(recoveredKey.private_hexstring, expected_keys.privateKey.toString('hex'))
    assert.strictEqual(recoveredKey.address, child.address)
  })
})

describeCall('keyRecoverBLS', function() {
  it('should derive the key and return a BLS address', function() {
    let recoveredKey = filecoin_signer.keyRecoverBLS(dataWallet.bls_private_key, true)

    console.log('Public Key Raw         :', recoveredKey.public_raw)
    console.log('Public Key             :', recoveredKey.public_hexstring)
    console.log('Private                :', recoveredKey.private_hexstring)
    console.log('Address                :', recoveredKey.address)

    assert.strictEqual(recoveredKey.address, dataWallet.bls_address)
  })
})

describe('transactionSerialize', function() {
  it('should serialize transaction', function() {
    assert.strictEqual(dataTxs[0].cbor, filecoin_signer.transactionSerialize(dataTxs[0].transaction))
  })

  let itCall = it
  if (process.env.PURE_JS) {
    itCall = it.skip
  }
  itCall('should serialize transaction with serialize params', function() {
    console.log(dataTxs[2].transaction)
    let serializedTransaction = filecoin_signer.transactionSerialize(dataTxs[2].transaction)

    console.log(serializedTransaction)

    assert.strictEqual(
      dataTxs[2].cbor,
      serializedTransaction,
    )
  })
})

describe('transactionSerializeRaw', function() {
  it('should serialize raw transaction', function() {
    let tx = dataTxs[0]
    let cbor_uint8_array = filecoin_signer.transactionSerializeRaw(tx.transaction)
    assert.strictEqual(tx.cbor, Buffer.from(cbor_uint8_array).toString('hex'))
  })
})

describe('transactionParse', function() {
  it('should parse transaction (testnet)', function() {
    let tx = dataTxs[0]
    assert.deepStrictEqual(tx.transaction, filecoin_signer.transactionParse(tx.cbor, tx.testnet))
  })

  it('should parse transaction (mainnet)', function() {
    let tx = dataTxs[1]
    assert.deepStrictEqual(tx.transaction, filecoin_signer.transactionParse(tx.cbor, tx.testnet))
  })

  it('should fail to parse because of extra bytes', function() {
    let tx = dataTxs[0]
    let cbor_transaction_extra_bytes = tx.cbor + '00'

    assert.throws(
      () => filecoin_signer.transactionParse(cbor_transaction_extra_bytes, false),
      /(Encoding error \| trailing data at offset 64|Extraneous CBOR data found beyond initial top-level object)/,
    )
  })

  it('should fail to parse because of extra bytes (non null)', function() {
    let tx = dataTxs[0]
    let cbor_transaction_extra_bytes = tx.cbor + '39'

    assert.throws(
      () => filecoin_signer.transactionParse(cbor_transaction_extra_bytes, false),
      /(Encoding error \| trailing data at offset 64|Failed to parse)/,
    )
  })
})

describe('transactionSign', function() {
  it('should sign transaction', function() {
    const child = dataWallet.childs[3]
    const tx = dataTxs[0]
    const example_key = MASTER_NODE.derivePath(child.path)

    var signed_tx = filecoin_signer.transactionSign(tx.transaction, example_key.privateKey.toString('base64'))
    console.log(signed_tx.signature)
    const signature = Buffer.from(signed_tx.signature.data, 'base64')

    let message_digest = getDigest(Buffer.from(tx.cbor, 'hex'))

    // Signature representation is R, S & V
    console.log('Signature  :', signature.toString('hex'))
    console.log('Digest     :', message_digest.toString('hex'))
    console.log('Public key :', example_key.publicKey.toString('hex'))

    assert.strictEqual(
      true,
      // Remove the V value from the signature (last byte)
      secp256k1.ecdsaVerify(signature.slice(0, -1), message_digest, example_key.publicKey),
    )

    // Verify recovery id which is the last byte of the signature
    assert.strictEqual(0x00, signature[64])
  })
})

describe('transactionSignLotus', function() {
  it('should sign transaction and return a Lotus compatible json string', function() {
    let data = fs.readFileSync('../../test_vectors/signed_message.json')
    let tc = JSON.parse(data)

    console.log(tc.tx.Message)

    var signed_tx = filecoin_signer.transactionSignLotus(tc.tx.Message, tc.pk)

    console.log(signed_tx)

    assert.deepStrictEqual(JSON.parse(signed_tx), tc.tx)
  })
})

describe('transactionSignRaw', function() {
  it('should sign transaction and return raw signature', function() {
    const child = dataWallet.childs[3]
    const tx = dataTxs[0]
    const example_key = MASTER_NODE.derivePath(child.path)

    let signature = filecoin_signer.transactionSignRaw(tx.transaction, example_key.privateKey.toString('base64'))
    signature = Buffer.from(signature)
    let message_digest = getDigest(Buffer.from(tx.cbor, 'hex'))

    // Signature representation is R, S & V
    console.log('Signature  :', signature.toString('hex'))
    console.log('Digest     :', message_digest.toString('hex'))
    console.log('Public key :', example_key.publicKey.toString('hex'))

    assert.strictEqual(
      true,
      // Remove the V value from the signature (last byte)
      secp256k1.ecdsaVerify(signature.slice(0, -1), message_digest, example_key.publicKey),
    )

    // Verify recovery id which is the last byte of the signature
    assert.strictEqual(0x00, signature[64])
  })
})

describe('verifySignature', function() {
  it('should verify signature', function() {
    const child = dataWallet.childs[3]
    const tx = dataTxs[0]
    let example_key = MASTER_NODE.derivePath(child.path)
    let message_digest = getDigest(Buffer.from(tx.cbor, 'hex'))

    // Get hex signature in the format (R,S)
    let signature = secp256k1.ecdsaSign(message_digest, example_key.privateKey)

    // Concat v value at the end of the signature
    let signatureRSV =
      Buffer.from(signature.signature).toString('hex') +
      Buffer.from([signature.recid]).toString('hex')

    console.log('RSV signature :', signatureRSV)
    console.log('CBOR Transaction hex :', tx.cbor)

    assert.strictEqual(filecoin_signer.verifySignature(signatureRSV, tx.cbor), true)
  })

  let itCall = it
  if (process.env.PURE_JS) {
    itCall = it.skip
  }

  itCall('verify BLS signature (1)', function() {
    const tc = dataTxs[4]

    const signed_tx = filecoin_signer.transactionSign(tc.message, Buffer.from(tc.sk, 'hex').toString('base64'))
    console.log(signed_tx)
    const raw_signature = filecoin_signer.transactionSignRaw(tc.message, Buffer.from(tc.sk, 'hex').toString('base64'))

    const hex_sig = Buffer.from(raw_signature).toString('hex')
    console.log(hex_sig)
    assert.strictEqual(hex_sig, tc.sig)

    const signature = Buffer.from(signed_tx.signature.data, 'base64')
    console.log(signature.toString('hex'))
    const tx = filecoin_signer.transactionSerialize(tc.message)
    const v = filecoin_signer.verifySignature(signature.toString('hex'), tx)
    console.log('v', v)

    assert.strictEqual(v, true)
  })

})

describeCall('SerializeParams', function() {
  /* Load params test data */
  let rawdata = fs.readFileSync('../../test_vectors/serialize_params.json')
  let data = JSON.parse(rawdata)

  for (let tc of data) {
    it(tc.description, function() {
      console.log(tc.params)
      let serialized_params = filecoin_signer.serializeParams(tc.params)

      assert.strictEqual(
        tc.serialized_params,
        Buffer.from(serialized_params).toString('base64'),
      )
    })
  }
})

describeCall('DeserializeParams', function() {
  /* Load params test data */
  let rawdata = fs.readFileSync('../../test_vectors/deserialize_params.json')
  let data = JSON.parse(rawdata)

  for (let tc of data) {
    it(tc.description, function() {
      if (tc.valid) {
        let params = filecoin_signer.deserializeParams(tc.serialized_params, tc.code_cid, tc.method)

        assert.deepStrictEqual(tc.params, params)
      } else {
        assert.throws(() => {
            filecoin_signer.deserializeParams(tc.serialized_params, tc.code_cid, tc.method)
          },
          new RegExp(tc.error),
        )
      }
    })
  }
})

describeCall('DeserializeConstructorParams', function() {
  /* Load params test data */
  let rawdata = fs.readFileSync('../../test_vectors/deserialize_constructor_params.json')
  let data = JSON.parse(rawdata)

  for (let tc of data) {
    it(tc.description, function() {
      if (tc.valid) {
        let params = filecoin_signer.deserializeConstructorParams(tc.serialized_params, tc.code_cid)

        assert.deepStrictEqual(tc.params, params)
      } else {
        assert.throws(() => {
            filecoin_signer.deserializeConstructorParams(tc.serialized_params, tc.code_cid)
          },
          new RegExp(tc.error),
        )
      }
    })
  }
})

describeCall('GetCid', function() {
  /* Load test data */
  let rawdata = fs.readFileSync('../../test_vectors/get_cid.json')
  let tc = JSON.parse(rawdata)

  it(tc.description, function() {
    let cid = filecoin_signer.getCid(tc.signed_message)

    assert(tc.valid)

    assert.strictEqual(tc.cid, cid)

  })
})

/* ------------------------------------------------------------------------------------------------- */

const bls_tests_vectors_path = '../generated_test_cases.json'
let rawBLSData = fs.readFileSync(bls_tests_vectors_path)
let jsonBLSData = JSON.parse(rawBLSData)

describeCall('BLS support', function() {

  for (let i = 0; i < jsonBLSData.length; i += 1) {
    let tc = jsonBLSData[i]

    it(`BLS signing test case n°${i}`, function() {
      var signed_tx = filecoin_signer.transactionSign(tc.message, Buffer.from(tc.sk, 'hex').toString('base64'))

      const signature = Buffer.from(signed_tx.signature.data, 'base64')

      // Signature representation is R, S & V
      console.log('Signature  :', signature.toString('hex'))
      console.log('Private key:', tc.sk)
      console.log('Public key :', tc.pk)

      assert.strictEqual(signature.length, 96)

      assert.strictEqual(signature.toString('hex'), tc.sig)

    })
  }
})

//////////////////////////////////////
// Parameterized tests
const tests_vectors_path = '../manual_testvectors.json'
let rawData = fs.readFileSync(tests_vectors_path)
let jsonData = JSON.parse(rawData)

describe('Transaction Serialization - Parameterized', function() {
  for (let i = 0; i < jsonData.length; i += 1) {
    let tc = jsonData[i]
    if (!tc.message.params) {
      tc.message['params'] = ''
    }

    if (tc.not_implemented) {
      // FIXME: cbor negative value
      continue
    }

    it('Create Transaction : ' + tc.description, () => {
      if (tc.valid) {
        // Valid doesn't throw
        try {
          var result = filecoin_signer.transactionSerialize(tc.message)
        } catch (e) {
          assert.match(e.message, /protocol not supported./)
          return
        }
        assert.strictEqual(tc.encoded_tx_hex, result)
      } else {
        // Not valid throw error
        // TODO: Add error type to manual_testvectors.json file
        assert.throws(
          () => filecoin_signer.transactionSerialize(tc.message),
          /Error/,
        )
      }
    })
  }
})

describe('Transaction Deserialization - Parameterized', function() {
  for (let i = 0; i < jsonData.length; i += 1) {
    let tc = jsonData[i]
    if (!tc.message.params) {
      tc.message['params'] = ''
    }

    if (tc.not_implemented) {
      // FIXME: Protocol 0 parsing not implemented in forest
      console.log('FIXME: Protocol 0 parsing not implemented in forest')
      continue
    }

    // Create test case for each
    it('Parse Transaction : ' + tc.description, () => {
      if (tc.valid) {
        try {
          var result = filecoin_signer.transactionParse(tc.encoded_tx_hex, tc.testnet)
        } catch (e) {
          assert.match(e.message, /protocol not supported./)
          return
        }
        assert.deepStrictEqual(tc.message, result)
      } else {
        // Not valid throw error
        // TODO: Add error type to manual_testvectors.json file
        assert.throws(
          () => filecoin_signer.transactionParse(tc.encoded_tx_hex, tc.testnet),
          /(error|^Error)/,
        )
      }
    })
  }
})
