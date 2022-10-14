import assert from 'assert'
import secp256k1 from 'secp256k1'
import fs from 'fs'

import * as utils from './utils.js'

let rawdata = fs.readFileSync('../../test_vectors/utils.json')
let data = JSON.parse(rawdata)

describe('Test for utils.js', function() {
  it('cidBytes', function() {
    const message = Buffer.from(data.cid_bytes.cbor_message, 'hex')


    // Calculate message digest
    // cid = prefix + blake2b-256(tx)
    // digest = blake2-256( cid )
    const calculatedCid = utils.getCID(message)
    assert.strictEqual(calculatedCid.toString('hex'), data.cid_bytes.cid)
  })

  for (let i in data.msg_digest) {
    it(`msgDigest n°${i}`, function() {
      const message = Buffer.from(data.msg_digest[i].cbor_message, 'hex')

      const msgDigest = utils.getDigest(message)
      assert.strictEqual(msgDigest.toString('hex'), data.msg_digest[i].digest)
    })
  }

  it('publicFromPrivate', function() {
    const privateKey = Buffer.from(data.public_from_private.private, 'hex')

    const pubkey = new Uint8Array(65)
    secp256k1.publicKeyCreate(privateKey, false, pubkey)

    assert.strictEqual(Buffer.from(pubkey).toString('hex'), data.public_from_private.public)
  })

  it('signature', function() {
    const privateKey = Buffer.from(data.signature_test.private, 'hex')
    const message = Buffer.from(data.signature_test.message, 'hex')

    const pubkey = new Uint8Array(65)
    secp256k1.publicKeyCreate(privateKey, false, pubkey)

    const digest = utils.getDigest(message)
    const signature = secp256k1.ecdsaSign(digest, privateKey)

    const sigStr =
      Buffer.from(signature.signature).toString('hex') + Buffer.from([signature.recid]).toString('hex')

    assert.strictEqual(sigStr, data.signature_test.signature)
  })
})
