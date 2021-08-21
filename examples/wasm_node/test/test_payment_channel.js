// Test twice for wasm version and pure js version
if (process.env.PURE_JS) {
  var filecoin_signer = require('@zondax/filecoin-signing-tools/js')
} else {
  var filecoin_signer = require('@zondax/filecoin-signing-tools')
}

const bip39 = require('bip39')
const bip32 = require('bip32')
const { getDigest, getDigestVoucher, blake2b256 } = require('./utils')
const secp256k1 = require('secp256k1')
const fs = require('fs')
const assert = require('assert')
const cbor = require('ipld-dag-cbor').util

/* Load wallet test data */
let rawdataWallet = fs.readFileSync('../../test_vectors/wallet.json')
let dataWallet = JSON.parse(rawdataWallet)

/* Load multisig test data */
let rawdataTxs = fs.readFileSync('../../test_vectors/payment_channel.json')
let dataTxs = JSON.parse(rawdataTxs)

/* Load voucher test data */
let rawdataVoucher = fs.readFileSync('../../test_vectors/voucher.json')
let dataVoucher = JSON.parse(rawdataVoucher)

const MASTER_NODE = bip32.fromBase58(dataWallet.master_key)

let describeCall = describe
if (process.env.PURE_JS) {
  describeCall = describe.skip
}

describeCall('createPymtChan', function() {
  it('create payment channel transaction and sign (SECP256K1)', function() {
    let paymentchannel_create = dataTxs.creation.secp256k1
    let recoveredKey = filecoin_signer.keyRecover(paymentchannel_create.private_key, true)

    let create_pymtchan = filecoin_signer.createPymtChanWithFee(
      paymentchannel_create.constructor_params.from,
      paymentchannel_create.constructor_params.to,
      paymentchannel_create.message.value,
      paymentchannel_create.message.nonce,
      paymentchannel_create.message.gaslimit.toString(),
      paymentchannel_create.message.gasfeecap,
      paymentchannel_create.message.gaspremium,
    )

    let signedMessage = filecoin_signer.transactionSignLotus(create_pymtchan, paymentchannel_create.private_key)
    signedMessage = JSON.parse(signedMessage)


    try {
      const messageForCid = {
        "message": {
          "to": signedMessage.Message.To,
          "from": signedMessage.Message.From,
          "nonce": +signedMessage.Message.Nonce,
          "value": signedMessage.Message.Value,
          "gas_limit": +signedMessage.Message.GasLimit,
          "gas_fee_cap": signedMessage.Message.GasFeeCap,
          "gas_premium": signedMessage.Message.GasPremium,
          "method": +signedMessage.Message.Method,
          "params": signedMessage.Message.Params
        },
        "signature": {
          "type": 1,
          "data": signedMessage.Signature.Data
        }
      }
      console.log('messageForCid: ', messageForCid);
      const cid = filecoin_signer.getCid(messageForCid);
      console.log('cid: ', cid);
    } catch (error) {
      console.log('getCid error: ', error)
    }

    assert.deepStrictEqual(paymentchannel_create.message.params, create_pymtchan.params)

    const signature = Buffer.from(signedMessage.Signature.Data, 'base64')

    const serializedMessage = filecoin_signer.transactionSerialize(create_pymtchan)

    const messageDigest = getDigest(Buffer.from(serializedMessage, 'hex'))

    // Remove the V value from the signature (last byte)
    assert(secp256k1.ecdsaVerify(signature.slice(0, -1), messageDigest, recoveredKey.public_raw))

  })
  it('create payment channel transaction and sign (BLS)', function() {
    let paymentchannel_create = dataTxs.creation.bls

    let create_pymtchan = filecoin_signer.createPymtChanWithFee(
      paymentchannel_create.constructor_params.from,
      paymentchannel_create.constructor_params.to,
      paymentchannel_create.message.value,
      paymentchannel_create.message.nonce,
      paymentchannel_create.message.gaslimit.toString(),
      paymentchannel_create.message.gasfeecap,
      paymentchannel_create.message.gaspremium,
    )

    let signedMessage = filecoin_signer.transactionSignLotus(create_pymtchan, paymentchannel_create.private_key)
    signedMessage = JSON.parse(signedMessage)

    try {
      const messageForCid = {
        "message": {
          "to": signedMessage.Message.To,
          "from": signedMessage.Message.From,
          "nonce": +signedMessage.Message.Nonce,
          "value": signedMessage.Message.Value,
          "gas_limit": +signedMessage.Message.GasLimit,
          "gas_fee_cap": signedMessage.Message.GasFeeCap,
          "gas_premium": signedMessage.Message.GasPremium,
          "method": +signedMessage.Message.Method,
          "params": signedMessage.Message.Params
        },
        "signature": {
          "type": 1,
          "data": signedMessage.Signature.Data
        }
      }
      console.log('messageForCid: ', messageForCid);
      const cid = filecoin_signer.getCid(messageForCid);
      console.log('cid: ', cid);
    } catch (error) {
      console.log('getCid error: ', error)
    }

    assert.deepStrictEqual(paymentchannel_create.message.params, create_pymtchan.params)

    // TODO: verify signature
    // but with which lib ?

  })
})

describeCall('updatePymtChan', function() {
  it('update payment channel transaction and sign', function() {
    let paymentchannel_update = dataTxs.update.secp256k1
    let recoveredKey = filecoin_signer.keyRecover(paymentchannel_update.private_key, true)

    let update_pymtchan = filecoin_signer.updatePymtChanWithFee(
      paymentchannel_update.message.to,
      paymentchannel_update.message.from,
      paymentchannel_update.voucher_base64,
      paymentchannel_update.message.nonce,
      paymentchannel_update.message.gaslimit.toString(),
      paymentchannel_update.message.gasfeecap,
      paymentchannel_update.message.gaspremium,
    )

    let signedMessage = filecoin_signer.transactionSignLotus(update_pymtchan, paymentchannel_update.private_key)
    signedMessage = JSON.parse(signedMessage)

    assert.deepStrictEqual(paymentchannel_update.message, update_pymtchan)

    const signature = Buffer.from(signedMessage.Signature.Data, 'base64')

    const serializedMessage = filecoin_signer.transactionSerialize(update_pymtchan)

    const messageDigest = getDigest(Buffer.from(serializedMessage, 'hex'))

    // Remove the V value from the signature (last byte)
    assert(secp256k1.ecdsaVerify(signature.slice(0, -1), messageDigest, recoveredKey.public_raw))
  })
})

describeCall('settlePymtChan', function() {
  it('settle payment channel and sign', function() {
    let paymentchannel_settle = dataTxs.settle.secp256k1
    let recoveredKey = filecoin_signer.keyRecover(paymentchannel_settle.private_key, true)


    let settle_pymtchan = filecoin_signer.settlePymtChanWithFee(
      paymentchannel_settle.message.to,
      paymentchannel_settle.message.from,
      paymentchannel_settle.message.nonce,
      paymentchannel_settle.message.gaslimit.toString(),
      paymentchannel_settle.message.gasfeecap,
      paymentchannel_settle.message.gaspremium,
    )

    let signedMessage = filecoin_signer.transactionSignLotus(settle_pymtchan, paymentchannel_settle.private_key)
    signedMessage = JSON.parse(signedMessage)

    assert.deepStrictEqual(paymentchannel_settle.message, settle_pymtchan)

    const signature = Buffer.from(signedMessage.Signature.Data, 'base64')
    const serializedMessage = filecoin_signer.transactionSerialize(settle_pymtchan)
    const messageDigest = getDigest(Buffer.from(serializedMessage, 'hex'))

    // Remove the V value from the signature (last byte)
    assert(secp256k1.ecdsaVerify(signature.slice(0, -1), messageDigest, recoveredKey.public_raw))
  })
})

describeCall('collectPymtChan', function() {
  it('collect payment channel and sign', function() {
    let paymentchannel_collect = dataTxs.collect.secp256k1
    let recoveredKey = filecoin_signer.keyRecover(paymentchannel_collect.private_key, true)

    let collect_pymtchan = filecoin_signer.collectPymtChanWithFee(
      paymentchannel_collect.message.to,
      paymentchannel_collect.message.from,
      paymentchannel_collect.message.nonce,
      paymentchannel_collect.message.gaslimit.toString(),
      paymentchannel_collect.message.gasfeecap,
      paymentchannel_collect.message.gaspremium,
    )

    let signedMessage = filecoin_signer.transactionSignLotus(collect_pymtchan, paymentchannel_collect.private_key)
    signedMessage = JSON.parse(signedMessage)

    assert.deepStrictEqual(paymentchannel_collect.message, collect_pymtchan)

    const signature = Buffer.from(signedMessage.Signature.Data, 'base64')
    const serializedMessage = filecoin_signer.transactionSerialize(collect_pymtchan)
    const messageDigest = getDigest(Buffer.from(serializedMessage, 'hex'))

    // Remove the V value from the signature (last byte)
    assert(secp256k1.ecdsaVerify(signature.slice(0, -1), messageDigest, recoveredKey.public_raw))
  })
})

describeCall('createVoucher', function() {
  it('create a voucher', function() {
    let voucher_expected = dataVoucher.sign.voucher

    const voucher = filecoin_signer.createVoucher(
      voucher_expected.payment_channel_address,
      voucher_expected.time_lock_min.toString(),
      voucher_expected.time_lock_max.toString(),
      voucher_expected.amount,
      voucher_expected.lane.toString(),
      voucher_expected.nonce,
      voucher_expected.min_settle_height.toString(),
    )

    assert(voucher)
  })
})

describeCall('signVoucher', function() {
  it('sign a voucher', function() {
    let voucher_expected = dataVoucher.sign.voucher

    let child = MASTER_NODE.derivePath('44\'/1\'/0/0/0')
    let privateKey = child.privateKey.toString('base64')

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true)

    const voucher = filecoin_signer.createVoucher(
      voucher_expected.payment_channel_address,
      voucher_expected.time_lock_min.toString(),
      voucher_expected.time_lock_max.toString(),
      voucher_expected.amount,
      voucher_expected.lane.toString(),
      voucher_expected.nonce,
      voucher_expected.min_settle_height.toString(),
    )

    const signedVoucher = filecoin_signer.signVoucher(voucher, privateKey)

    let signature = cbor.deserialize(Buffer.from(signedVoucher, 'base64'))[10]

    signature = signature.slice(1, -1)

    const messageDigest = getDigestVoucher(Buffer.from(voucher, 'base64'))

    assert(secp256k1.ecdsaVerify(signature, messageDigest, recoveredKey.public_raw))
  })

})

describeCall('verifyVoucherSignature', function() {
  it('should return true', function() {
    let voucher = dataVoucher.verify

    assert(filecoin_signer.verifyVoucherSignature(voucher.signed_voucher_base64, voucher.address_signer))
  })
})
