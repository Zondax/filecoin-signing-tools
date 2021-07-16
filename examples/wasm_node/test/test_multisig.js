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
let rawdataTxs = fs.readFileSync('../../test_vectors/multisig.json')
let dataTxs = JSON.parse(rawdataTxs)

const MASTER_NODE = bip32.fromBase58(dataWallet.master_key)

let describeCall = describe
if (process.env.PURE_JS) {
  describeCall = describe.skip
}

describeCall('createMultisig', function() {
  it('should return a create multisig transaction', function() {
    const multisig_create = dataTxs.create

    let create_multisig_transaction = filecoin_signer.createMultisigWithFee(
      multisig_create.message.from,
      multisig_create.constructor_params.signers,
      multisig_create.message.value,
      multisig_create.constructor_params.num_approvals_threshold,
      multisig_create.message.nonce,
      multisig_create.constructor_params.unlock_duration.toString(),
      multisig_create.constructor_params.start_epoch.toString(),
      multisig_create.message.gaslimit.toString(),
      multisig_create.message.gasfeecap,
      multisig_create.message.gaspremium,
    )

    assert.deepStrictEqual(multisig_create.message, create_multisig_transaction)
  })

  it('should return a create multisig transaction with duration -1', function() {
    const multisig_create = dataTxs.create

    let create_multisig_transaction = filecoin_signer.createMultisigWithFee(
      multisig_create.message.from,
      multisig_create.constructor_params.signers,
      multisig_create.message.value,
      multisig_create.constructor_params.num_approvals_threshold,
      multisig_create.message.nonce,
      BigInt(-1).toString(),
      multisig_create.constructor_params.start_epoch.toString(),
      multisig_create.message.gaslimit.toString(),
      multisig_create.message.gasfeecap,
      multisig_create.message.gaspremium,
    )

    assert(create_multisig_transaction)
  })


  it('should return a serialized version of the create multisig transaction', function() {
    const multisig_create = dataTxs.create

    let serialized_create_multisig_transaction = filecoin_signer.transactionSerialize(multisig_create.message)

    assert.strictEqual(dataTxs.create.cbor, serialized_create_multisig_transaction)
  })

  it('should return a signature of the create multisig transaction', function() {
    const multisig_create = dataTxs.create

    let child = MASTER_NODE.derivePath('44\'/1\'/0/0/0')
    let privateKey = child.privateKey.toString('base64')


    let signature = filecoin_signer.transactionSignLotus(multisig_create.message, privateKey)

    assert(JSON.parse(signature).Signature)
  })

  it('should fail because of bigint', function() {
    const multisig_create = dataTxs.create

    assert.throws(
      () => filecoin_signer.createMultisigWithFee(
        multisig_create.message.from,
        multisig_create.constructor_params.signers,
        multisig_create.message.value,
        multisig_create.constructor_params.num_approvals_threshold,
        multisig_create.message.nonce,
        multisig_create.constructor_params.unlock_duration.toString(),
        multisig_create.constructor_params.start_epoch.toString(),
        '18446744073709551617',
        multisig_create.message.gasfeecap,
        multisig_create.message.gaspremium,
      ),
      /(number too large to fit in target type)/,
    )

  })

})

describeCall('proposeMultisig', function() {
  it('should return a propose multisig transaction', function() {
    const multisig_propose = dataTxs.propose

    let propose_multisig_transaction = filecoin_signer.proposeMultisigWithFee(
      multisig_propose.message.to,
      multisig_propose.proposal_params.to,
      multisig_propose.message.from,
      multisig_propose.proposal_params.value,
      multisig_propose.message.nonce,
      multisig_propose.message.gaslimit.toString(),
      multisig_propose.message.gasfeecap,
      multisig_propose.message.gaspremium,
      multisig_propose.proposal_params.method,
      multisig_propose.proposal_params.params,
    )

    assert.deepStrictEqual(multisig_propose.message, propose_multisig_transaction)
  })

  it('should return a serialized version of the propose multisig transaction', function() {
    const multisig_propose = dataTxs.propose

    let serialized_propose_multisig_transaction = filecoin_signer.transactionSerialize(multisig_propose.message)

    assert.strictEqual(multisig_propose.cbor, serialized_propose_multisig_transaction)
  })

  it('should return a signature of the create multisig transaction', function() {
    const multisig_propose = dataTxs.propose

    let child = MASTER_NODE.derivePath('44\'/1\'/0/0/0')
    let privateKey = child.privateKey.toString('base64')

    let signature = filecoin_signer.transactionSignLotus(multisig_propose.message, privateKey)

    console.log(signature)

    assert(JSON.parse(signature).Signature)
  })
})

describeCall('approveMultisig', function() {
  it('should return an approval multisig transaction', function() {
    const multisig_approve = dataTxs.approve

    let approve_multisig_transaction = filecoin_signer.approveMultisigWithFee(
      multisig_approve.message.to,
      multisig_approve.approval_params.txn_id,
      multisig_approve.proposal_params.requester,
      multisig_approve.proposal_params.to,
      multisig_approve.proposal_params.value,
      multisig_approve.message.from,
      multisig_approve.message.nonce,
      multisig_approve.message.gaslimit.toString(),
      multisig_approve.message.gasfeecap,
      multisig_approve.message.gaspremium,
    )

    assert.deepStrictEqual(multisig_approve.message, approve_multisig_transaction)
  })

  it('should return a serialized version of the approval multisig transaction', function() {
    const multisig_approve = dataTxs.approve

    let serialized_approve_multisig_transaction = filecoin_signer.transactionSerialize(multisig_approve.message)


    assert.strictEqual(multisig_approve.cbor, serialized_approve_multisig_transaction)
  })

  it('should return a signature of the approve multisig transaction', function() {
    const multisig_approve = dataTxs.approve

    let child = MASTER_NODE.derivePath('44\'/1\'/0/0/0')
    let privateKey = child.privateKey.toString('base64')

    let signature = filecoin_signer.transactionSignLotus(multisig_approve.message, privateKey)

    assert(JSON.parse(signature).Signature)
  })
})

describeCall('cancelMultisig', function() {
  it('should return a cancel multisig transaction', function() {
    const multisig_cancel = dataTxs.cancel

    let cancel_multisig_transaction = filecoin_signer.cancelMultisigWithFee(
      multisig_cancel.message.to,
      multisig_cancel.cancel_params.txn_id,
      multisig_cancel.proposal_params.requester,
      multisig_cancel.proposal_params.to,
      multisig_cancel.proposal_params.value,
      multisig_cancel.message.from,
      multisig_cancel.message.nonce,
      multisig_cancel.message.gaslimit.toString(),
      multisig_cancel.message.gasfeecap,
      multisig_cancel.message.gaspremium,
    )

    assert.deepStrictEqual(multisig_cancel.message, cancel_multisig_transaction)
  })

  it('should return a serialized version of the cancel multisig transaction', function() {
    const multisig_cancel = dataTxs.cancel

    let serialized_cancel_multisig_transaction = filecoin_signer.transactionSerialize(multisig_cancel.message)

    assert.strictEqual(multisig_cancel.cbor, serialized_cancel_multisig_transaction)
  })

  it('should return a signature of the cancel multisig transaction', function() {
    const multisig_cancel = dataTxs.cancel

    let child = MASTER_NODE.derivePath('44\'/1\'/0/0/0')
    let privateKey = child.privateKey.toString('base64')

    let signature = filecoin_signer.transactionSignLotus(multisig_cancel.message, privateKey)

    assert(JSON.parse(signature).Signature)
  })
})
