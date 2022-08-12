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

    let constructor_params = { 
      Signers: multisig_create.constructor_params["Signers"],
      NumApprovalsThreshold: multisig_create.constructor_params["NumApprovalsThreshold"],
      UnlockDuration: multisig_create.constructor_params["UnlockDuration"],
      StartEpoch: multisig_create.constructor_params["StartEpoch"]
    }

    console.log(constructor_params)

    let params = {
      CodeCid: 'bafk2bzacebhldfjuy4o5v7amrhp5p2gzv2qo5275jut4adnbyp56fxkwy5fag',
      ConstructorParams: Buffer.from(filecoin_signer.serializeParams(constructor_params)).toString('base64')
    }

    console.log(params)

    let serialized_params = filecoin_signer.serializeParams(params);

    console.log(Buffer.from(serialized_params).toString('base64'))

    let create_multisig_transaction = {
      To: multisig_create.message["To"],
      From: multisig_create.message["From"],
      Nonce: multisig_create.message["Nonce"],
      Value: multisig_create.message["Value"],
      GasLimit: multisig_create.message["GasLimit"],
      GasFeeCap: multisig_create.message["GasFeeCap"],
      GasPremium: multisig_create.message["GasPremium"],
      Method: multisig_create.message["Method"],
      Params: Buffer.from(serialized_params).toString('base64')
    }

    /*let create_multisig_transaction = filecoin_signer.createMultisigWithFee(
      multisig_create.message["From"],
      multisig_create.constructor_params["Signers"],
      multisig_create.message["Value"],
      multisig_create.constructor_params["NumApprovalsThreshold"],
      multisig_create.message["Nonce"],
      multisig_create.constructor_params["UnlockDuration"].toString(),
      multisig_create.constructor_params["StartEpoch"].toString(),
      multisig_create.message["GasLimit"].toString(),
      multisig_create.message["GasFeeCap"],
      multisig_create.message["GasPremium"],
      "mainnet"
    )*/

    assert.deepStrictEqual(create_multisig_transaction, multisig_create.message)
  })

  it('should return a create multisig transaction with duration -1', function() {
    const multisig_create = dataTxs.create

    let create_multisig_transaction = filecoin_signer.createMultisigWithFee(
      multisig_create.message["From"],
      multisig_create.constructor_params["Signers"],
      multisig_create.message["Value"],
      multisig_create.constructor_params["NumApprovalsThreshold"],
      multisig_create.message["Nonce"],
      BigInt(-1).toString(),
      multisig_create.constructor_params["StartEpoch"].toString(),
      multisig_create.message["GasLimit"].toString(),
      multisig_create.message["GasFeeCap"],
      multisig_create.message["GasPremium"],
      "mainnet"
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
        multisig_create.message["From"],
        multisig_create.constructor_params["Signers"],
        multisig_create.message["Value"],
        multisig_create.constructor_params["NumApprovalsThreshold"],
        multisig_create.message["Nonce"],
        multisig_create.constructor_params["UnlockDuration"].toString(),
        multisig_create.constructor_params["StartEpoch"].toString(),
        '18446744073709551617',
        multisig_create.message["GasFeeCap"],
        multisig_create.message["GasPremium"],
        "mainnet"
      ),
      /(number too large to fit in target type)/,
    )

  })

})

describeCall('proposeMultisig', function() {
  it('should return a propose multisig transaction', function() {
    const multisig_propose = dataTxs.propose

    let propose_multisig_transaction = filecoin_signer.proposeMultisigWithFee(
      multisig_propose.message["To"],
      multisig_propose.proposal_params["To"],
      multisig_propose.message["From"],
      multisig_propose.proposal_params["Value"],
      multisig_propose.message["Nonce"],
      multisig_propose.message["GasLimit"].toString(),
      multisig_propose.message["GasFeeCap"],
      multisig_propose.message["GasPremium"],
      multisig_propose.proposal_params["Method"],
      multisig_propose.proposal_params["Params"],
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
      multisig_approve.message["To"],
      multisig_approve.approval_params["TxnID"],
      multisig_approve.proposal_params["Requester"],
      multisig_approve.proposal_params["To"],
      multisig_approve.proposal_params["Value"],
      multisig_approve.message["From"],
      multisig_approve.message["Nonce"],
      multisig_approve.message["GasLimit"].toString(),
      multisig_approve.message["GasFeeCap"],
      multisig_approve.message["GasPremium"],
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
      multisig_cancel.message["To"],
      multisig_cancel.cancel_params["TxnID"],
      multisig_cancel.proposal_params["Requester"],
      multisig_cancel.proposal_params["To"],
      multisig_cancel.proposal_params["Value"],
      multisig_cancel.message["From"],
      multisig_cancel.message["Nonce"],
      multisig_cancel.message["GasLimit"].toString(),
      multisig_cancel.message["GasFeeCap"],
      multisig_cancel.message["GasPremium"],
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

describeCall('serializeParams reported cases', function() {
  it('newThreshold', function () {
    const innerParams = {
      NewThreshold: 2
    }

    const result = filecoin_signer.serializeParams(innerParams)

    assert.strictEqual(Buffer.from(result).toString('hex'), '8102')
  })
})