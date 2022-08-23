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

    let params = {
      CodeCid: 'bafk2bzacebhldfjuy4o5v7amrhp5p2gzv2qo5275jut4adnbyp56fxkwy5fag',
      ConstructorParams: Buffer.from(filecoin_signer.serializeParams(constructor_params)).toString('base64')
    }

    let serialized_params = filecoin_signer.serializeParams(params);

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

    assert.deepStrictEqual(create_multisig_transaction, multisig_create.message)
  })

  it('should return a create multisig transaction with duration -1', function() {
    const multisig_create = dataTxs.create

    let constructor_params = { 
      Signers: multisig_create.constructor_params["Signers"],
      NumApprovalsThreshold: multisig_create.constructor_params["NumApprovalsThreshold"],
      UnlockDuration: -1,
      StartEpoch: multisig_create.constructor_params["StartEpoch"]
    }

    let serialized_params = filecoin_signer.serializeParams(constructor_params);

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

    let constructor_params = { 
      Signers: multisig_create.constructor_params["Signers"],
      NumApprovalsThreshold: multisig_create.constructor_params["NumApprovalsThreshold"],
      UnlockDuration: 18446744073709551617,
      StartEpoch: multisig_create.constructor_params["StartEpoch"]
    }

    assert.throws(
      () => filecoin_signer.serializeParams(constructor_params),
      /(Error parsing parameters: data did not match any variant of untagged enum MessageParams)/,
    )

  })
})

describeCall('proposeMultisig', function() {
  it('should return a propose multisig transaction', function() {
    const multisig_propose = dataTxs.propose

    let propose_params = { 
      To: multisig_propose.proposal_params["To"],
      Value: multisig_propose.proposal_params["Value"],
      Method: multisig_propose.proposal_params["Method"],
      Params: multisig_propose.proposal_params["Params"]
    }

    let serialized_params = filecoin_signer.serializeParams(propose_params);

    let propose_multisig_transaction = {
      To: multisig_propose.message["To"],
      From: multisig_propose.message["From"],
      Nonce: multisig_propose.message["Nonce"],
      Value: multisig_propose.message["Value"],
      GasLimit: multisig_propose.message["GasLimit"],
      GasFeeCap: multisig_propose.message["GasFeeCap"],
      GasPremium: multisig_propose.message["GasPremium"],
      Method: multisig_propose.message["Method"],
      Params: Buffer.from(serialized_params).toString('base64')
    }

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

    let proposal_params = {
      Requester: multisig_approve.proposal_params["Requester"],
      To: multisig_approve.proposal_params["To"],
      Value: multisig_approve.proposal_params["Value"],
      Method: multisig_approve.proposal_params["Method"],
      Params: multisig_approve.proposal_params["Params"]
    }

    console.log(proposal_params)
    const proposalHash = filecoin_signer.computeProposalHash(proposal_params)

    let approve_params = {
      ID: multisig_approve.approval_params["TxnID"],
      ProposalHash: proposalHash.toString('base64')
    }

    console.log(approve_params)

    let serialized_params = filecoin_signer.serializeParams(approve_params);

    let approve_multisig_transaction = {
      To: multisig_approve.message["To"],
      From: multisig_approve.message["From"],
      Nonce: multisig_approve.message["Nonce"],
      Value: multisig_approve.message["Value"],
      GasLimit: multisig_approve.message["GasLimit"],
      GasFeeCap: multisig_approve.message["GasFeeCap"],
      GasPremium: multisig_approve.message["GasPremium"],
      Method: multisig_approve.message["Method"],
      Params: Buffer.from(serialized_params).toString('base64')
    }

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

    let proposal_params = {
      Requester: multisig_cancel.proposal_params["Requester"],
      To: multisig_cancel.proposal_params["To"],
      Value: multisig_cancel.proposal_params["Value"],
      Method: multisig_cancel.proposal_params["Method"],
      Params: multisig_cancel.proposal_params["Params"]
    }

    const proposalHash = filecoin_signer.computeProposalHash(proposal_params)

    let cancel_params = {
      ID: multisig_cancel.cancel_params["TxnID"],
      ProposalHash: proposalHash.toString('base64')
    }

    let serialized_params = filecoin_signer.serializeParams(cancel_params);

    let cancel_multisig_transaction = {
      To: multisig_cancel.message["To"],
      From: multisig_cancel.message["From"],
      Nonce: multisig_cancel.message["Nonce"],
      Value: multisig_cancel.message["Value"],
      GasLimit: multisig_cancel.message["GasLimit"],
      GasFeeCap: multisig_cancel.message["GasFeeCap"],
      GasPremium: multisig_cancel.message["GasPremium"],
      Method: multisig_cancel.message["Method"],
      Params: Buffer.from(serialized_params).toString('base64')
    }

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