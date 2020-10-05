// Test twice for wasm version and pure js version
if (process.env.PURE_JS) {
  var filecoin_signer = require('@zondax/filecoin-signing-tools/js');
} else {
  var filecoin_signer = require('@zondax/filecoin-signing-tools');
}

const bip39 = require('bip39');
const bip32 = require('bip32');
const {getDigest, getDigestVoucher, blake2b256} = require('./utils');
const secp256k1 = require('secp256k1');
const fs = require('fs');
const assert = require('assert');
const cbor = require("ipld-dag-cbor").util;
const { 
  EXAMPLE_MNEMONIC,
  EXAMPLE_CBOR_TX,
  EXAMPLE_ADDRESS_MAINNET,
  EXAMPLE_TRANSACTION,
  EXAMPLE_TRANSACTION_MAINNET,
  MASTER_KEY,
  MASTER_NODE,
} = require('./constants.js');

let describeCall = describe;
if (process.env.PURE_JS) { describeCall = describe.skip }

describeCall("createMultisig", function() {
  it("should return a create multisig transaction", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let addresses = [recoveredKey.address,"t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"];
    let sender_address = recoveredKey.address;

    let constructor_params = {
      signers: addresses,
      num_approvals_threshold: 1,
      unlock_duration: 0,
    };

    let exec_params = {
      code_cid: 'fil/1/multisig',
      constructor_params: Buffer.from(filecoin_signer.serializeParams(constructor_params)).toString('base64'),
    };

    let expected = {
      to: 't01',
      from: recoveredKey.address,
      nonce: 1,
      value: '1000',
      gaslimit: 1000000,
      gasfeecap: '2500',
      gaspremium: '2500',
      method: 2,
      params: Buffer.from(filecoin_signer.serializeParams(exec_params)).toString('base64')
    };

    let create_multisig_transaction = filecoin_signer.createMultisig(sender_address, addresses, "1000", 1, 1, BigInt(0), "1000000", "2500", "2500");

    console.log(create_multisig_transaction);

    assert.deepStrictEqual(expected, create_multisig_transaction);
  });

  it("should return a create multisig transaction with duration -1", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let addresses = [recoveredKey.address,"t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"];
    let sender_address = recoveredKey.address;

    let constructor_params = {
      signers: addresses,
      num_approvals_threshold: 1,
      unlock_duration: -1,
    };

    let exec_params = {
      code_cid: 'fil/1/multisig',
      constructor_params: Buffer.from(filecoin_signer.serializeParams(constructor_params)).toString('base64'),
    };

    let expected = {
      to: 't01',
      from: recoveredKey.address,
      nonce: 1,
      value: '1000',
      gaslimit: 1000000,
      gasfeecap: '2500',
      gaspremium: '2500',
      method: 2,
      params: Buffer.from(filecoin_signer.serializeParams(exec_params)).toString('base64')
    };

    let create_multisig_transaction = filecoin_signer.createMultisig(sender_address, addresses, "1000", 1, 1, BigInt(-1), "1000000", "2500", "2500");

    console.log(create_multisig_transaction);

    assert.deepStrictEqual(expected, create_multisig_transaction);
  });


  it("should return a serialized version of the create multisig transaction", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let addresses = [recoveredKey.address,"t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"];
    let sender_address = recoveredKey.address;
    let expected = "8A004200015501DFE49184D46ADC8F89D44638BEB45F78FCAD259001430003E81A000F4240430009C4430009C402584982D82A53000155000E66696C2F312F6D756C7469736967583083825501DFE49184D46ADC8F89D44638BEB45F78FCAD259055011EAF1C8A4BBFEEB0870B1745B1F57503470B71160100".toLowerCase();

    let create_multisig_transaction = filecoin_signer.createMultisig(sender_address, addresses, "1000", 1, 1, BigInt(0), "1000000", "2500", "2500");

    let serialized_create_multisig_transaction = filecoin_signer.transactionSerialize(create_multisig_transaction);

    console.log(serialized_create_multisig_transaction);

    assert.strictEqual(expected, serialized_create_multisig_transaction);
  });

  it("should return a signature of the create multisig transaction", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let addresses = [recoveredKey.address,"t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"];
    let sender_address = recoveredKey.address;

    let expected = {
      "Message":{
        "From":recoveredKey.address,
        "GasLimit":1000000,
        "GasFeeCap":"2500",
        "GasPremium":"2500",
        "Method":2,
        "Nonce":1,
        "Params":"gtgqUwABVQAOZmlsLzEvbXVsdGlzaWdYMIOCVQHf5JGE1Grcj4nURji+tF94/K0lkFUBHq8ciku/7rCHCxdFsfV1A0cLcRYBAA==",
        "To":"t01",
        "Value":"1000"
      },
      "Signature":{
        "Data":"8pj9RPIe5qC6kQAfQN5s9EO4uj1TnyNvOyxRylFMWq4axjBpbu7/GfKnhpWx5OX/RMLj8N6905yPGyY+Rh7GYwE=",
        "Type":1
      }
    }

    let create_multisig_transaction = filecoin_signer.createMultisig(sender_address, addresses, "1000", 1, 1, BigInt(0), "1000000", "2500", "2500");

    let signature = filecoin_signer.transactionSignLotus(create_multisig_transaction, privateKey);

    console.log(signature);

    assert.deepStrictEqual(expected, JSON.parse(signature));
  });
})

describeCall("proposeMultisig", function() {
  it("should return a propose multisig transaction", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let to_address = recoveredKey.address;
    let from_address = recoveredKey.address;

    let params = {
      to: recoveredKey.address,
      value: '1000',
      method: 0,
      params: ''
    };

    let params_base64 = Buffer.from(filecoin_signer.serializeParams(params)).toString('base64');

    let expected = {
      to: 't01004',
      from: recoveredKey.address,
      nonce: 1,
      value: '0',
      gaslimit: 1000000,
      gasfeecap: '2500',
      gaspremium: '2500',
      method: 2,
      params: params_base64
    }

    let propose_multisig_transaction = filecoin_signer.proposeMultisig("t01004", to_address, from_address, "1000", 1, "1000000", "2500", "2500");

    console.log(propose_multisig_transaction);

    assert.deepStrictEqual(expected, propose_multisig_transaction);
  });

  it("should return a serialized version of the propose multisig transaction", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let to_address = recoveredKey.address;
    let from_address = recoveredKey.address;

    let expected = "8a004300ec075501dfe49184d46adc8f89d44638beb45f78fcad259001401a000f4240430009c4430009c402581d845501dfe49184d46adc8f89d44638beb45f78fcad2590430003e80040";

    let propose_multisig_transaction = filecoin_signer.proposeMultisig("t01004", to_address, from_address, "1000", 1, "1000000", "2500", "2500");

    let serialized_propose_multisig_transaction = filecoin_signer.transactionSerialize(propose_multisig_transaction);

    console.log(serialized_propose_multisig_transaction);

    assert.strictEqual(expected, serialized_propose_multisig_transaction);
  });

  it("should return a signature of the create multisig transaction", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let to_address = recoveredKey.address;
    let from_address = recoveredKey.address;

    let expected = {
      "Message":{
        "From":recoveredKey.address,
        "GasLimit":1000000,
        "GasPremium":"2500",
        "GasFeeCap":"2500",
        "Method":2,
        "Nonce":1,
        "Params":"hFUB3+SRhNRq3I+J1EY4vrRfePytJZBDAAPoAEA=",
        "To":"t01004",
        "Value":"0"
      },
      "Signature":{
        "Data":"2bXhOIt6j7FM3jppLghaB29ZPrRSYjOEpz/2ZxVQQz09nC/Nlasnz4Eff6Ii5FIMd8bl7Z9ZcadhT9r+jqkN7wE=",
        "Type":1
      }
    }

    let propose_multisig_transaction = filecoin_signer.proposeMultisig("t01004", to_address, from_address, "1000", 1, "1000000", "2500", "2500");

    let signature = filecoin_signer.transactionSignLotus(propose_multisig_transaction, privateKey);

    console.log(signature);

    assert.deepStrictEqual(expected, JSON.parse(signature));
  });
})

describeCall("approveMultisig", function() {
  it("should return an approval multisig transaction", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let to_address = recoveredKey.address;
    let from_address = recoveredKey.address;
    let proposer_address = recoveredKey.address;

    let proposal_params = {
      requester: recoveredKey.address,
      to: recoveredKey.address,
      value: '1000',
      method: 0,
      params: ''
    };

    let txn_id_params = {
      txn_id: 1234,
      proposal_hash_data: Buffer.from(blake2b256(filecoin_signer.serializeParams(proposal_params))).toString('base64')
    }

    let expected = {
      to: 't01004',
      from: recoveredKey.address,
      nonce: 1,
      value: '0',
      gaslimit: 1000000,
      gasfeecap: '2500',
      gaspremium: '2500',
      method: 3,
      params: Buffer.from(filecoin_signer.serializeParams(txn_id_params)).toString('base64')
    }

    let approve_multisig_transaction = filecoin_signer.approveMultisig("t01004", 1234, proposer_address, to_address, "1000", to_address, 1, "1000000", "2500", "2500");

    console.log(approve_multisig_transaction);

    assert.deepStrictEqual(expected, approve_multisig_transaction);
  });

  it("should return a serialized version of the approval multisig transaction", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let to_address = recoveredKey.address;
    let from_address = recoveredKey.address;
    let proposer_address = recoveredKey.address;

    let expected = "8a004300ec075501dfe49184d46adc8f89d44638beb45f78fcad259001401a000f4240430009c4430009c4035826821904d25820fab4c2e272e30fd1de8bed36c39637c1be941e16dd92edae0f54b6067cff42ff";

    let approve_multisig_transaction = filecoin_signer.approveMultisig("t01004", 1234, proposer_address, to_address, "1000", to_address, 1, "1000000", "2500", "2500");

    let serialized_approve_multisig_transaction = filecoin_signer.transactionSerialize(approve_multisig_transaction);

    console.log(serialized_approve_multisig_transaction);

    assert.strictEqual(expected, serialized_approve_multisig_transaction);
  });

  it("should return a signature of the approve multisig transaction", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let to_address = recoveredKey.address;
    let from_address = recoveredKey.address;
    let proposer_address = recoveredKey.address;

    let expected = {
      "Message":{
        "From":recoveredKey.address,
        "GasLimit":1000000,
        "GasFeeCap":"2500",
        "GasPremium":"2500",
        "Method":3,
        "Nonce":1,
        "Params":"ghkE0lgg+rTC4nLjD9Hei+02w5Y3wb6UHhbdku2uD1S2Bnz/Qv8=",
        "To":"t01004",
        "Value":"0"
      },
      "Signature":{
        "Data":"mIo6gwU4DmW39/GGIeFbT64r5V6E3tkdpCmYUsdI3mFlJczRHn/Qqm1XJXHuJqxkdP9GcnOEBmN69vML76QESAE=",
        "Type":1
      }
    }

    let approve_multisig_transaction = filecoin_signer.approveMultisig("t01004", 1234, proposer_address, to_address, "1000", to_address, 1, "1000000", "2500", "2500");

    let signature = filecoin_signer.transactionSignLotus(approve_multisig_transaction, privateKey);

    console.log(signature);

    assert.deepStrictEqual(expected, JSON.parse(signature));
  });
})

describeCall("cancelMultisig", function() {
  it("should return a cancel multisig transaction", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let to_address = recoveredKey.address;
    let from_address = recoveredKey.address;
    let proposer_address = recoveredKey.address;

    let proposal_params = {
      requester: recoveredKey.address,
      to: recoveredKey.address,
      value: '1000',
      method: 0,
      params: ''
    };

    let txn_id_params = {
      txn_id: 1234,
      proposal_hash_data: Buffer.from(blake2b256(filecoin_signer.serializeParams(proposal_params))).toString('base64')
    }

    let expected = {
      to: 't01004',
      from: recoveredKey.address,
      nonce: 1,
      value: '0',
      gaslimit: 1000000,
      gasfeecap: '2500',
      gaspremium: '2500',
      method: 4,
      params: Buffer.from(filecoin_signer.serializeParams(txn_id_params)).toString('base64')
    }

    let cancel_multisig_transaction = filecoin_signer.cancelMultisig("t01004", 1234, proposer_address, to_address, "1000", to_address, 1, "1000000", "2500", "2500");

    console.log(cancel_multisig_transaction);

    assert.deepStrictEqual(expected, cancel_multisig_transaction);
  });

  it("should return a serialized version of the cancel multisig transaction", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let to_address = recoveredKey.address;
    let from_address = recoveredKey.address;
    let proposer_address = recoveredKey.address;

    let expected = "8a004300ec075501dfe49184d46adc8f89d44638beb45f78fcad259001401a000f4240430009c4430009c4045826821904d25820fab4c2e272e30fd1de8bed36c39637c1be941e16dd92edae0f54b6067cff42ff";

    let cancel_multisig_transaction = filecoin_signer.cancelMultisig("t01004", 1234, proposer_address, to_address, "1000", to_address, 1, "1000000", "2500", "2500");

    let serialized_cancel_multisig_transaction = filecoin_signer.transactionSerialize(cancel_multisig_transaction);

    console.log(serialized_cancel_multisig_transaction);

    assert.strictEqual(expected, serialized_cancel_multisig_transaction);
  });

  it("should return a signature of the cancel multisig transaction", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let to_address = recoveredKey.address;
    let from_address = recoveredKey.address;
    let proposer_address = recoveredKey.address;

    let expected = {
      "Message":{
        "From":recoveredKey.address,
        "GasLimit":1000000,
        "GasPremium":"2500",
        "GasFeeCap":"2500",
        "Method":4,
        "Nonce":1,
        "Params":"ghkE0lgg+rTC4nLjD9Hei+02w5Y3wb6UHhbdku2uD1S2Bnz/Qv8=",
        "To":"t01004",
        "Value":"0"
      },
      "Signature":{
        "Data":"+9MLw/DXhDGESG6rYiWuhoEvzLT0GUEg8aQE1GFxX6JO6pyGQDSshPOLv8h9Ox9tWKVUK1JXipUba5wxI7SJ8wA=",
        "Type":1
      }
    }

    let cancel_multisig_transaction = filecoin_signer.cancelMultisig("t01004", 1234, proposer_address, to_address, "1000", to_address, 1, "1000000", "2500", "2500");

    let signature = filecoin_signer.transactionSignLotus(cancel_multisig_transaction, privateKey);

    console.log(signature);

    assert.deepStrictEqual(expected, JSON.parse(signature));
  });
})
