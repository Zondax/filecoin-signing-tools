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

describeCall('createPymtChan', function () {
  it('create payment channel transaction and sign (SECP256K1)', function () {
    const privateKey = "+UXJi0663hCExYMxZVb9J+wKyFWhhX51jnG7WXkeAw0=";

    const recover = filecoin_signer.keyRecover(privateKey, true);

    const from = recover.address;
    const to = "t3smdzzt2fbrzalmfi5rskc3tc6wpwcj2zbgyu5engqtkkzrxteg2oyqpukqzrhqqfvzqadh7mtqye443liejq";

    let serializedParams

    if (!process.env.PURE_JS) {
      const createParams = {
        From: from,
        To: to,
      }

      serializedParams = Buffer.from(filecoin_signer.serializeParams(createParams));

      let execParams = {
          CodeCid: 'fil/1/paymentchannel',
          ConstructorParams: serializedParams.toString('base64')
      }

      serializedParams = Buffer.from(filecoin_signer.serializeParams(execParams)).toString("base64");
    } else {
      serializedParams = "gtgqWBkAAVUAFGZpbC8xL3BheW1lbnRjaGFubmVsWEqCVQElRUfDOAbbTJ6ACbjr2cTS5fIBglgxA5MHnM9FDHIFsKjsZKFuYvWfYSdZCbFOkaaE1KzG8yG07EH0VDMTwgWuYAGf7JwwTg==";
    }

    const expected = {
      Message: {
        From: from,
        GasLimit: 200000000,
        GasFeeCap: '2500',
        GasPremium: '2500',
        Method: 2,
        Nonce: 1,
        Params: serializedParams,
        To: 't01',
        Value: '10000000000'
      },
    }

    let create_pymtchan = filecoin_signer.createPymtChan(from, to, "10000000000", 1);

    console.log(create_pymtchan)

    let signedMessage = filecoin_signer.transactionSignLotus(create_pymtchan, privateKey);
    signedMessage = JSON.parse(signedMessage)

    console.log(signedMessage);

    assert.deepStrictEqual(expected.Message, signedMessage.Message);

    const signature = Buffer.from(signedMessage.Signature.Data, "base64");

    const serializedMessage = filecoin_signer.transactionSerialize(create_pymtchan);

    const messageDigest = getDigest(Buffer.from(serializedMessage, 'hex'));

    // Remove the V value from the signature (last byte)
    assert(secp256k1.ecdsaVerify(signature.slice(0, -1), messageDigest, recover.public_raw))

  })
  it('create payment channel transaction and sign (BLS)', function () {
    let privateKey = "8niW4fUBoKNo3GMDVfWu0oari11js4t1QpwXVBpEpFA=";
    let from = "t3smdzzt2fbrzalmfi5rskc3tc6wpwcj2zbgyu5engqtkkzrxteg2oyqpukqzrhqqfvzqadh7mtqye443liejq";
    let to = "t1evcupqzya3nuzhuabg4oxwoe2ls7eamcu3uw4cy";

    let serializedParams

    if (!process.env.PURE_JS) {
      const createParams = {
        From: from,
        To: to,
      }

      serializedParams = Buffer.from(filecoin_signer.serializeParams(createParams));

      let execParams = {
          CodeCid: 'fil/1/paymentchannel',
          ConstructorParams: serializedParams.toString('base64')
      }

      serializedParams = Buffer.from(filecoin_signer.serializeParams(execParams)).toString('base64');
      console.log(serializedParams)
    } else {
      serializedParams = "gtgqWBkAAVUAFGZpbC8xL3BheW1lbnRjaGFubmVsWEqCWDEDkwecz0UMcgWwqOxkoW5i9Z9hJ1kJsU6RpoTUrMbzIbTsQfRUMxPCBa5gAZ/snDBOVQElRUfDOAbbTJ6ACbjr2cTS5fIBgg==";
    }

    console.log(serializedParams)

    const expected = {
      Message: {
        From: from,
        GasLimit: 200000000,
        GasFeeCap: '2500',
        GasPremium: '2500',
        Method: 2,
        Nonce: 1,
        Params: serializedParams,
        To: 't01',
        Value: '10000000000'
      }
    }

    let create_pymtchan = filecoin_signer.createPymtChan(from, to, "10000000000", 1)

    console.log(create_pymtchan)

    let signedMessage = filecoin_signer.transactionSignLotus(create_pymtchan, privateKey);
    signedMessage = JSON.parse(signedMessage);

    assert.deepStrictEqual(expected.Message, signedMessage.Message);

    // TODO: verify signature
    // but with which lib ?

  })
})

describeCall('updatePymtChan', function () {
  it('update payment channel transaction and sign', function () {
    const privateKey = "+UXJi0663hCExYMxZVb9J+wKyFWhhX51jnG7WXkeAw0=";

    const recover = filecoin_signer.keyRecover(privateKey, true);

    const from = recover.address;

    const signedVoucherBase64 = "i1UCP53KVzJUi7wjUUapT5IVPBQn/BcZBNIAQPYAAUQAAYagAYBYQgFyEfwyxLoQd7Vr3+BbaVvfRhvAP74X7YFEhRNTKRnP1Tqe36cZ9vjVh/SzLY19pOjPwiX8aYO2cYJ6m7+ezuc3AQ==";

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    let serializedParams

    if (!process.env.PURE_JS) {

      let updateChannelStateParams = {
        Sv: signedVoucherBase64,
        Secret: [],
        Proof: [],
      }

      serializedParams = Buffer.from(filecoin_signer.serializeParams(updateChannelStateParams)).toString('base64');
    } else {
      serializedParams = "g4oZBNIAQPYAAUQAAYagAYBYQgGKqPFMze+bytqgOI/JJY3VI6Gu4UElA6qS1w+/SmM6xm9TK+EcCJw/9Y/kOoWQTfvaoEZyphNO8ty7HOUPRTKeAUBA";
    }

    const expected = {
      Message : {
        From: from,
        GasLimit: 200000000,
        GasFeeCap: '2500',
        GasPremium: '2500',
        Method: 2,
        Nonce: 1,
        Params: serializedParams,
        To: 't01003',
        Value: '0'
      }
    }

    let update_pymtchan = filecoin_signer.updatePymtChan("t01003", recoveredKey.address, signedVoucherBase64, 1)

    console.log(update_pymtchan)

    let signedMessage = filecoin_signer.transactionSignLotus(update_pymtchan, privateKey);
    signedMessage = JSON.parse(signedMessage)

    assert.deepStrictEqual(expected.Message, signedMessage.Message);

    const signature = Buffer.from(signedMessage.Signature.Data, "base64");

    const serializedMessage = filecoin_signer.transactionSerialize(update_pymtchan);

    const messageDigest = getDigest(Buffer.from(serializedMessage, 'hex'));

    // Remove the V value from the signature (last byte)
    assert(secp256k1.ecdsaVerify(signature.slice(0, -1), messageDigest, recover.public_raw));
  })
})

describeCall('settlePymtChan', function () {
  it('settle payment channel and sign', function () {
    const privateKey = "+UXJi0663hCExYMxZVb9J+wKyFWhhX51jnG7WXkeAw0=";
    const recover = filecoin_signer.keyRecover(privateKey, true);
    const from = recover.address;
    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    const expected = {
      Message : {
        From: from,
        GasLimit: 20000000,
        GasFeeCap: '2500',
        GasPremium: '2500',
        Method: 3,
        Nonce: 1,
        Params: "",
        To: 't01003',
        Value: '0'
      }
    }
    let settle_pymtchan = filecoin_signer.settlePymtChan("t01003", recoveredKey.address, 1)

    console.log(settle_pymtchan)

    let signedMessage = filecoin_signer.transactionSignLotus(settle_pymtchan, privateKey);
    signedMessage = JSON.parse(signedMessage);

    assert.deepStrictEqual(expected.Message, signedMessage.Message);

    const signature = Buffer.from(signedMessage.Signature.Data, "base64");
    const serializedMessage = filecoin_signer.transactionSerialize(settle_pymtchan);
    const messageDigest = getDigest(Buffer.from(serializedMessage, 'hex'));

    // Remove the V value from the signature (last byte)
    assert(secp256k1.ecdsaVerify(signature.slice(0, -1), messageDigest, recover.public_raw));
  })
})

describeCall('collectPymtChan', function () {
  it('settle payment channel and sign', function () {
    const privateKey = "+UXJi0663hCExYMxZVb9J+wKyFWhhX51jnG7WXkeAw0=";
    const recover = filecoin_signer.keyRecover(privateKey, true);
    const from = recover.address;
    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    const expected = {
      Message : {
        From: from,
        GasLimit: 20000000,
        GasFeeCap: '2500',
        GasPremium: '2500',
        Method: 4,
        Nonce: 1,
        Params: "",
        To: 't01003',
        Value: '0'
      }
    }

    let collect_pymtchan = filecoin_signer.collectPymtChan("t01003", recoveredKey.address, 1)
    let signedMessage = filecoin_signer.transactionSignLotus(collect_pymtchan, privateKey);
    signedMessage = JSON.parse(signedMessage);

    assert.deepStrictEqual(expected.Message, signedMessage.Message);

    const signature = Buffer.from(signedMessage.Signature.Data, "base64");
    const serializedMessage = filecoin_signer.transactionSerialize(collect_pymtchan);
    const messageDigest = getDigest(Buffer.from(serializedMessage, 'hex'));

    // Remove the V value from the signature (last byte)
    assert(secp256k1.ecdsaVerify(signature.slice(0, -1), messageDigest, recover.public_raw));
  })
})

describeCall('createVoucher', function () {
  it('create a voucher', function () {
    const voucher = filecoin_signer.createVoucher(
      "t2h6o4uvzsksf3yi2ri2uu7eqvhqkcp7axmg3mski",
      BigInt(1234),
      BigInt(0),
      "100000",
      BigInt(0),
      BigInt(1),
      BigInt(1),
    );

    const expected = "i1UCP53KVzJUi7wjUUapT5IVPBQn/BcZBNIAQPYAAUQAAYagAYD2";

    assert.strictEqual(expected, voucher);
  })
})

describeCall('signVoucher', function () {
  it('sign a voucher', function () {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    const voucher = "i1UCP53KVzJUi7wjUUapT5IVPBQn/BcZBNIAQPYAAUQAAYagAYD2";

    const signedVoucher = filecoin_signer.signVoucher(voucher, privateKey);

    console.log(signedVoucher)

    let signature = cbor.deserialize(Buffer.from(signedVoucher, 'base64'))[10];

    signature = signature.slice(1,-1);
    console.log(signature.toString("base64"))

    const messageDigest = getDigestVoucher(Buffer.from(voucher, 'base64'));

    assert(secp256k1.ecdsaVerify(signature, messageDigest, recoveredKey.public_raw));
  })

  it('sign a voucher (2)', function () {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    const voucher = filecoin_signer.createVoucher(
      "t24acjqhdetck7irsvmn2p6jpuwnouzjxuoa22rva",
      BigInt(0),
      BigInt(0),
      "10000",
      BigInt(1),
      BigInt(1),
      BigInt(0),
    );

    /*
    {"jsonrpc":"2.0","result":{"ChannelAddr":"t24acjqhdetck7irsvmn2p6jpuwnouzjxuoa22rva","TimeLockMin":0,"TimeLockMax":0,"SecretPreimage":null,"Extra":null,"Lane":1,"Nonce":1,"Amount":"10000","MinSettleHeight":0,"Merges":null,"Signature":{"Type":1,"Data":"ZEPtUQzGHPmFZaDocdXBEzp1GZ2RBaOxFfrz5Y/PrNJmBwqftyItNZooaAF6CR+vixe2HCmqSLub4ySOoFiuawE="}},"id":1}
    */
    let expectedSignature = "ZEPtUQzGHPmFZaDocdXBEzp1GZ2RBaOxFfrz5Y/PrNJmBwqftyItNZooaAF6CR+vixe2HCmqSLub4ySOoFiuawE=";

    const signedVoucher = filecoin_signer.signVoucher(voucher, privateKey);

    let signedVoucherCBOR = cbor.deserialize(Buffer.from(signedVoucher, 'base64'));

    console.log(signedVoucherCBOR)
    let signature = signedVoucherCBOR[10]
    console.log(Buffer.from(expectedSignature, 'base64'))
    console.log(signature.slice(1, -1).toString('base64'))

    assert.strictEqual(signature.slice(1).toString('base64'), expectedSignature);

  })

})