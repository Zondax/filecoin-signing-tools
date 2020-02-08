import * as assert from 'assert';
import {hello, verify_signature, transaction_parse, transaction_create} from 'fcwebsigner';

const cbor_transaction = "885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c6285501b882619d46558f3d9e316d11b48dcf211327025a0144000186a0430009c4430061a80040";

const transaction = {
  "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
  "from": "t1xcbgdhkgkwht3hrrnui3jdopeejsoas2rujnkdi",
  "nonce": 1,
  "value": "100000",
  "gas_price": "2500",
  "gas_limit": "25000",
  "method": 0,
  "params": ""
}

test('Hello world', () => {
    assert.equal(hello(), 123);
});

// FIXME: Disabled to avoid having CI issues. Move to a standard test runner
test('Hello world fail', () => {
    // assert.equal(hello(), 124);
});

test('Parse Cbor Transaction', () => {
  assert.equal(JSON.stringify(transaction), transaction_parse(cbor_transaction))
})

test('Parse Cbor Transaction fail', () => {
  let cbor_transaction_extra_bytes = cbor_transaction + "00";

  try {
    transaction_parse(cbor_transaction_extra_bytes);
  } catch (e) {
    console.log(e);
  }

  assert.throws(
    () => transaction_parse(cbor_transaction_extra_bytes),
    "Extra byte added should not be able to parse"
  );
})

test('Create Transaction', () => {
  assert.equal(cbor_transaction,transaction_create(JSON.stringify(transaction)))
});

test('Create Transaction Fail (missing nonce)', () => {
  let unvalid_transaction = {
    "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
    "from": "t1xcbgdhkgkwht3hrrnui3jdopeejsoas2rujnkdi",
    "value": "100000",
    "gas_price": "2500",
    "gas_limit": "25000",
    "method": 0,
    "params": ""
  }

  try {
    transaction_create(JSON.stringify(unvalid_transaction));
  } catch (e) {
    console.log(e);
  }

  assert.throws(
    () => transaction_create(JSON.stringify(unvalid_transaction)),
    "Should be missing nonce field"
  );

});

test('Verify signature', () => {
  assert.equal(verify_signature(), false);
})
