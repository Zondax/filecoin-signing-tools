import * as assert from 'assert';
import secp256k1 from 'secp256k1';
import {hello, verify_signature, transaction_parse, transaction_create, sign_transaction} from 'fcwebsigner';
import bip32 from 'bip32'
import {getDigest} from './utils.mjs'

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

const prv_root_key = "xprv9s21ZrQH143K49QgrAgAVELf6ue2tZNHYUc7yfj8JGZY9SpZ38u8EfhWi85GsA6grUeB36wXrbNTkjX9EfGP1ybbPRG4sdP2EPfY1SZ2BF5"
let node = bip32.fromBase58(prv_root_key)

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
  let invalid_transaction = {
    "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
    "from": "t1xcbgdhkgkwht3hrrnui3jdopeejsoas2rujnkdi",
    "value": "100000",
    "gas_price": "2500",
    "gas_limit": "25000",
    "method": 0,
    "params": ""
  }

  try {
    transaction_create(JSON.stringify(invalid_transaction));
  } catch (e) {
    console.log(e);
  }

  assert.throws(
    () => transaction_create(JSON.stringify(invalid_transaction)),
    "Should be missing nonce field"
  );

});

test('Sign Transaction', () => {
  let child = node.derivePath("m/44'/461'/0/0/0")

  try {
    var signature = sign_transaction(JSON.stringify(transaction), child.privateKey.toString("hex"));
  } catch(e) {
    console.log(e)
  }

  signature = Buffer.from(signature, 'hex')
  let message_digest = getDigest(Buffer.from(cbor_transaction, 'hex'))

  console.log("Signature :",signature)
  console.log("Digest :", message_digest)
  console.log("Public key :", child.publicKey)

  assert.equal(
    true,
    secp256k1.ecdsaVerify(signature, message_digest, child.publicKey)
  )

});


test('Verify signature', () => {
  assert.equal(verify_signature(), false);
})
