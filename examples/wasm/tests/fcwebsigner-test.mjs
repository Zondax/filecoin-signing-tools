import * as assert from 'assert';
import secp256k1 from 'secp256k1';
import {verify_signature, transaction_parse, transaction_create, sign_transaction} from 'fcwebsigner';
import bip32 from 'bip32'
import {getDigest} from './utils.mjs'

//////////////////////////////////
//
//     Initiate variable
//
////////////////////////////////
const cbor_transaction = "885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855010f323f4709e8e4db0c1d4cd374f9f35201d26fb20144000186a0430009c4430061a80040";

const transaction = {
  "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
  "from": "t1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka",
  "nonce": 1,
  "value": "100000",
  "gas_price": "2500",
  "gas_limit": "25000",
  "method": 0,
  "params": ""
}

const prv_root_key = "xprv9s21ZrQH143K49QgrAgAVELf6ue2tZNHYUc7yfj8JGZY9SpZ38u8EfhWi85GsA6grUeB36wXrbNTkjX9EfGP1ybbPRG4sdP2EPfY1SZ2BF5"
let node = bip32.fromBase58(prv_root_key)

//////////////////////////////////
//
//     Tests
//
////////////////////////////////
test('Parse Cbor Transaction', () => {
  assert.equal(JSON.stringify(transaction), transaction_parse(cbor_transaction))
})

test('Parse Cbor Transaction fail (extra bytes)', () => {
  let cbor_transaction_extra_bytes = cbor_transaction + "00";

  assert.throws(
    () => transaction_parse(cbor_transaction_extra_bytes),
    /CBOR error/
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

  assert.throws(
    () => transaction_create(JSON.stringify(invalid_transaction)),
    /missing field `nonce`/
  );

});

test('Key Generate', () => {

  // TODO
  let key = key_generate();

  console.log("Pubkey :", key.pubkey);
  console.log("Prvkey :", key.prvkey);

  assert.equal(key.pubkey, "Public key!")
})

test('Key Derive', () => {
  let keypair = key_derive("equip will roof matter pink blind book anxiety banner elbow sun young", "m/44'/161'/0/0/1");

  console.log("Pubkey :", keypair.pubkey);
  console.log("Prvkey :", keypair.prvkey);
})

test('Verify signature', () => {
  assert.equal(verify_signature(), false);
})

test('Sign Transaction', () => {
  let child = node.derivePath("m/44'/461'/0/0/0")

  try {
    var signature = sign_transaction(JSON.stringify(transaction), child.privateKey.toString("hex"));
  } catch(e) {
    assert.fail(e);
  }

  signature = Buffer.from(signature, 'hex')
  let message_digest = getDigest(Buffer.from(cbor_transaction, 'hex'))

  // Signature representation is R, S & V
  console.log("Signature :",signature.toString('hex'))
  console.log("Digest :", message_digest.toString('hex'))
  console.log("Public key :", child.publicKey.toString('hex'))

  assert.equal(
    true,
    // Remove the V value from the signature (last byte)
    secp256k1.ecdsaVerify(signature.slice(0,-1), message_digest, child.publicKey)
  )

  // Verify recovery id which is the last byte of the signature
  assert.equal(0x01, signature[64]);

});

test('Verify signature', () => {
  let child = node.derivePath("m/44'/461'/0/0/0");
  let message_digest = getDigest(Buffer.from(cbor_transaction, 'hex'));

  // Get hex signature in the format (R,S)
  let signature = secp256k1.ecdsaSign(message_digest, child.privateKey);

  // Concat v value at the end of the signature
  let signatureRSV = Buffer.from(signature.signature).toString('hex') + Buffer.from([signature.recid]).toString('hex');

  console.log("RSV signature :", signatureRSV);
  console.log("CBOR Transaction hex :", cbor_transaction)

  assert.equal(verify_signature(signatureRSV, cbor_transaction), true);
})
