import * as assert from 'assert';
import secp256k1 from 'secp256k1';
import {key_derive, verify_signature, transaction_parse, transaction_create, sign_transaction} from 'fcwasmsigner';
import bip32 from 'bip32';
import {getDigest} from './utils.mjs'
import fs from 'fs';

//////////////////////////////////
//
//     Initiate variable
//
////////////////////////////////

const mnemonic_example = "equip will roof matter pink blind book anxiety banner elbow sun young";

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
  assert.equal(JSON.stringify(transaction), transaction_parse(cbor_transaction, true))
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

/*test('Key Generate Mnemonic', () => {
  // Can't get a random number to generate mnemonic
  // panicked at 'could not initialize thread_rng: getrandom: this target is not supported', ~/.cargo/registry/src/github.com-1ecc6299db9ec823/rand-0.7.3/src/rngs/thread.rs:65:17
})*/

test('Key Derive', () => {
  let child = node.derivePath("m/44'/461'/0/0/1");

  let keypair = key_derive(mnemonic_example, "m/44'/461'/0/0/1");

  console.log("Pubkey :", keypair.pubkey);
  console.log("Prvkey :", keypair.prvkey);
  console.log("Address :", keypair.address);

  assert.equal(child.privateKey.toString("hex"), keypair.prvkey);

})

test('Key Derive Invalid Path', () => {

  assert.throws(
    () => key_derive(mnemonic_example, "m/44'/461'/a/0/1"),
    /Cannot parse integer/
  );
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

//////////////////////////////////
//
//     Tests vectors
//
////////////////////////////////
const tests_vectors_path = "../manual_testvectors.json";

let rawData = fs.readFileSync(tests_vectors_path);
let jsonData = JSON.parse(rawData);

for (let i = 0; i < jsonData.length; i += 1) {
  let tc = jsonData[i];
  if (!tc.message.params) {
    tc.message["params"] = ""
  }

  // Create test case for each
  test("Create Transaction : " + tc.description, () => {
    if (tc.valid) {
      // Valid doesn't throw
      let result = transaction_create(JSON.stringify(tc.message));
      assert.equal(tc.encoded_tx_hex,result);
    } else {
      // Not valid throw error
      // TODO: Add error type to manual_testvectors.json file
      assert.throws(
        () => transaction_create(JSON.stringify(tc.message)),
        /Error/
      );
    }
  })

  if (tc.not_implemented) {
    // FIXME: Protocol 0 parsing not implemented in forest
    // FIXME: should handle the case when address have 0 byte (issue #53)
    // FIXME: doesn't fail for empty value #54
    console.log("FIX ME");
    continue;
  };

  // Create test case for each
  test("Parse Transaction : " + tc.description, () => {
    if (tc.valid) {
      let result = transaction_parse(tc.encoded_tx_hex, tc.testnet);
      assert.equal(JSON.stringify(tc.message),result);
    } else {
      // Not valid throw error
      // TODO: Add error type to manual_testvectors.json file
      assert.throws(
        () => transaction_parse(tc.encoded_tx_hex, tc.testnet),
        /error/
      );
    }
  })
}
