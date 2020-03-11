/* eslint-disable no-console */
import { test, expect } from "jest";
import { callMethod } from "../src";
import * as bip32 from "bip32";
import {getDigest} from './utils.js'
import secp256k1 from 'secp256k1';
import fs from 'fs';

const tests_vectors_path = "../manual_testvectors.json";

// FIXME: fcservice is expected to be running
const URL = "http://127.0.0.1:3030/v0";

const mnemonic = "equip will roof matter pink blind book anxiety banner elbow sun young";

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
};

const prv_root_key = "xprv9s21ZrQH143K49QgrAgAVELf6ue2tZNHYUc7yfj8JGZY9SpZ38u8EfhWi85GsA6grUeB36wXrbNTkjX9EfGP1ybbPRG4sdP2EPfY1SZ2BF5";
let node = bip32.fromBase58(prv_root_key);

test("key_generate_mnemonic", async () => {
  const response = await callMethod(URL, "key_generate_mnemonic", [], 1);
  console.log(response);

  // Do we have a results
  expect(response).toHaveProperty("result");
  // Verify we have 24 words
  expect(response.result.split(" ").length).toBe(24);
});

test("key_derive", async () => {
  const path = "m/44'/461'/0/0/0";
  const response = await callMethod(URL, "key_derive", [mnemonic, path], 1);
  let child = node.derivePath(path);
  console.log(response)

  // Do we have a results
  expect(response).toHaveProperty("result");
  expect(response.result.prvkey).toEqual(child.privateKey.toString("hex"));
  expect(response.result.pubkey).toEqual(child.publicKey.toString("hex"));
  expect(response.result.address).toEqual("t1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka");
});

test("key_derive missing all parameters", async () => {
  const response = await callMethod(URL, "key_derive", [], 1);
  console.log(response);

  expect(response).toHaveProperty("error");
  expect(response.error.message).toMatch(/Invalid params/);
});

test("key_derive missing 1 parameters", async () => {
  const response = await callMethod(URL, "key_derive", [mnemonic], 1);
  console.log(response);

  expect(response).toHaveProperty("error");
  expect(response.error.message).toMatch(/Invalid params/);
});

test("transaction_create", async () => {
  const response = await callMethod(
    URL,
    "transaction_create",
    transaction,
    1,
  );

  expect(response.result).toBe(cbor_transaction);
});

test("transaction_parse", async () => {
  const response = await callMethod(
    URL,
    "transaction_parse",
    [cbor_transaction, true],
    1,
  );

  expect(response.result).toBe(JSON.stringify(transaction));
});

test("transaction_testvectors", async () => {
  let rawData = fs.readFileSync(tests_vectors_path);
  let jsonData = JSON.parse(rawData);

  for (let i = 0; i < jsonData.length; i += 1) {
    let tc = jsonData[i];
    console.log(tc.message);
    if (!tc.message.params) {
      tc.message["params"] = ""
    }

    let response = await callMethod(URL, "transaction_create", tc.message, i);

    if (response.error) {
      console.log("Error", response);
      expect(tc.valid).toEqual(false);
    } else {
      console.log("Testcase ------------------------------------------------------------------------------------");
      console.log(tc.description);
      console.log("Reply", response);
      expect(response.result).toEqual(tc.encoded_tx_hex);
    }
  }
});

let rawData = fs.readFileSync(tests_vectors_path);
let jsonData = JSON.parse(rawData);

for (let i = 0; i < jsonData.length; i += 1) {
  let tc = jsonData[i];
  if (!tc.message.params) {
    tc.message["params"] = "";
  }

  if (tc.not_implemented) {
    // FIXME: Protocol 0 parsing not implemented in forest
    // FIXME: should handle the case when address have 0 byte (issue #53)
    // FIXME: doesn't fail for empty value #54
    console.log("FIX ME");
    continue;
  };

  // Create test case for each
  test("Parse Transaction : " + tc.description, async () => {
    let response = await callMethod(URL, "transaction_parse", [tc.encoded_tx_hex, tc.testnet], i);

    if (tc.valid) {
      console.log(response);
      expect(JSON.parse(response.result)).toEqual(tc.message);
    } else {
      console.log(response.error);
      expect(response).toHaveProperty('error');
    }

  })
}

test("sign_transaction", async () => {
  let child = node.derivePath("m/44'/461'/0/0/0");
  let message_digest = getDigest(Buffer.from(cbor_transaction, 'hex'));

  const response = await callMethod(
    URL,
    "sign_transaction",
    [transaction, child.privateKey.toString("hex")],
    1,
  );

  let signatureBuffer = Buffer.from(response.result, "hex").slice(0,-1);

  // compare signature
  let signatureCompare = secp256k1.ecdsaSign(message_digest, child.privateKey);

  expect(Buffer.from(signatureCompare.signature)).toEqual(signatureBuffer);

  // Remove V from result to verify signature
  let result = secp256k1.ecdsaVerify(signatureBuffer, message_digest, child.publicKey);

  expect(result).toBeTruthy();
});

test("sign_invalid_transaction", async () => {
  let child = node.derivePath("m/44'/461'/0/0/0");
  let invalid_transaction = {
    "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
    "from": "t1xcbgdhkgkwht3hrrnui3jdopeejsoas2rujnkdi",
    "value": "100000",
    "gas_price": "2500",
    "gas_limit": "25000",
    "method": 0,
    "params": ""
  };

  const response = await callMethod(
    URL,
    "sign_transaction",
    [invalid_transaction, child.privateKey.toString("hex")],
    1,
  );

  // Verify we have an error message
  expect(response).toHaveProperty('error');
  // Verify we have the corrcet error message 'missing nonce'
  expect(response.error.message).toMatch(/missing field `nonce`/);
})

test("verify_signature", async () => {
  let child = node.derivePath("m/44'/461'/0/0/0");

  let message_digest = getDigest(Buffer.from(cbor_transaction, 'hex'));

  let signature = secp256k1.ecdsaSign(message_digest, child.privateKey);

  // Concat v value at the end of the signature
  let signatureRSV = Buffer.from(signature.signature).toString('hex') + Buffer.from([signature.recid]).toString('hex');

  const response = await callMethod(
    URL,
    "verify_signature",
    [signatureRSV, cbor_transaction],
    1,
  );

  console.log(response);

  expect(response.result).toEqual(true);
});

test("verify_invalid_signature", async () => {
  let child = node.derivePath("m/44'/461'/0/0/0");

  let message_digest = getDigest(Buffer.from(cbor_transaction, 'hex'));

  let signature = secp256k1.ecdsaSign(message_digest, child.privateKey);

  // Tampered signature
  let invalid_signature = Buffer.concat([Buffer.from(signature.signature).slice(0,36), Buffer.alloc(28)]);

  // Concat recovery id value at the end of the signature
  let signatureRSV = invalid_signature.toString('hex') + Buffer.from([signature.recid]).toString('hex');

  const response = await callMethod(
    URL,
    "verify_signature",
    [signatureRSV, cbor_transaction],
    1,
  );

  console.log(response);

  let result = secp256k1.ecdsaVerify(invalid_signature, message_digest, child.publicKey);

  expect(result).toEqual(false);
  expect(response.result).toEqual(false);
});

test("get_status", async () => {
  let message_cid = "bafy2bzacea2ob4bctlucgp2okbczqvk5ctx4jqjapslz57mbcmnnzyftgeqgu";
  const response = await callMethod(URL, "get_status", [message_cid], 1);
  console.log(response);

  // Do we have a results
  expect(response).toHaveProperty("result");
  expect(response.result).toEqual({
        "From": "t3wjxuftije2evjmzo2yoy5ghfe2o42mavrpmwuzooghzcxdhqjdu7kn6dvkzf4ko37w7sfnnzdzstcjmeooea",
        "GasLimit": "1000",
        "GasPrice": "0",
        "Method": 0,
        "Nonce": 66867,
        "Params": "",
        "To": "t1lv32q33y64xs64pnyn6om7ftirax5ikspkumwsa",
        "Value": "5000000000000000"
    });
});

test("get_status fail", async () => {
  let message_cid = "bafy2bzaceaxm23epjsmh75yvzcecsrbavlmkcxnva66bkdebdcnyw3bjrc74u";
  const response = await callMethod(URL, "get_status", [message_cid], 1);
  console.log(response);

  // Do we have a results
  expect(response).toHaveProperty("error");
});
