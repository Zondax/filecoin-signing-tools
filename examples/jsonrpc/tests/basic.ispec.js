/* eslint-disable no-console */
import { test, expect } from "jest";
import { callMethod } from "../src";
import * as bip32 from "bip32";
import {getDigest} from './utils.js'
import secp256k1 from 'secp256k1';

// FIXME: fcservice is expected to be running
const URL = "http://127.0.0.1:3030/v0";

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
};

const prv_root_key = "xprv9s21ZrQH143K49QgrAgAVELf6ue2tZNHYUc7yfj8JGZY9SpZ38u8EfhWi85GsA6grUeB36wXrbNTkjX9EfGP1ybbPRG4sdP2EPfY1SZ2BF5";
let node = bip32.fromBase58(prv_root_key);

test("key_generate", async () => {
  // FIXME: Disabled until this is implemented
  // const response = await callMethod(URL, "key_generate", [], 1);
  // // TODO: Check results
  // console.log(response);
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

test("sign_transaction", async () => {
  let child = node.derivePath("m/44'/461'/0/0/0");

  const response = await callMethod(
    URL,
    "sign_transaction",
    [transaction, child.privateKey.toString("hex")],
    1,
  );

  let message_digest = getDigest(Buffer.from(cbor_transaction, 'hex'));
  let result = secp256k1.ecdsaVerify(Buffer.from(response.result, "hex"), message_digest, child.publicKey);

  expect(result).toBeTruthy();
});

test("verify_signature", async () => {
  let child = node.derivePath("m/44'/461'/0/0/0");

  let message_digest = getDigest(Buffer.from(cbor_transaction, 'hex'));

  let signature = secp256k1.ecdsaSign(message_digest, child.privateKey);
  signature = Buffer.from(signature.signature);

  const response = await callMethod(
    URL,
    "verify_signature",
    [signature.toString('hex'), message_digest.toString('hex'), child.publicKey.toString("hex")],
    1,
  );

  expect(response.result).toBeTruthy();
});
