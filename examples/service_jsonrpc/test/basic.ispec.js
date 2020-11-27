import { expect, test } from "jest";
import * as bip32 from "bip32";
import * as bip39 from "bip39";
import secp256k1 from "secp256k1";
import fs from "fs";
import { getDigest } from "./utils.js";
import { callMethod } from "../src";

const testsVectorsPath = "../manual_testvectors.json";

// WARNING: filecoin-service is expected to be running
const URL = "http://127.0.0.1:3030/v0";
const MASTER_NODE = bip32.fromBase58(dataWallet.master_key)

/* Load Txs test data */
let rawdataTxs = fs.readFileSync('../../test_vectors/txs.json')
let dataTxs = JSON.parse(rawdataTxs)

/* Load wallet test data */
let rawdataWallet = fs.readFileSync('../../test_vectors/wallet.json')
let dataWallet = JSON.parse(rawdataWallet)

test("key_generate_mnemonic", async () => {
  const response = await callMethod(URL, "key_generate_mnemonic", [], 1);
  console.log(response);

  // Do we have a results
  expect(response).toHaveProperty("result");
  // Verify we have 24 words
  expect(response.result.split(" ").length).toBe(24);
});

test("key_derive", async () => {
  const response = await callMethod(URL, "key_derive", [dataWallet.mnemonic, dataWallet.childs[3].path, "", dataWallet.language_code], 1);
  const child = MASTER_NODE.derivePath(dataWallet.childs[3].path);
  console.log(response);

  // Do we have a results
  expect(response).toHaveProperty("result");
  expect(response.result.private_base64).toEqual(child.privateKey.toString("base64"));
  expect(response.result.address).toEqual(dataWallet.childs[3].address);
});

test("key_derive testnet path", async () => {
  const response = await callMethod(URL, "key_derive", [dataWallet.mnemonic, dataWallet.childs[2].path, "", dataWallet.language_code], 1);
  const child = MASTER_NODE.derivePath(dataWallet.childs[2].path);
  const expectedPubKey = Buffer.from(secp256k1.publicKeyCreate(child.privateKey, false));

  console.log(response);

  // Do we have a results
  expect(response).toHaveProperty("result");
  expect(response.result.private_base64).toEqual(child.privateKey.toString("base64"));
  expect(response.result.public_hexstring).toEqual(expectedPubKey.toString("hex"));
  expect(response.result.address.startsWith("t")).toBeTruthy();
});

test("key_derive missing all parameters", async () => {
  const response = await callMethod(URL, "key_derive", [], 1);
  console.log(response);

  expect(response).toHaveProperty("error");
  expect(response.error.message).toMatch(/Invalid params/);
});

test("key_derive missing path parameters", async () => {
  const response = await callMethod(URL, "key_derive", [dataWallet.mnemonic], 1);
  console.log(response);

  expect(response).toHaveProperty("error");
  expect(response.error.message).toMatch(/Invalid params/);
});

test("key_derive invalid path parameter", async () => {
  const response = await callMethod(URL, "key_derive", [dataWallet.mnemonic, "", "", dataWallet.language_code], 1);
  console.log(response);

  expect(response).toHaveProperty("error");
  expect(response.error.message).toMatch(/Path should start with `m`/);
});

test("key_derive missing password parameter (verify default)", async () => {
  const response = await callMethod(URL, "key_derive", [dataWallet.mnemonic, dataWallet.childs[3].path, "", dataWallet.language_code], 1);
  const child = MASTER_NODE.derivePath(dataWallet.childs[3].path);
  const expectedPubKey = Buffer.from(secp256k1.publicKeyCreate(child.privateKey, false));
  console.log(response);

  expect(response).toHaveProperty("result");
  expect(response.result.private_base64).toEqual(child.privateKey.toString("base64"));
  expect(response.result.public_hexstring).toEqual(expectedPubKey.toString("hex"));
  expect(response.result.address).toEqual(dataWallet.childs[3].address);
});

test("key_derive_from_seed", async () => {
  const seed = bip39.mnemonicToSeedSync(dataWallet.mnemonic).toString("hex");

  const response = await callMethod(URL, "key_derive_from_seed", [seed, dataWallet.childs[3].path], 1);
  const child = MASTER_NODE.derivePath(dataWallet.childs[3].path);
  const expectedPubKey = Buffer.from(secp256k1.publicKeyCreate(child.privateKey, false));
  console.log(response);

  // Do we have a results
  expect(response).toHaveProperty("result");
  expect(response.result.private_base64).toEqual(child.privateKey.toString("base64"));
  expect(response.result.public_hexstring).toEqual(expectedPubKey.toString("hex"));
  expect(response.result.address).toEqual(dataWallet.childs[3].address);
});

test("transaction_serialize", async () => {
  const response = await callMethod(URL, "transaction_serialize", dataTxs[0].transaction, 1);

  expect(Buffer.from(response.result).toString("hex")).toBe(dataTxs[0].cbor);
});

test("transaction_parse", async () => {
  const response = await callMethod(URL, "transaction_parse", [dataTxs[0].cbor, true], 1);

  expect(JSON.parse(response.result)).toStrictEqual(dataTxs[0].transaction);
});

test("transaction_parse_invalid_length", async () => {
  const response = await callMethod(URL, "transaction_parse", [`${dataTxs[0].cbor}'`, true], 1);

  expect(response).toHaveProperty("error");
  expect(response.error.message).toMatch(/Hex decoding | Invalid length/);
});

const rawData = fs.readFileSync(testsVectorsPath);
const jsonData = JSON.parse(rawData);

for (let i = 0; i < jsonData.length; i += 1) {
  const tc = jsonData[i];
  if (!tc.message.params) {
    tc.message.params = "";
  }
  
  test(`Serialize Transaction : ${tc.description}`, async () => {
    const response = await callMethod(URL, "transaction_serialize", tc.message, i);

    console.log(response)
    if (response.error) {
      console.log("Error", response);
      expect(tc.valid).toEqual(false);
    } else {
      expect(Buffer.from(response.result).toString("hex")).toEqual(tc.encoded_tx_hex);
    }
  })

  if (tc.not_implemented) {
    // FIXME: Doesn't raise an error when parsing negative value
    console.log("FIX ME: Protocol 0 parsing not implemented in forest");
    continue;
  }
  // Create test case for each
  test(`Parse Transaction : ${tc.description}`, async () => {
    const response = await callMethod(URL, "transaction_parse", [tc.encoded_tx_hex, tc.testnet], i);

    if (tc.valid) {
      console.log(response);
      expect(JSON.parse(response.result)).toStrictEqual(tc.message);
    } else {
      console.log(response.error);
      expect(response).toHaveProperty("error");
    }
  });
}

test("sign_transaction", async () => {
  const child = MASTER_NODE.derivePath("m/44'/461'/0/0/0");
  const message_digest = getDigest(Buffer.from(dataTxs[0].cbor, "hex"));

  const response = await callMethod(
    URL,
    "sign_transaction",
    [dataTxs[0].transaction, child.privateKey.toString("base64")],
    1,
  );

  console.log(response);

  const signatureBuffer = Buffer.from(response.result.signature.data, "base64").slice(0, -1);

  // compare signature
  const signatureCompare = secp256k1.ecdsaSign(message_digest, child.privateKey);

  expect(Buffer.from(signatureCompare.signature)).toEqual(signatureBuffer);

  // Remove V from result to verify signature
  const result = secp256k1.ecdsaVerify(signatureBuffer, message_digest, child.publicKey);

  expect(result).toBeTruthy();
});

test("sign_invalid_transaction", async () => {
  const child = MASTER_NODE.derivePath("m/44'/461'/0/0/0");
  const invalid_transaction = {
    to: "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
    from: "t1xcbgdhkgkwht3hrrnui3jdopeejsoas2rujnkdi",
    value: "100000",
    gaslimit: 25000,
    gasfeecap: "1",
    gaspremium: "1",
    method: 0,
    params: "",
  };

  const response = await callMethod(
    URL,
    "sign_transaction",
    [invalid_transaction, child.privateKey.toString("hex")],
    1,
  );

  // Verify we have an error message
  expect(response).toHaveProperty("error");
  // Verify we have the corrcet error message 'missing nonce'
  expect(response.error.message).toMatch(/missing field `nonce`/);
});

test("verify_signature", async () => {
  const child = MASTER_NODE.derivePath("m/44'/461'/0/0/0");

  const message_digest = getDigest(Buffer.from(dataTxs[0].cbor, "hex"));

  const signature = secp256k1.ecdsaSign(message_digest, child.privateKey);

  // Concat v value at the end of the signature
  const signatureRSV =
    Buffer.from(signature.signature).toString("hex") + Buffer.from([signature.recid]).toString("hex");

  const response = await callMethod(URL, "verify_signature", [signatureRSV, dataTxs[0].cbor], 1);

  console.log(response);

  expect(response.result).toEqual(true);
});

test("verify_signature signed with lotus", async () => {
  const child = MASTER_NODE.derivePath("m/44'/461'/0/0/0");

  const tx = {
    to: "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
    from: "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
    nonce: 1,
    value: "100000",
    method: 0,
    gaslimit: 25000,
    gasfeecap: "1",
    gaspremium: "1",
    params: "",
  };

  const serialized_tx = await callMethod(URL, "transaction_serialize", tx, 1);
  const cbor_tx = Buffer.from(serialized_tx.result).toString("hex");
  const message_digest = getDigest(Buffer.from(cbor_tx, "hex"));

  const signatureRSV = Buffer.from(
    "nFuTI7MxEXqTQ0QmmQTmqbUsNZfHFXlNjz+susVDkAk1SrRCdJKxlVZZrM4vUtVBSYgtMIeigNfpqdKGIFhoWQA=",
    "base64",
  ).toString("hex");

  const signatureBuffer = Buffer.from(signatureRSV, "hex").slice(0, -1);
  const recoveredID = Buffer.from(signatureRSV, "hex")[64];

  const result = secp256k1.ecdsaVerify(signatureBuffer, message_digest, child.publicKey);
  
  console.log(result);

  const recovered_pubkey = secp256k1.ecdsaRecover(signatureBuffer, 0, message_digest);
  console.log(child.publicKey.toString('hex'))
  console.log(Buffer.from(recovered_pubkey).toString("hex"))
  expect(Buffer.from(recovered_pubkey).toString("hex") == child.publicKey.toString("hex")).toEqual(true);

  const response = await callMethod(URL, "verify_signature", [signatureRSV, cbor_tx], 1);

  console.log(response);

  expect(response.result).toBe(true);
});

test("verify_invalid_signature", async () => {
  const child = MASTER_NODE.derivePath("m/44'/461'/0/0/0");

  const message_digest = getDigest(Buffer.from(dataTxs[0].cbor, "hex"));

  const signature = secp256k1.ecdsaSign(message_digest, child.privateKey);

  // Tampered signature
  const invalid_signature = Buffer.concat([Buffer.from(signature.signature).slice(0, 36), Buffer.alloc(28)]);

  // Concat recovery id value at the end of the signature
  const signatureRSV = invalid_signature.toString("hex") + Buffer.from([signature.recid]).toString("hex");

  const response = await callMethod(URL, "verify_signature", [signatureRSV, dataTxs[0].cbor], 1);

  console.log(response);

  const result = secp256k1.ecdsaVerify(invalid_signature, message_digest, child.publicKey);

  expect(result).toEqual(false);
  expect(response.result).toEqual(false);
});

var messageCID

test("send_signed_tx", async () => {
  jest.setTimeout(40000);
  const keyAddressResponse = await callMethod(URL, "key_derive", [dataWallet.mnemonic, dataWallet.childs[2].path, "", dataWallet.language_code], 1);

  console.log(keyAddressResponse);

  // Get Nonce
  const nonceResponse = await callMethod(URL, "get_nonce", [keyAddressResponse.result.address], 1);

  console.log("-----------------------------------------------------------------------------------");
  let nonce = nonceResponse.result;
  console.log("Nonce: ", nonce);

  if (isNaN(nonce)) {
    nonce = 1;
  }

  expect(!isNaN(nonce)).toBeTruthy();

  const transaction = {
    to: "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
    from: keyAddressResponse.result.address,
    nonce,
    value: "10000",
    gaslimit: 539085,
    gasfeecap: "131941",
    gaspremium: "130964",
    method: 0,
    params: "",
  };

  console.log("-----------------------------------------------------------------------------------");

  const signedTxResponse = await callMethod(
    URL,
    "sign_transaction",
    [transaction, keyAddressResponse.result.private_base64],
    2,
  );

  console.log("SignedTx: ", signedTxResponse);

  const signature_hex = Buffer.from(signedTxResponse.result.signature.data, "base64").toString("hex");
  console.log("Signature_hex: ", signature_hex);
  console.log("Signature_hex_len: ", signature_hex.length);
  expect(signature_hex.length).toBe(130);

  console.log("-----------------------------------------------------------------------------------");

  const response = await callMethod(URL, "send_signed_tx", [signedTxResponse.result], 1);

  console.log(response);
  expect(response).toHaveProperty("result");
  
  messageCID = response.result['/']
});

test("get_status", async () => {
  const messageCid = messageCID;
  const response = await callMethod(URL, "get_status", [messageCid], 1);
  console.log(response);

  expect(response).toHaveProperty("result");

  expect(response.result).toHaveProperty("From");
  expect(response.result).toHaveProperty("GasFeeCap");
  expect(response.result).toHaveProperty("GasLimit");
  expect(response.result).toHaveProperty("GasPremium");
  expect(response.result).toHaveProperty("Method");
  expect(response.result).toHaveProperty("Nonce");
  expect(response.result).toHaveProperty("Params");
  expect(response.result).toHaveProperty("To");
  expect(response.result).toHaveProperty("Value");
  expect(response.result).toHaveProperty("Version");
});

test("get_status fail", async () => {
  const messageCid = "bafy2bzacedjxvl3e2rjm77j3grrsdv3vrlnvaepi4umlv2x4feg12ewmpyxgq";
  const response = await callMethod(URL, "get_status", [messageCid], 1);
  console.log(response);

  expect(response).toHaveProperty("error");
});

test("get_nonce", async () => {
  jest.setTimeout(25000);

  const account = "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba";

  const response = await callMethod(URL, "get_nonce", [account], 1);

  console.log(response);

  expect(response.result).toBeGreaterThanOrEqual(0);
});

test("send_sign", async () => {
  jest.setTimeout(40000);

  const keyAddressResponse = await callMethod(URL, "key_derive", [dataWallet.mnemonic, dataWallet.childs[2].path, "", dataWallet.language_code], 1);

  console.log(keyAddressResponse);

  // Get Nonce
  const nonceResponse = await callMethod(URL, "get_nonce", [keyAddressResponse.result.address], 1);

  let nonce = nonceResponse.result;
  console.log("Nonce: ", nonce);
  console.log(keyAddressResponse.result.address)

  const transaction = {
    to: "t1ojyfm5btrqq63zquewexr4hecynvq6yjyk5xv6q",
    from: keyAddressResponse.result.address,
    nonce,
    value: "10000",
    gaslimit: 539085,
    gasfeecap: "131941",
    gaspremium: "130964",
    method: 0,
    params: "",
  };

  const response = await callMethod(
    URL,
    "send_sign",
    [transaction, keyAddressResponse.result.private_base64],
    2,
  );

  console.log("cidHash: ", response);

  expect(response).toHaveProperty("result");
});

test("send_sign wrong network", async () => {
  const keyAddressResponse = await callMethod(URL, "key_derive", [dataWallet.mnemonic, dataWallet.childs[3].path, "", dataWallet.language_code], 1);

  console.log(keyAddressResponse);

  // Get Nonce
  const nonceResponse = await callMethod(URL, "get_nonce", [keyAddressResponse.result.address], 1);

  console.log("-----------------------------------------------------------------------------------");
  let nonce = nonceResponse.result;
  nonce++;
  console.log("Nonce: ", nonce);

  const transaction = {
    to: "f17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
    from: keyAddressResponse.result.address,
    nonce,
    value: "1",
    gasprice: "0",
    gaslimit: "1000000",
    method: 0,
    params: "",
  };

  console.log("-----------------------------------------------------------------------------------");

  const response = await callMethod(
    URL,
    "send_sign",
    [transaction, keyAddressResponse.result.private_hexstring],
    2,
  );

  console.log("error: ", response);

  expect(response).toHaveProperty("error");
});
