/* eslint-disable no-console */
import {test} from "jest";
import {callMethod} from "../src";
import fs from 'fs';

// FIXME: fcservice is expected to be running
const URL = "http://127.0.0.1:3030/v0";

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
    {
      to: "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
      from: "t1xcbgdhkgkwht3hrrnui3jdopeejsoas2rujnkdi",
      nonce: 1,
      value: "100000",
      gas_price: "2500",
      gas_limit: "25000",
      method: 0,
      params: "",
    },
    1,
  );
  // TODO: Check results
  console.log(response);
});

test("transaction_testvectors", async () => {
  let rawData = fs.readFileSync('tests/manual_testvectors.json');
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
