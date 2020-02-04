/* eslint-disable no-console */
import { test } from "jest";
import { callMethod } from "../src";

// FIXME: fcservice is expected to be running
const URL = "http://127.0.0.1:3030/v0";

test("key_generate", async () => {
  const response = await callMethod(URL, "key_generate", [], 1);
  console.log(response);
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
  console.log(response);
});
