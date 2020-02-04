/* eslint-disable no-console */
import { expect, test } from "jest";
import {callMethod} from "../src";

// FIXME: fcservice is expected to be running
const URL = "http://127.0.0.1:3030/v0";

test("key_generate", async () => {
  const response = await callMethod(URL, 'key_generate', [], 1);
  console.log(response)
});
