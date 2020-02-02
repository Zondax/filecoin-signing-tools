import {expect, test} from "jest";
import Transport from "@ledgerhq/hw-transport";
import {hello} from "fcwebsigner";

test("get version", async () => {
  hello();
});
