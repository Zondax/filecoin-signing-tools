/** ******************************************************************************
 *  (c) 2020 ZondaX GmbH
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */
const Zemu = require("@zondax/zemu").default;
const Resolve = require("path").resolve;

const TransportNodeHid = require('@ledgerhq/hw-transport-node-hid').default;
const signer_wasm = require('@zondax/filecoin-signer');

describe("Ledger device", function () {
  it("Get version", async function () {
      this.timeout(10000);

      const transport = await TransportNodeHid.create();
      var answer = await signer_wasm.getVersionFromDevice(transport);

      console.log(answer);
  });

  it("Get address", async function () {
      this.timeout(10000);
      const path = "m/44'/461'/5/0/3";

      const transport = await TransportNodeHid.create()
      var answer = await signer_wasm.keyRetrieveFromDevice(path, transport);

      console.log(answer);
  });

  it("Show address", async function () {
      this.timeout(10000);
      const path = "m/44'/461'/5/0/3";

      const transport = await TransportNodeHid.create()
      var answer = await signer_wasm.showKeyOnDevice(path, transport);

      console.log(answer);
  });
})

// Failing with Zemu
it.skip("With Zemu", async function () {
    this.timeout(10000);

    const DEMO_APP_PATH = Resolve("bin/app.elf");
    const sim = new Zemu(DEMO_APP_PATH);
    await sim.start({ logging: true });

    const transport = sim.getTransport()
    console.log(transport.exchange)
    var answer = await signer_wasm.getVersionFromDevice(transport);

    console.log(answer);
});
