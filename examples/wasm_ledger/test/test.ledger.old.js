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
const FilecoinApp = require("@zondax/ledger-filecoin").default;
const Resolve = require("path").resolve;

const signer_wasm = require('@zondax/filecoin-signer');

const EXAMPLE_CBOR_TX = "885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855010f323f4709e8e4db0c1d4cd374f9f35201d26fb20144000186a0430009c41961a80040";

it("empty", async function () {
    this.timeout(10000);

    const DEMO_APP_PATH = Resolve("bin/app.elf");
    const sim = new Zemu(DEMO_APP_PATH);
    await sim.start({ logging: true });

    const app = new FilecoinApp(sim.getTransport());
    const resp = await app.getVersion();

    signer_wasm.transactionParse(EXAMPLE_CBOR_TX, true);

    console.log(resp);

    await sim.close();
});

/*
jest.setTimeout(10000);
const DEMO_APP_PATH = Resolve("bin/demoApp/app.elf");

test("Zemu-Start&Close", async () => {
  const sim = new Zemu(DEMO_APP_PATH);
  expect(sim).not.toBeNull();
  try {
    await sim.start(true);
  } finally {
    await sim.close();
  }
});

test("Zemu-Snapshot", async () => {
  const sim = new Zemu(DEMO_APP_PATH);
  try {
    await sim.start();
    expect(sim.session.title).toEqual("LibVNCServer");
    expect(sim.session.width).toEqual(128);
    expect(sim.session.height).toEqual(32);

    const snapshot = await sim.snapshot();
    expect(snapshot.width).toEqual(128);
    expect(snapshot.height).toEqual(32);
  } finally {
    await sim.close();
  }
});

test("Zemu-Basic Control", async () => {
  const sim = new Zemu(DEMO_APP_PATH);
  try {
    await sim.start();

    await sim.clickLeft();
    await sim.clickLeft();
    await sim.clickLeft();

    // Move up and down and check screens
    const view0 = await sim.snapshot("tests/snapshots/0.png");
    const view1 = await sim.clickRight("tests/snapshots/1.png");
    const view2 = await sim.clickLeft("tests/snapshots/2.png");

    // compare to check that it went back to the same view
    expect(view2).toEqual(view0);
    expect(view1).not.toEqual(view0);
  } finally {
    await sim.close();
  }
});


 */
