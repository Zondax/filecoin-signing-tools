const signer = require('@zondax/filecoin-signing-tools');
const assert = require('assert');
const secp256k1 = require('secp256k1/elliptic');
const getDigest = require('./utils').getDigest;
const Resolve = require("path").resolve;
const Zemu = require("@zondax/zemu").default;
const fs = require("fs");

/* Load multisig test data */
let rawdataTxs = fs.readFileSync('../../test_vectors/txs.json')
let dataTxs = JSON.parse(rawdataTxs)

/* Load wallet test data */
let rawdataWallet = fs.readFileSync('../../test_vectors/wallet.json')
let dataWallet = JSON.parse(rawdataWallet)

const catchExit = async () => {
  process.on("SIGINT", () => {
    Zemu.stopAllEmuContainers(function () {
      process.exit();
    });
  });
};


describe("LEDGER TEST", function () {
  this.timeout(80000);

  var sim,
      transport;

  before(async function() {
    // runs before tests start
    await catchExit();
    await Zemu.checkAndPullImage();
    await Zemu.stopAllEmuContainers();
  })

  beforeEach(async function() {
    const DEMO_APP_PATH = Resolve("bin/app.elf");
    sim = new Zemu(DEMO_APP_PATH);
    const sim_options = {
        logging: true,
        custom: `-s "${dataWallet.mnemonic}"`,
        press_delay: 150
        //,X11: true
    };

    await sim.start(sim_options);

    transport = sim.getTransport();
  });

  afterEach(async function() {
    // runs after all the test are done
    await sim.close();
    // reset
    transport = null;
  })

  it("#getVersionFromDevice()", async function() {
    const resp = await signer.getVersion(transport);

    assert("test_mode" in resp);
    assert("major" in resp);
    assert("minor" in resp);
    assert("patch" in resp);
    assert(!resp.test_mode);
  });

  it("#keyRetrieveFromDevice()", async function() {
    const resp = await signer.keyRetrieveFromDevice(dataWallet.childs[0].path, transport);

    assert("addrByte" in resp);
    assert("addrString" in resp);
    assert("publicKey" in resp);

    assert.strictEqual(
      resp.addrString,
      dataWallet.childs[0].address
    );
  });

  it("#showKeyOnDevice()", async function() {
    const respRequest = signer.showKeyOnDevice(dataWallet.childs[0].path, transport);
    await Zemu.sleep(2000);

    // click right
    await sim.clickRight();
    await sim.clickRight();
    await sim.clickRight();
    await sim.clickRight();
    await sim.clickBoth();

    const resp = await respRequest;

    assert("addrByte" in resp);
    assert("addrString" in resp);
    assert("publicKey" in resp);

    assert.strictEqual(
      resp.addrString,
      dataWallet.childs[0].address
    );
  });

  it("#keyRetrieveFromDevice() Testnet", async function() {
    const resp = await signer.keyRetrieveFromDevice(dataWallet.childs[2].path, transport);

    assert("addrByte" in resp);
    assert("addrString" in resp);
    assert("publicKey" in resp);

    assert.strictEqual(
      resp.addrString,
      dataWallet.childs[2].address
    );
  });

  it("deviceInfo", async function() {
    const resp = await signer.deviceInfo(transport);

    assert("targetId" in resp);
    assert("seVersion" in resp);
    assert("flag" in resp);
    assert("mcuVersion" in resp);
  });

  it("#transactionSignRawWithDevice()", async function() {
    this.timeout(50000);

    const message = Buffer.from(dataTxs[0].cbor, "hex");

    const responsePk = await signer.keyRetrieveFromDevice(dataWallet.childs[3].path, transport);
    const responseRequest = signer.transactionSignRawWithDevice(message, path, transport);
    // Wait until we are not in the main menu
    await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

    for (let i = 0; i < 9; i++) {
      await sim.clickRight();
    }
    await sim.clickBoth();

    const responseSign = await responseRequest;

    // Calculate message digest
    const msgDigest = getDigest(message);

    // Check signature is valid
    const signatureDER = responseSign.signature_der;
    const signature = secp256k1.signatureImport(signatureDER);

    // Check compact signatures
    const sigBuf = Buffer.from(signature);
    const sigCompBuf = Buffer.from(responseSign.signature_compact.slice(0, 64));

    assert.deepStrictEqual(sigBuf, sigCompBuf);

    const compressedPublicKey = secp256k1.publicKeyConvert(responsePk.publicKey, true);
    const signatureOk = secp256k1.ecdsaVerify(signature, msgDigest, compressedPublicKey);
    assert(signatureOk);
  });

  it("#transactionSignWithDevice() Testnet", async function() {
    this.timeout(50000);

    const responsePk = await signer.keyRetrieveFromDevice(dataWallet.childs[3].path, transport);
    const responseRequest = signer.transactionSignWithDevice(dataTxs[0].transaction, dataWallet.childs[3].path, transport);
    // Wait until we are not in the main menu
    await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());
    
    for (let i = 0; i < 9; i++) {
      await sim.clickRight();
    }
    await sim.clickBoth();

    const responseSign = await responseRequest;
    
    let result = signer.verifySignature(responseSign.signature.data, dataTxs[0].cbor);
    assert(result);
  });

  it.skip("#transactionSignRawWithDevice() Fail", async function() {
    this.timeout(40000);

    let invalidMessage = Buffer.from(
      "89005501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855011eaf1c8a4bbfeeb0870b1745b1f57503470b71160144000186a0430009c41961a80040" + "01",
      "hex",
    );

    const responseRequest = signer.transactionSignRawWithDevice(invalidMessage, dataWallet.childs[3].path, transport);
    // Wait until we are not in the main menu
    await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

    try {
      const responseSign = await responseRequest;
    } catch(e) {
      console.log(e)
      assert.strictEqual(e.return_code, 0x6984);
      assert.strictEqual(
        e.error_message,
        "[APDU_CODE_DATA_INVALID] data reversibly blocked (invalidated)"
      );

      return
    }

    assert(false);

  });

})
