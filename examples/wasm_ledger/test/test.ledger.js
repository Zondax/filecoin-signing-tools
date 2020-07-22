const signer = require('@zondax/filecoin-signing-tools');
const assert = require('assert');
const secp256k1 = require('secp256k1/elliptic');
const getDigest = require('./utils').getDigest;
const Resolve = require("path").resolve;
const Zemu = require("@zondax/zemu").default;

const catchExit = async () => {
  process.on("SIGINT", () => {
    Zemu.stopAllEmuContainers(function () {
      process.exit();
    });
  });
};


describe("LEDGER TEST", function () {
  this.timeout(20000);

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
    const APP_SEED = "equip will roof matter pink blind book anxiety banner elbow sun young";
    const sim_options = {
        logging: true,
        custom: `-s "${APP_SEED}"`,
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

    // eslint-disable-next-line no-console
    console.log(resp);

    assert("test_mode" in resp);
    assert("major" in resp);
    assert("minor" in resp);
    assert("patch" in resp);
    assert(!resp.test_mode);
  });

  it("#keyRetrieveFromDevice()", async function() {
    const path = "m/44'/461'/5/0/3";
    const resp = await signer.keyRetrieveFromDevice(path, transport);

    // eslint-disable-next-line no-console
    console.log(resp);

    assert("addrByte" in resp);
    assert("addrString" in resp);
    assert("publicKey" in resp);

    assert.strictEqual(
      resp.publicKey.toString("hex"),
      "04240ecf6ec722b701f051aaaffde7455a56e433139e4c0ff2ad7c8675e2cce104a8027ba13e5bc640ec9932cce184f33a789bb9c32f41e34328118b7862fc9ca2",
    );

    assert.strictEqual(
      resp.addrByte.toString("hex"),
      "0175a6b113220c2f71c4db420753aab2cef5edb6a8"
    );

    assert.strictEqual(
      resp.addrString,
      "f1owtlcezcbqxxdrg3iidvhkvsz3263nvijwpumui"
    );
  });

  it("#showKeyOnDevice()", async function() {
    const path = "m/44'/461'/0/0/1";
    const respRequest = signer.showKeyOnDevice(path, transport);
    await Zemu.sleep(2000);

    // click right
    await sim.clickRight();
    await sim.clickRight();
    await sim.clickRight();
    await sim.clickRight();
    await sim.clickBoth();

    const resp = await respRequest;

    // eslint-disable-next-line no-console
    console.log(resp);

    assert("addrByte" in resp);
    assert("addrString" in resp);
    assert("publicKey" in resp);

    assert.strictEqual(
      resp.publicKey.toString("hex"),
      "04fc016f3d88dc7070cdd95b5754d32fd5290f850b7c2208fca0f715d35861de1841d9a342a487692a63810a6c906b443a18aa804d9d508d69facc5b06789a01b4",
    );

    assert.strictEqual(
      resp.addrByte.toString("hex"),
      "018bab69a28eeb4525bd8f49679a740a9582691906"
    );

    assert.strictEqual(
      resp.addrString,
      "f1rovwtiuo5ncslpmpjftzu5akswbgsgighjazxoi"
    );
  });

  it("#keyRetrieveFromDevice() Testnet", async function() {
    const path = "m/44'/1'/0/0/0";
    const resp = await signer.keyRetrieveFromDevice(path, transport);

    // eslint-disable-next-line no-console
    console.log(resp);

    assert("addrByte" in resp);
    assert("addrString" in resp);
    assert("publicKey" in resp);

    assert.strictEqual(
      resp.publicKey.toString("hex"),
      "0466f2bdb19e90fd7c29e4bf63612eb98515e5163c97888042364ba777d818e88b765c649056ba4a62292ae4e2ccdabd71b845d8fa0991c140f664d2978ac0972a",
    );

    assert.strictEqual(
      resp.addrByte.toString("hex"),
      "01dfe49184d46adc8f89d44638beb45f78fcad2590"
    );

    assert.strictEqual(
      resp.addrString,
      "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy"
    );
  });

  it("#appInfo()", async function() {
    const resp = await signer.appInfo(transport);

    // eslint-disable-next-line no-console
    console.log(resp);

    assert("appName" in resp);
    assert("appVersion" in resp);
    assert("flagLen" in resp);
    assert("flagsValue" in resp);
    assert("flag_recovery" in resp );
    assert("flag_signed_mcu_code" in resp);
    assert("flag_onboarded" in resp);
    assert("flag_pin_validated" in resp);
  });

  it("deviceInfo", async function() {
    const resp = await signer.deviceInfo(transport);

    // eslint-disable-next-line no-console
    console.log(resp);

    assert("targetId" in resp);
    assert("seVersion" in resp);
    assert("flag" in resp);
    assert("mcuVersion" in resp);
  });

  it("#transactionSignRawWithDevice()", async function() {
    this.timeout(20000);

    const path = "m/44'/461'/0/0/0";
    const message = Buffer.from(
      "89005501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855011eaf1c8a4bbfeeb0870b1745b1f57503470b71160144000186a0430009c41961a80040",
      "hex",
    );

    const responsePk = await signer.keyRetrieveFromDevice(path, transport);
    console.log(responsePk)
    const responseRequest = signer.transactionSignRawWithDevice(message, path, transport);
    await Zemu.sleep(2000);

    await sim.clickBoth();
    await sim.clickRight();
    await sim.clickBoth();

    const responseSign = await responseRequest;

    console.log(responseSign)

    // Calculate message digest
    const msgDigest = getDigest(message);

    // Check signature is valid
    const signatureDER = responseSign.signature_der;
    const signature = secp256k1.signatureImport(signatureDER);

    // Check compact signatures
    const sigBuf = Buffer.from(signature);
    const sigCompBuf = Buffer.from(responseSign.signature_compact.slice(0, 64));

    assert.deepStrictEqual(sigBuf, sigCompBuf);

    const compressedPublicKey = secp256k1.publicKeyConvert(responsePk.publicKey, true)
    const signatureOk = secp256k1.ecdsaVerify(signature, msgDigest, compressedPublicKey);
    assert(signatureOk);
  });

  it.skip("#transactionSignWithDevice() Testnet", async function() {
    const path = "m/44'/1'/0/0/0";
    const messageContent = {
      from: "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy",
      to: "t1t5gdjfb6jojpivbl5uek6vf6svlct7dph5q2jwa",
      value: "1000",
      method: 0,
      gasPrice: "1",
      gasLimit: 1000,
      nonce: 0,
      params: ""
    };

    const responsePk = await signer.keyRetrieveFromDevice(path, transport);
    console.log(responsePk)
    const responseRequest = signer.transactionSignWithDevice(messageContent, path, transport);
    await Zemu.sleep(2000);

    await sim.clickLeft();
    await sim.clickRight();
    await sim.clickBoth();

    const responseSign = await responseRequest;

    console.log(responseSign);

    // Calculate message digest
    const msgDigest = getDigest(message);
    console.log(`Digest: ${msgDigest.toString("hex")}`);

    // Check signature is valid
    const signatureDER = responseSign.signature_der;
    const signature = secp256k1.signatureImport(signatureDER);
    console.log(`DER   : ${responseSign.signature_der.toString("hex")}`);

    // Check compact signatures
    const sigBuf = Buffer.from(signature);
    const sigCompBuf = Buffer.from(responseSign.signature_compact.slice(0, 64));
    console.log(`compact   : ${Buffer.from(responseSign.signature_compact).toString("hex")}`);

    assert.deepStrictEqual(sigBuf, sigCompBuf);

    const compressedPublicKey = secp256k1.publicKeyConvert(responsePk.publicKey, true)
    const signatureOk = secp256k1.ecdsaVerify(signature, msgDigest, compressedPublicKey);
    assert(signatureOk);

    console.log(`compact   : ${responseSign.signature_compact.toString("base64")}`);
  });

  it.skip("#transactionSignRawWithDevice() Fail", async function() {
    this.timeout(20000);

    const path = "m/44'/461'/0/0/0";
    let invalidMessage = Buffer.from(
      "89005501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855011eaf1c8a4bbfeeb0870b1745b1f57503470b71160144000186a0430009c41961a80040" + "01",
      "hex",
    );

    const responseRequest = signer.transactionSignRawWithDevice(invalidMessage, path, transport);


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
