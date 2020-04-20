const signer = require('@zondax/filecoin-signer');
const DeviceSession = require('@zondax/filecoin-signer').DeviceSession;
const DeviceEnum = require('@zondax/filecoin-signer').DeviceEnum;
const assert = require('assert');
const TransportNodeHid = require('@ledgerhq/hw-transport-node-hid').default;
const secp256k1 = require('secp256k1/elliptic');
const getDigest = require('./utils').getDigest;

describe.skip("LEDGER TEST", function () {
  var transport,
      session;

  beforeEach(async function() {
    // runs before each test in this block
    transport = await TransportNodeHid.create();
    session = new DeviceSession(DeviceEnum.LEDGER, transport);

    //console.log('Initiated')
  });

  afterEach(async function() {
    // runs after each test in this block
    await transport.close();
    // reset
    transport = null;
    session = null;

    //console.log('Reset')
  })

  it("#getVersionFromDevice()", async function() {
    const resp = await signer.getVersionFromDevice(session);

    // eslint-disable-next-line no-console
    console.log(resp);

    //expect(resp.return_code).toEqual(ERROR_CODE.NoError);
    assert.strictEqual(resp.error_message, "No errors");
    assert("test_mode" in resp);
    assert("major" in resp);
    assert("minor" in resp);
    assert("patch" in resp);
    assert(!resp.test_mode);
  });

  it("#keyRetrieveFromDevice()", async function() {
    const path = "m/44'/461'/5'/0/3";
    const resp = await signer.keyRetrieveFromDevice(path, session);

    // eslint-disable-next-line no-console
    console.log(resp);

    //expect(resp.return_code).toEqual(ERROR_CODE.NoError);
    assert.strictEqual(
      resp.error_message,
      "No errors"
    );

    assert("addrByte" in resp);
    assert("addrString" in resp);
    assert("compressed_pk" in resp);

    //expect(resp.compressed_pk.length).toEqual(PKLEN);
    assert.strictEqual(
      resp.compressed_pk.toString("hex"),
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
    // So we have enough time
    this.timeout(60000);

    const path = "m/44'/461'/0'/0/1";
    const resp = await signer.showKeyOnDevice(path, session);

    // eslint-disable-next-line no-console
    console.log(resp);

    assert.strictEqual(resp.return_code, 0x9000);
    assert.strictEqual(resp.error_message, "No errors");

    assert("addrByte" in resp);
    assert("addrString" in resp);
    assert("compressed_pk" in resp);

    //expect(resp.compressed_pk.length).toEqual(PKLEN);
    assert.strictEqual(
      resp.compressed_pk.toString("hex"),
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
    const path = [44, 1, 0, 0, 0];
    const resp = await signer.keyRetrieveFromDevice(path, session);

    // eslint-disable-next-line no-console
    console.log(resp);

    assert.strictEqual(resp.return_code, 0x9000);
    assert.strictEqual(resp.error_message, "No errors");

    assert("addrByte" in resp);
    assert("addrString" in resp);
    assert("compressed_pk" in resp);

    //expect(resp.compressed_pk.length).toEqual(PKLEN);
    assert.strictEqual(
      resp.compressed_pk.toString("hex"),
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
    const resp = await signer.appInfo(session);

    // eslint-disable-next-line no-console
    console.log(resp);

    assert.strictEqual(resp.return_code, 0x9000);
    assert.strictEqual(resp.error_message, "No errors");

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
    const resp = await signer.deviceInfo(session);

    // eslint-disable-next-line no-console
    console.log(resp);

    assert.strictEqual(resp.return_code, 0x9000);
    assert.strictEqual(resp.error_message, "No errors");

    assert("targetId" in resp);
    assert("seVersion" in resp);
    assert("flag" in resp);
    assert("mcuVersion" in resp);
  });

  it("#transactionSignRawWithDevice()", async function() {
    this.timeout(60000);

    // Derivation path. First 3 items are automatically hardened!
    const path = "m/44'/461'/0'/0/0";
    const message = Buffer.from(
      "885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c6285501b882619d46558f3d9e316d11b48dcf211327025a0144000186a0430009c4430061a80040",
      "hex",
    );

    const responsePk = await signer.keyRetrieveFromDevice(path, session);
    const responseSign = await signer.transactionSignRawWithDevice(message, path, session);

    assert.strictEqual(responsePk.return_code, 0x9000);
    assert.strictEqual(responsePk.error_message, "No errors");
    assert.strictEqual(responseSign.return_code, 0x9000);
    assert.strictEqual(responseSign.error_message, "No errors");

    // Calculate message digest
    const msgDigest = getDigest(message);

    // Check signature is valid
    const signatureDER = responseSign.signature_der;
    const signature = secp256k1.signatureImport(signatureDER);

    // Check compact signatures
    const sigBuf = Buffer.from(signature);
    const sigCompBuf = Buffer.from(responseSign.signature_compact.slice(0, 64));

    assert.deepStrictEqual(sigBuf, sigCompBuf);

    const signatureOk = secp256k1.ecdsaVerify(signature, msgDigest, responsePk.compressed_pk);
    assert(signatureOk);
  });

  it("#transactionSignRawWithDevice() Testnet", async function() {
    this.timeout(60000);

    // Derivation path. First 3 items are automatically hardened!
    const path = [44, 1, 0, 0, 0];


    const messageContent = {
      from: "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy",
      to: "t1t5gdjfb6jojpivbl5uek6vf6svlct7dph5q2jwa",
      value: "1000",
      method: 0,
      gasPrice: "1",
      gasLimit: "1000",
      nonce: 0,
    };

    const responsePk = await signer.keyRetrieveFromDevice(path, session);
    const responseSign = await signer.transactionSignRawWithDevice(messageContent, path, session);

    assert.strictEqual(responsePk.return_code, 0x9000);
    assert.strictEqual(responsePk.error_message, "No errors");
    assert.strictEqual(responseSign.return_code, 0x9000);
    assert.strictEqual(responseSign.error_message, "No errors");

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

    const signatureOk = secp256k1.ecdsaVerify(signature, msgDigest, responsePk.compressed_pk);
    assert(signatureOk);

    console.log(`compact   : ${responseSign.signature_compact.toString("base64")}`);
  });

  it("#transactionSignRawWithDevice() Fail", async function() {
    this.timeout(60000);

    const path = "m/44'/461'/0'/0/0";
    let invalidMessage = Buffer.from(
      "88315501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c6285501b882619d46558f3d9e316d11b48dcf211327025a0144000186a0430009c4430061a80040",
      "hex",
    );
    invalidMessage += "1";

    const responseSign = await signer.transactionSignRawWithDevice(path, invalidMessage, session);

    // eslint-disable-next-line no-console
    console.log(responseSign);
    assert.strictEqual(responseSign.return_code, 0x6984);
    assert.strictEqual(
      responseSign.error_message,
      "Data is invalid : Unexpected data type"
    );
  });

})
