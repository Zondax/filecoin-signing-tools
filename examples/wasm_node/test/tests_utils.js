const secp256k1 = require('secp256k1');
const blake2 = require('blake2');
const utils = require('./utils');
var assert = require('assert');

describe("Test for utils.js", function() {
    it("cidBytes", function() {
        const message = Buffer.from(
            "884300e9075501d18cb80b758a3f4e136112ef4c7590c2c0a4691200420001404200010040",
            "hex",
        );

        const expectedCid = Buffer.from(
            "0171a0e4022099e46697a8c0eb7f5c4dd10df6eaf81211bdcffe70bf0c9e7c3e0a6faaa9f432",
            "hex",
        );

        // Calculate message digest
        // cid = prefix + blake2b-256(tx)
        // digest = blake2-256( cid )
        const calculatedCid = utils.getCID(message);
        assert.strictEqual(calculatedCid.toString("hex"), expectedCid.toString("hex"));

        const hasher = blake2.createHash("blake2b", { digestLength: 32 });
        hasher.update(calculatedCid);
        const msgDigest = hasher.digest();
        console.log(msgDigest.toString("hex"));

        //
        // // Check signature is valid
        // const signatureDER = responseSign.signature_der;
        // const signature = secp256k1.signatureImport(signatureDER);
        //
        // // Check compact signatures
        // const sigBuf = Buffer.from(signature);
        // const sigCompBuf = Buffer.from(responseSign.signature_compact.slice(0, 64));
        //
        // expect(sigBuf).toEqual(sigCompBuf);
        //
        // const signatureOk = secp256k1.ecdsaVerify(signature, msgDigest, responsePk.compressed_pk);
        // expect(signatureOk).toEqual(true);
    });

    it("msgDigest", function() {
        const message = Buffer.from(
            "885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c6285501b882619d46558f3d9e316d11b48dcf211327025a0144000186a0430009c4430061a80040",
            "hex",
        );

        const expectedDigest = Buffer.from(
            "5a51287d2e5401b75014da0f050c8db96fe0bacdad75fce964520ca063b697e1",
            "hex",
        );

        const msgDigest = utils.getDigest(message);
        assert.strictEqual(msgDigest.toString("hex"), expectedDigest.toString("hex"));
    });

    it("msgDigest2", function() {
        const message = Buffer.from(
            "884300e90755018ebe704199334c947ee2876baa77eabd4399658400420001404200010040",
            "hex",
        );

        const expectedDigest = Buffer.from(
            "ca79d521db9d024dde2bbd8675721aa0a0f8eab509e85d3280f5754262813c18",
            "hex",
        );

        const msgDigest = utils.getDigest(message);
        assert.strictEqual(msgDigest.toString("hex"), expectedDigest.toString("hex"));
    });

    it("publicFromPrivate", function() {
        const privateKey = Buffer.from("6f48d2978a1cd05bf0110702fd8c2f1e73978dfda66048dad7c6a76e3bb5ab2e", "hex");
        const expectedPubkey =
            "043ba3c9c97454d6d5caaf3fa129228ca7b9aeb0b82de0c3a883fb2a96ea7d27b51a1e84dab69b756f69974ae55d7e20739b186e815143a22dd345720b108fcbe5";

        const pubkey = new Uint8Array(65);
        secp256k1.publicKeyCreate(privateKey, false, pubkey);

        assert.strictEqual(Buffer.from(pubkey).toString("hex"), expectedPubkey);
    });

    it("signature", function() {
        const privateKey = Buffer.from("b6e3f4e621e89656ed1f3a34023e8204a9f3416fdf6f4ba57f9a4c8971a91341", "hex");
        const message = Buffer.from(
            "884300e9075501f7c7cd6e87ca5cc5782b259c389f46f52617569c00420001404200010040",
            "hex",
        );
        const expectedSignature =
            "8808dead9bd0d6953e7519f8a7ffd07eac98313f645c792664146b7727e33d782b6a3c803949c5520cb73869a003e59f173f0f9326fd2d8825e1a1d9df59afb201";

        const pubkey = new Uint8Array(65);
        secp256k1.publicKeyCreate(privateKey, false, pubkey);

        const digest = utils.getDigest(message);
        const signature = secp256k1.ecdsaSign(digest, privateKey);

        const sigStr =
            Buffer.from(signature.signature).toString("hex") + Buffer.from([signature.recid]).toString("hex");

        console.log(sigStr);
        assert.strictEqual(sigStr, expectedSignature);
    });
})
