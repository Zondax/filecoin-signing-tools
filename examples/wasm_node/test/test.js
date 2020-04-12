const signer_wasm = require('@zondax/filecoin-signer-wasm');
const bip32 = require('bip32');
const bip39 = require('bip39');
const getDigest = require('./utils').getDigest;
const secp256k1 = require('secp256k1');
const fs = require('fs');
const assert = require('assert');

const EXAMPLE_MNEMONIC = "equip will roof matter pink blind book anxiety banner elbow sun young";

const EXAMPLE_CBOR_TX = "885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c6285501b882619d46558f3d9e316d11b48dcf211327025a0144000186a0430009c41961a80040";

const EXAMPLE_TRANSACTION = {
    "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
    "from": "t1xcbgdhkgkwht3hrrnui3jdopeejsoas2rujnkdi",
    "nonce": 1,
    "value": "100000",
    "gasprice": "2500",
    "gaslimit": 25000,
    "method": 0,
    "params": ""
};

const MASTER_KEY = "xprv9s21ZrQH143K49QgrAgAVELf6ue2tZNHYUc7yfj8JGZY9SpZ38u8EfhWi85GsA6grUeB36wXrbNTkjX9EfGP1ybbPRG4sdP2EPfY1SZ2BF5";
let MASTER_NODE = bip32.fromBase58(MASTER_KEY);

describe('Serialization / Deserialization', function () {
    it('Valid cbor should be fine', function () {
        assert.strictEqual(JSON.stringify(EXAMPLE_TRANSACTION), signer_wasm.transaction_parse(EXAMPLE_CBOR_TX, true))
    });

    it('Extra bytes should fail', function () {
        let cbor_transaction_extra_bytes = EXAMPLE_CBOR_TX + "00";

        assert.throws(
            () => signer_wasm.transaction_parse(cbor_transaction_extra_bytes,),
            /CBOR error/
        );
    });

    it('Serialize Transaction', () => {
        assert.strictEqual(EXAMPLE_CBOR_TX, signer_wasm.transaction_serialize(JSON.stringify(EXAMPLE_TRANSACTION)))
    });

    it('Serialize Transaction Fail (missing nonce)', () => {
        let invalid_transaction = {
            "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
            "from": "t1xcbgdhkgkwht3hrrnui3jdopeejsoas2rujnkdi",
            "value": "100000",
            "gasprice": "2500",
            "gaslimit": 25000,
            "method": 0,
            "params": ""
        };

        assert.throws(
            () => signer_wasm.transaction_serialize(JSON.stringify(invalid_transaction)),
            /missing field `nonce`/
        );
    });
});

describe('Key generation / derivation', function () {
    it('Key Generate Mnemonic', () => {
        const mnemonic = signer_wasm.mnemonic_generate();
        console.log(mnemonic);
        assert.strictEqual(mnemonic.split(" ").length, 24);
    });

    it('Key Derive', () => {
        const keypair = signer_wasm.key_derive(EXAMPLE_MNEMONIC, "m/44'/461'/0/0/1");

        console.log("Public Key Raw         :", keypair.public_raw);
        console.log("Public Key             :", keypair.public_hexstring);
        console.log("Public Key Compressed  :", keypair.public_compressed_hexstring);
        console.log("Private                :", keypair.private_hexstring);
        console.log("Address                :", keypair.address);

        const expected_keys = MASTER_NODE.derivePath("m/44'/461'/0/0/1");
        assert.strictEqual(keypair.private_hexstring, expected_keys.privateKey.toString("hex"));
        assert.strictEqual(keypair.address, "t1rovwtiuo5ncslpmpjftzu5akswbgsgighjazxoi");
    });

    it('Key Derive From Seed', () => {
        const seed = bip39.mnemonicToSeedSync(EXAMPLE_MNEMONIC).toString('hex');

        const keypair = signer_wasm.key_derive_from_seed(seed, "m/44'/461'/0/0/1");

        console.log("Public Key Raw         :", keypair.public_raw);
        console.log("Public Key             :", keypair.public_hexstring);
        console.log("Public Key Compressed  :", keypair.public_compressed_hexstring);
        console.log("Private                :", keypair.private_hexstring);
        console.log("Address                :", keypair.address);

        const expected_keys = MASTER_NODE.derivePath("m/44'/461'/0/0/1");
        assert.strictEqual(keypair.private_hexstring, expected_keys.privateKey.toString("hex"));
        assert.strictEqual(keypair.address, "t1rovwtiuo5ncslpmpjftzu5akswbgsgighjazxoi");
    });

    it('Key Derive Invalid Path', () => {
        assert.throws(
            () => signer_wasm.key_derive(EXAMPLE_MNEMONIC, "m/44'/461'/a/0/1"),
            /Cannot parse integer/
        );
    });

    it('Sign Transaction', () => {
        const example_key = MASTER_NODE.derivePath("m/44'/461'/0/0/0");

        var signed_tx = signer_wasm.transaction_sign(EXAMPLE_TRANSACTION, example_key.privateKey.toString("hex"));
        console.log(signed_tx.signature);
        const signature = Buffer.from(signed_tx.signature.data, 'base64');

        let message_digest = getDigest(Buffer.from(EXAMPLE_CBOR_TX, 'hex'));

        // Signature representation is R, S & V
        console.log("Signature  :", signature.toString('hex'));
        console.log("Digest     :", message_digest.toString('hex'));
        console.log("Public key :", example_key.publicKey.toString('hex'));

        assert.strictEqual(
            true,
            // Remove the V value from the signature (last byte)
            secp256k1.ecdsaVerify(signature.slice(0, -1), message_digest, example_key.publicKey)
        );

        // Verify recovery id which is the last byte of the signature
        assert.strictEqual(0x01, signature[64]);
    });

    it('Verify signature', () => {
        let child = MASTER_NODE.derivePath("m/44'/461'/0/0/0");
        let message_digest = getDigest(Buffer.from(EXAMPLE_CBOR_TX, 'hex'));

        // Get hex signature in the format (R,S)
        let signature = secp256k1.ecdsaSign(message_digest, child.privateKey);

        // Concat v value at the end of the signature
        let signatureRSV =
            Buffer.from(signature.signature).toString('hex') +
            Buffer.from([signature.recid]).toString('hex');

        console.log("RSV signature :", signatureRSV);
        console.log("CBOR Transaction hex :", EXAMPLE_CBOR_TX);

        console.log(signatureRSV)
        console.log(EXAMPLE_CBOR_TX)

        assert.equal(signer_wasm.verify_signature(signatureRSV, EXAMPLE_CBOR_TX), true);
    });
});

describe('Key Recover testnet/mainnet', function () {
    it("key recover testnet", () => {
        let child = MASTER_NODE.derivePath("m/44'/461'/0/0/0");
        let privateKey = child.privateKey.toString('hex');

        let recoveredKey = signer_wasm.key_recover(privateKey, true);

        console.log("Public Key Raw         :", recoveredKey.public_raw);
        console.log("Public Key             :", recoveredKey.public_hexstring);
        console.log("Public Key Compressed  :", recoveredKey.public_compressed_hexstring);
        console.log("Private                :", recoveredKey.private_hexstring);
        console.log("Address                :", recoveredKey.address);

        assert.equal(recoveredKey.private_hexstring, child.privateKey.toString("hex"));
        assert.equal(recoveredKey.address, "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba");
    });

    it("key recover mainnet", () => {
        let child = MASTER_NODE.derivePath("m/44'/461'/0/0/0");
        let privateKey = child.privateKey.toString('hex');

        let recoveredKey = signer_wasm.key_recover(privateKey, false);

        console.log("Public Key Raw         :", recoveredKey.public_raw);
        console.log("Public Key             :", recoveredKey.public_hexstring);
        console.log("Public Key Compressed  :", recoveredKey.public_compressed_hexstring);
        console.log("Private                :", recoveredKey.private_hexstring);
        console.log("Address                :", recoveredKey.address);

        assert.equal(recoveredKey.private_hexstring, child.privateKey.toString("hex"));
        assert.equal(recoveredKey.address, "f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba");
    })
});

//////////////////////////////////////
// Parameterized tests
const tests_vectors_path = "../manual_testvectors.json";
let rawData = fs.readFileSync(tests_vectors_path);
let jsonData = JSON.parse(rawData);

describe('Parameterized Tests - Serialize', function () {
    for (let i = 0; i < jsonData.length; i += 1) {
        let tc = jsonData[i];
        if (!tc.message.params) {
            tc.message["params"] = ""
        }

        it("Create Transaction : " + tc.description, () => {
            if (tc.valid) {
                // Valid doesn't throw
                let result = signer_wasm.transaction_serialize(JSON.stringify(tc.message));
                assert.equal(tc.encoded_tx_hex, result);
            } else {
                // Not valid throw error
                // TODO: Add error type to manual_testvectors.json file
                assert.throws(
                    () => signer_wasm.transaction_serialize(JSON.stringify(tc.message)),
                    /Error/
                );
            }
        });
    }
});

describe('Parameterized Tests - Deserialize', function () {
    for (let i = 0; i < jsonData.length; i += 1) {
        let tc = jsonData[i];
        if (!tc.message.params) {
            tc.message["params"] = ""
        }

        if (tc.not_implemented) {
            // FIXME: Protocol 0 parsing not implemented in forest
            // FIXME: doesn't fail for empty value #54
            console.log("FIX ME");
            continue;
        }

        // Create test case for each
        it("Parse Transaction : " + tc.description, () => {
            if (tc.valid) {
                let result = signer_wasm.transaction_parse(tc.encoded_tx_hex, tc.testnet);
                assert.equal(JSON.stringify(tc.message), result);
            } else {
                // Not valid throw error
                // TODO: Add error type to manual_testvectors.json file
                assert.throws(
                    () => signer_wasm.transaction_parse(tc.encoded_tx_hex, tc.testnet),
                    /error/
                );
            }
        })
    }
});
