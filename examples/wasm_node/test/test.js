const signer_wasm = require('@zondax/filecoin-signer');
const bip32 = require('bip32');
const bip39 = require('bip39');
const getDigest = require('./utils').getDigest;
const secp256k1 = require('secp256k1');
const fs = require('fs');
const assert = require('assert');

const EXAMPLE_MNEMONIC = "equip will roof matter pink blind book anxiety banner elbow sun young";

const EXAMPLE_CBOR_TX = "885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855010f323f4709e8e4db0c1d4cd374f9f35201d26fb20144000186a0430009c41961a80040";

const EXAMPLE_TRANSACTION = {
    "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
    "from": "t1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka",
    "nonce": 1,
    "value": "100000",
    "gasprice": "2500",
    "gaslimit": 25000,
    "method": 0,
    "params": ""
};

const EXAMPLE_TRANSACTION_MAINNET = {
    "to": "f17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
    "from": "f1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka",
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
        assert.deepStrictEqual(EXAMPLE_TRANSACTION, signer_wasm.transactionParse(EXAMPLE_CBOR_TX, true))
    });

    it('Valid cbor should be fine - missing is undefined converted to false', function () {
        assert.deepStrictEqual(EXAMPLE_TRANSACTION_MAINNET, signer_wasm.transactionParse(EXAMPLE_CBOR_TX, false));
    });

    it('Extra bytes should fail', function () {
        let cbor_transaction_extra_bytes = EXAMPLE_CBOR_TX + "00";

        assert.throws(
            () => signer_wasm.transactionParse(cbor_transaction_extra_bytes, false),
            /CBOR error: 'trailing data at offset 61'/
        );
    });

    it('Serialize Transaction', () => {
        assert.strictEqual(EXAMPLE_CBOR_TX, signer_wasm.transactionSerialize(EXAMPLE_TRANSACTION));
    });

    it('Serialize Transaction return buffer', () => {
        let cbor_uint8_array = signer_wasm.transaction_serialize_raw(EXAMPLE_TRANSACTION);
        assert.strictEqual(EXAMPLE_CBOR_TX, Buffer.from(cbor_uint8_array).toString('hex'));
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
            () => signer_wasm.transactionSerialize(invalid_transaction),
            /missing field `nonce`/
        );
    });
});

describe('Key generation / derivation', function () {
    it('Key Generate Mnemonic', () => {
        const mnemonic = signer_wasm.generateMnemonic();
        console.log(mnemonic);
        assert.strictEqual(mnemonic.split(" ").length, 24);
    });

    it('Key Derive', () => {
        const keypair = signer_wasm.keyDerive(EXAMPLE_MNEMONIC, "m/44'/461'/0/0/1", "");

        console.log("Public Key Raw         :", keypair.public_raw);
        console.log("Public Key             :", keypair.public_hexstring);
        console.log("Public Key Compressed  :", keypair.public_compressed_hexstring);
        console.log("Private                :", keypair.private_hexstring);
        console.log("Address                :", keypair.address);

        const expected_keys = MASTER_NODE.derivePath("m/44'/461'/0/0/1");
        assert.strictEqual(keypair.private_hexstring, expected_keys.privateKey.toString("hex"));
        assert.strictEqual(keypair.address, "f1rovwtiuo5ncslpmpjftzu5akswbgsgighjazxoi");
    });

    it('Key Derive testnet', () => {
        const keypair = signer_wasm.key_derive(EXAMPLE_MNEMONIC, "m/44'/1'/0/0/1", "");

        console.log("Public Key Raw         :", keypair.public_raw);
        console.log("Public Key             :", keypair.public_hexstring);
        console.log("Public Key Compressed  :", keypair.public_compressed_hexstring);
        console.log("Private                :", keypair.private_hexstring);
        console.log("Address                :", keypair.address);

        const expected_keys = MASTER_NODE.derivePath("m/44'/1'/0/0/1");
        assert.strictEqual(keypair.private_hexstring, expected_keys.privateKey.toString("hex"));
        assert(keypair.address.startsWith('t'));
    });

    it('Key Derive missing password', () => {
        assert.throws(() => {
                signer_wasm.key_derive(EXAMPLE_MNEMONIC, "m/44'/461'/0/0/1")
            },
            /argument must be of type string or an instance of Buffer or ArrayBuffer. Received undefined/
        );
    });

    it('Key Derive with password', () => {
        const keypair = signer_wasm.key_derive(EXAMPLE_MNEMONIC, "m/44'/461'/0/0/1", "password");

        console.log("Public Key Raw         :", keypair.public_raw);
        console.log("Public Key             :", keypair.public_hexstring);
        console.log("Public Key Compressed  :", keypair.public_compressed_hexstring);
        console.log("Private                :", keypair.private_hexstring);
        console.log("Address                :", keypair.address);

        const seed = bip39.mnemonicToSeedSync(EXAMPLE_MNEMONIC, "password");
        const node = bip32.fromSeed(seed);

        const expected_keys = node.derivePath("m/44'/461'/0/0/1");
        assert.strictEqual(keypair.private_hexstring, expected_keys.privateKey.toString("hex"));
    });

    it('Key Derive with different password', () => {
        const keypair = signer_wasm.key_derive(EXAMPLE_MNEMONIC, "m/44'/461'/0/0/1", "password");

        console.log("Public Key Raw         :", keypair.public_raw);
        console.log("Public Key             :", keypair.public_hexstring);
        console.log("Public Key Compressed  :", keypair.public_compressed_hexstring);
        console.log("Private                :", keypair.private_hexstring);
        console.log("Address                :", keypair.address);

        const seed = bip39.mnemonicToSeedSync(EXAMPLE_MNEMONIC, "lol");
        const node = bip32.fromSeed(seed);

        const expected_keys = node.derivePath("m/44'/461'/0/0/1");
        assert.notEqual(keypair.private_hexstring, expected_keys.privateKey.toString("hex"));
    });

    it('Key Derive invalid paswword type (throw)', () => {
        assert.throws(
            () => signer_wasm.key_derive(EXAMPLE_MNEMONIC, "m/44'/461'/0/0/1", 123),
            /Error/
        );
    });

    it('Key Derive From Seed', () => {
        const seed = bip39.mnemonicToSeedSync(EXAMPLE_MNEMONIC).toString('hex');

        const keypair = signer_wasm.keyDeriveFromSeed(seed, "m/44'/461'/0/0/1");

        console.log("Public Key Raw         :", keypair.public_raw);
        console.log("Public Key             :", keypair.public_hexstring);
        console.log("Public Key Compressed  :", keypair.public_compressed_hexstring);
        console.log("Private                :", keypair.private_hexstring);
        console.log("Address                :", keypair.address);

        const expected_keys = MASTER_NODE.derivePath("m/44'/461'/0/0/1");
        assert.strictEqual(keypair.private_hexstring, expected_keys.privateKey.toString("hex"));
        assert.strictEqual(keypair.address, "f1rovwtiuo5ncslpmpjftzu5akswbgsgighjazxoi");
    });

    it('Key Derive From Seed Buffer', () => {
        const seed = bip39.mnemonicToSeedSync(EXAMPLE_MNEMONIC);

        const keypair = signer_wasm.key_derive_from_seed(seed, "m/44'/461'/0/0/1");

        console.log("Public Key Raw         :", keypair.public_raw);
        console.log("Public Key             :", keypair.public_hexstring);
        console.log("Public Key Compressed  :", keypair.public_compressed_hexstring);
        console.log("Private                :", keypair.private_hexstring);
        console.log("Address                :", keypair.address);

        const expected_keys = MASTER_NODE.derivePath("m/44'/461'/0/0/1");
        assert.strictEqual(keypair.private_hexstring, expected_keys.privateKey.toString("hex"));
        assert.strictEqual(keypair.address, "f1rovwtiuo5ncslpmpjftzu5akswbgsgighjazxoi");
    });

    it('Key Derive Invalid Path', () => {
        assert.throws(
            () => signer_wasm.keyDerive(EXAMPLE_MNEMONIC, "m/44'/461'/a/0/1", ""),
            /Cannot parse integer/
        );
    });

    it('Sign Transaction', () => {
        const example_key = MASTER_NODE.derivePath("m/44'/461'/0/0/0");

        var signed_tx = signer_wasm.transactionSign(EXAMPLE_TRANSACTION, example_key.privateKey.toString("hex"));
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

        assert.equal(signer_wasm.verifySignature(signatureRSV, EXAMPLE_CBOR_TX), true);
    });
});

describe('Key Recover testnet/mainnet', function () {
    it("key recover testnet", () => {
        let child = MASTER_NODE.derivePath("m/44'/461'/0/0/0");
        let privateKey = child.privateKey.toString('hex');

        let recoveredKey = signer_wasm.keyRecover(privateKey, true);

        console.log("Public Key Raw         :", recoveredKey.public_raw);
        console.log("Public Key             :", recoveredKey.public_hexstring);
        console.log("Public Key Compressed  :", recoveredKey.public_compressed_hexstring);
        console.log("Private                :", recoveredKey.private_hexstring);
        console.log("Address                :", recoveredKey.address);

        assert.equal(recoveredKey.private_hexstring, child.privateKey.toString("hex"));
        assert.equal(recoveredKey.address, "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba");
    });

    it("key recover testnet buffer", () => {
        let child = MASTER_NODE.derivePath("m/44'/461'/0/0/0");
        let privateKey = child.privateKey;

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

        let recoveredKey = signer_wasm.keyRecover(privateKey, false);

        console.log("Public Key Raw         :", recoveredKey.public_raw);
        console.log("Public Key             :", recoveredKey.public_hexstring);
        console.log("Public Key Compressed  :", recoveredKey.public_compressed_hexstring);
        console.log("Private                :", recoveredKey.private_hexstring);
        console.log("Address                :", recoveredKey.address);

        assert.equal(recoveredKey.private_hexstring, child.privateKey.toString("hex"));
        assert.equal(recoveredKey.address, "f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba");
    })
});

const bls_tests_vectors_path = "../generated_test_cases.json";
let rawBLSData = fs.readFileSync(bls_tests_vectors_path);
let jsonBLSData = JSON.parse(rawBLSData);

describe('BLS support', function () {

    for (let i = 0; i < jsonBLSData.length; i += 1) {
        let tc = jsonBLSData[i];

        it(`BLS signing test case n°${i}`, function () {
            var signed_tx = signer_wasm.transaction_sign(tc.message, tc.sk);

            const signature = Buffer.from(signed_tx.signature.data, 'base64');

            // Signature representation is R, S & V
            console.log("Signature  :", signature.toString('hex'));
            console.log("Private key:", tc.sk);
            console.log("Public key :", tc.pk);

            assert.equal(signature.length, 96);

            assert.equal(signature.toString('hex'), tc.sig);

        })
    }
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
                let result = signer_wasm.transactionSerialize(tc.message);
                assert.equal(tc.encoded_tx_hex, result);
            } else {
                // Not valid throw error
                // TODO: Add error type to manual_testvectors.json file
                assert.throws(
                    () => signer_wasm.transactionSerialize(tc.message),
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
            console.log("FIXME: Protocol 0 parsing not implemented in forest");
            continue;
        }

        // Create test case for each
        it("Parse Transaction : " + tc.description, () => {
            if (tc.valid) {
                let result = signer_wasm.transactionParse(tc.encoded_tx_hex, tc.testnet);
                assert.deepStrictEqual(tc.message, result);
            } else {
                // Not valid throw error
                // TODO: Add error type to manual_testvectors.json file
                assert.throws(
                    () => signer_wasm.transactionParse(tc.encoded_tx_hex, tc.testnet),
                    /error/
                );
            }
        })
    }
});
