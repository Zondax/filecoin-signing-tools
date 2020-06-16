// Test twice for wasm verion and pure js version
if (process.env.PURE_JS) {
  var filecoin_signer = require('@zondax/filecoin-signer/js');
} else {
  var filecoin_signer = require('@zondax/filecoin-signer');
}

const bip39 = require('bip39');
const bip32 = require('bip32');
const getDigest = require('./utils').getDigest;
const secp256k1 = require('secp256k1');
const fs = require('fs');
const assert = require('assert');

const EXAMPLE_MNEMONIC = "equip will roof matter pink blind book anxiety banner elbow sun young";
const EXAMPLE_CBOR_TX = "89005501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855011eaf1c8a4bbfeeb0870b1745b1f57503470b71160144000186a0430009c41961a80040";
const EXAMPLE_ADDRESS_MAINNET = "f1rovwtiuo5ncslpmpjftzu5akswbgsgighjazxoi";
const EXAMPLE_TRANSACTION = {
    "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
    "from": "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
    "nonce": 1,
    "value": "100000",
    "gasprice": "2500",
    "gaslimit": 25000,
    "method": 0,
    "params": ""
};

const EXAMPLE_TRANSACTION_MAINNET = {
    "to": "f17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
    "from": "f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
    "nonce": 1,
    "value": "100000",
    "gasprice": "2500",
    "gaslimit": 25000,
    "method": 0,
    "params": ""
};

const MASTER_KEY = "xprv9s21ZrQH143K49QgrAgAVELf6ue2tZNHYUc7yfj8JGZY9SpZ38u8EfhWi85GsA6grUeB36wXrbNTkjX9EfGP1ybbPRG4sdP2EPfY1SZ2BF5";
let MASTER_NODE = bip32.fromBase58(MASTER_KEY);

describe("generateMnemonic", function() {
  it("should generate a 24 words mnemonic", function() {
    const mnemonic = filecoin_signer.generateMnemonic();
    assert.strictEqual(mnemonic.split(" ").length, 24);
  });
})

describe("keyDerive", function() {
  it("should derive key from mnemonic", function() {
    const keypair = filecoin_signer.keyDerive(EXAMPLE_MNEMONIC, "m/44'/461'/0/0/1", "");

    console.log("Public Key Raw         :", keypair.public_raw);
    console.log("Public Key             :", keypair.public_hexstring);
    console.log("Private                :", keypair.private_hexstring);
    console.log("Address                :", keypair.address);

    const expected_keys = MASTER_NODE.derivePath("m/44'/461'/0/0/1");
    assert.strictEqual(keypair.private_hexstring, expected_keys.privateKey.toString("hex"));
    assert.strictEqual(keypair.address, EXAMPLE_ADDRESS_MAINNET);
  });

  it("should derive key from mnemonic and return a testnet address", function() {
      const keypair = filecoin_signer.keyDerive(EXAMPLE_MNEMONIC, "m/44'/1'/0/0/1", "");

      console.log("Public Key Raw         :", keypair.public_raw);
      console.log("Public Key             :", keypair.public_hexstring);
      console.log("Private                :", keypair.private_hexstring);
      console.log("Address                :", keypair.address);

      const expected_keys = MASTER_NODE.derivePath("m/44'/1'/0/0/1");
      assert.strictEqual(keypair.private_hexstring, expected_keys.privateKey.toString("hex"));
      assert(keypair.address.startsWith('t'));
  });

  it("should not work without password", function() {
    assert.throws(() => {
            filecoin_signer.keyDerive(EXAMPLE_MNEMONIC, "m/44'/461'/0/0/1")
        },
        /argument must be of type string or an instance of Buffer or ArrayBuffer. Received undefined/
    );
  });

  it("should derive key with the password", function() {
      const keypair = filecoin_signer.keyDerive(EXAMPLE_MNEMONIC, "m/44'/461'/0/0/1", "password");

      console.log("Public Key Raw         :", keypair.public_raw);
      console.log("Public Key             :", keypair.public_hexstring);
      console.log("Private                :", keypair.private_hexstring);
      console.log("Address                :", keypair.address);

      const seed = bip39.mnemonicToSeedSync(EXAMPLE_MNEMONIC, "password");
      const node = bip32.fromSeed(seed);

      const expected_keys = node.derivePath("m/44'/461'/0/0/1");
      assert.strictEqual(keypair.private_hexstring, expected_keys.privateKey.toString("hex"));
  });

  it("should not match the key with the different password", function() {
      const keypair = filecoin_signer.keyDerive(EXAMPLE_MNEMONIC, "m/44'/461'/0/0/1", "password");

      console.log("Public Key Raw         :", keypair.public_raw);
      console.log("Public Key             :", keypair.public_hexstring);
      console.log("Private                :", keypair.private_hexstring);
      console.log("Address                :", keypair.address);

      const seed = bip39.mnemonicToSeedSync(EXAMPLE_MNEMONIC, "lol");
      const node = bip32.fromSeed(seed);

      const expected_keys = node.derivePath("m/44'/461'/0/0/1");
      assert.notEqual(keypair.private_hexstring, expected_keys.privateKey.toString("hex"));
  });

})

describe("keyDeriveFromSeed", function() {
  it("should derive key from seed", function() {
    const seed = bip39.mnemonicToSeedSync(EXAMPLE_MNEMONIC).toString('hex');

    const keypair = filecoin_signer.keyDeriveFromSeed(seed, "m/44'/461'/0/0/1");

    console.log("Public Key Raw         :", keypair.public_raw);
    console.log("Public Key             :", keypair.public_hexstring);
    console.log("Private                :", keypair.private_hexstring);
    console.log("Address                :", keypair.address);

    const expected_keys = MASTER_NODE.derivePath("m/44'/461'/0/0/1");
    assert.strictEqual(keypair.private_hexstring, expected_keys.privateKey.toString("hex"));
    assert.strictEqual(keypair.address, EXAMPLE_ADDRESS_MAINNET);
  });

  it('should be able to derive from seed buffer', function() {
      const seed = bip39.mnemonicToSeedSync(EXAMPLE_MNEMONIC);

      const keypair = filecoin_signer.keyDeriveFromSeed(seed, "m/44'/461'/0/0/1");

      console.log("Public Key Raw         :", keypair.public_raw);
      console.log("Public Key             :", keypair.public_hexstring);
      console.log("Private                :", keypair.private_hexstring);
      console.log("Address                :", keypair.address);

      const expected_keys = MASTER_NODE.derivePath("m/44'/461'/0/0/1");
      assert.strictEqual(keypair.private_hexstring, expected_keys.privateKey.toString("hex"));
      assert.strictEqual(keypair.address, EXAMPLE_ADDRESS_MAINNET);
  });

  it('should throw an error because of invalid path', function() {
      assert.throws(
          () => filecoin_signer.keyDerive(EXAMPLE_MNEMONIC, "m/44'/461'/a/0/1", ""),
          /Expected BIP32Path, got String | Invalid BIP44 path/
      );
  });
})

describe("keyRecover", function() {
  it("should recover testnet key", function() {
    let child = MASTER_NODE.derivePath("m/44'/461'/0/0/0");
    let privateKey = child.privateKey.toString('hex');

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log("Public Key Raw         :", recoveredKey.public_raw);
    console.log("Public Key             :", recoveredKey.public_hexstring);
    console.log("Private                :", recoveredKey.private_hexstring);
    console.log("Address                :", recoveredKey.address);

    assert.strictEqual(recoveredKey.private_hexstring, child.privateKey.toString("hex"));
    assert.strictEqual(recoveredKey.address, "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba");
  });

  it("should recover testnet key (buffer private key)", function() {
    let child = MASTER_NODE.derivePath("m/44'/461'/0/0/0");
    let privateKey = child.privateKey;

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log("Public Key Raw         :", recoveredKey.public_raw);
    console.log("Public Key             :", recoveredKey.public_hexstring);
    console.log("Private                :", recoveredKey.private_hexstring);
    console.log("Address                :", recoveredKey.address);

    assert.strictEqual(recoveredKey.private_hexstring, child.privateKey.toString("hex"));
    assert.strictEqual(recoveredKey.address, "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba");
  });

  it("should recover mainnet key", function() {
    let child = MASTER_NODE.derivePath("m/44'/461'/0/0/0");
    let privateKey = child.privateKey.toString('hex');

    let recoveredKey = filecoin_signer.keyRecover(privateKey, false);

    console.log("Public Key Raw         :", recoveredKey.public_raw);
    console.log("Public Key             :", recoveredKey.public_hexstring);
    console.log("Private                :", recoveredKey.private_hexstring);
    console.log("Address                :", recoveredKey.address);

    assert.strictEqual(recoveredKey.private_hexstring, child.privateKey.toString("hex"));
    assert.strictEqual(recoveredKey.address, "f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba");
  });

  it("key recover mainnet base64", () => {
      let child = MASTER_NODE.derivePath("m/44'/461'/0/0/0");
      let privateKey = child.privateKey.toString('base64');

      let recoveredKey = filecoin_signer.keyRecover(privateKey, false);

      console.log("Public Key Raw         :", recoveredKey.public_raw);
      console.log("Public Key (hex)       :", recoveredKey.public_hexstring);
      console.log("Private Key (hex)      :", recoveredKey.private_hexstring);
      console.log("Public Key (base64)    :", recoveredKey.public_base64);
      console.log("Private Key (base64)   :", recoveredKey.private_base64);
      console.log("Address                :", recoveredKey.address);

      assert.strictEqual(recoveredKey.private_hexstring, child.privateKey.toString("hex"));
      assert.strictEqual(recoveredKey.address, "f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba");
  });
})

describe("transactionSerialize", function() {
  it("should serialize transaction", function() {
    assert.strictEqual(EXAMPLE_CBOR_TX, filecoin_signer.transactionSerialize(EXAMPLE_TRANSACTION));
  });
})

describe("transactionSerializeRaw", function() {
  it("should serialize raw transaction", function() {
    let cbor_uint8_array = filecoin_signer.transactionSerializeRaw(EXAMPLE_TRANSACTION);
    assert.strictEqual(EXAMPLE_CBOR_TX, Buffer.from(cbor_uint8_array).toString('hex'));
  })
})

describe("transactionParse", function() {
  it("should parse transaction (testnet)", function() {
    assert.deepStrictEqual(EXAMPLE_TRANSACTION, filecoin_signer.transactionParse(EXAMPLE_CBOR_TX, true))
  });

  it("should parse transaction (mainnet)", function () {
      assert.deepStrictEqual(EXAMPLE_TRANSACTION_MAINNET, filecoin_signer.transactionParse(EXAMPLE_CBOR_TX, false));
  });

  it.skip("should fail to parse because of extra bytes", function () {
      let cbor_transaction_extra_bytes = EXAMPLE_CBOR_TX + "00";

      assert.throws(
          () => filecoin_signer.transactionParse(cbor_transaction_extra_bytes, false),
          /CBOR error: 'trailing data at offset 62'/
      );
  });

  it("should fail to parse because of extra bytes (non null)", function () {
      let cbor_transaction_extra_bytes = EXAMPLE_CBOR_TX + "39";

      assert.throws(
          () => filecoin_signer.transactionParse(cbor_transaction_extra_bytes, false),
          /(CBOR error: 'trailing data at offset 62'|Failed to parse)/
      );
  });
})

describe("transactionSign", function() {
  it("should sign transaction", function() {
    const example_key = MASTER_NODE.derivePath("m/44'/461'/0/0/0");

    var signed_tx = filecoin_signer.transactionSign(EXAMPLE_TRANSACTION, example_key.privateKey.toString("hex"));
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
  })
})

describe("transactionSignLotus", function() {
  it("should sign transaction and return a Lotus compatible json string", function() {
    const example_key = MASTER_NODE.derivePath("m/44'/461'/0/0/0");

    var signed_tx = filecoin_signer.transactionSignLotus(EXAMPLE_TRANSACTION, example_key.privateKey.toString("hex"));

    console.log(signed_tx)

    // Order is important...
    assert.strictEqual(signed_tx, JSON.stringify({
      "Message": {
        "From": "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
        "GasLimit": 25000,
        "GasPrice": "2500",
        "Method": 0,
        "Nonce": 1,
        "Params": "",
        "To": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
        "Value": "100000"
      },
      "Signature": {
        "Data": "BjmEhQYMoqTeuXAn9Rj0VWk2DDhzpDA5JvppCacpnUxViDRjEgg2NY/zOWiC7g3CzxWWG9SVzfs94e4ui9N2jgE=",
        "Type": 1
      }
    }));
  })
})

describe("transactionSignRaw", function() {
  it("should sign transaction and return raw signature", function() {
    const example_key = MASTER_NODE.derivePath("m/44'/461'/0/0/0");

    let signature = filecoin_signer.transactionSignRaw(EXAMPLE_TRANSACTION, example_key.privateKey.toString("hex"));
    signature = Buffer.from(signature);
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
  })
})

describe("verifySignature", function() {
  it("should verify signature", function() {
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

    assert.strictEqual(filecoin_signer.verifySignature(signatureRSV, EXAMPLE_CBOR_TX), true);
  })
})

/* ------------------------------------------------------------------------------------------------- */

const bls_tests_vectors_path = "../generated_test_cases.json";
let rawBLSData = fs.readFileSync(bls_tests_vectors_path);
let jsonBLSData = JSON.parse(rawBLSData);

let describeCall = describe;
if (process.env.PURE_JS) { describeCall = describe.skip }

describeCall('BLS support', function () {

    for (let i = 0; i < jsonBLSData.length; i += 1) {
        let tc = jsonBLSData[i];

        it(`BLS signing test case n°${i}`, function () {
            var signed_tx = filecoin_signer.transactionSign(tc.message, tc.sk);

            const signature = Buffer.from(signed_tx.signature.data, 'base64');

            // Signature representation is R, S & V
            console.log("Signature  :", signature.toString('hex'));
            console.log("Private key:", tc.sk);
            console.log("Public key :", tc.pk);

            assert.strictEqual(signature.length, 96);

            assert.strictEqual(signature.toString('hex'), tc.sig);

        })
    }
});

//////////////////////////////////////
// Parameterized tests
const tests_vectors_path = "../manual_testvectors.json";
let rawData = fs.readFileSync(tests_vectors_path);
let jsonData = JSON.parse(rawData);

describe('Transaction Serialization - Parameterized', function () {
    for (let i = 0; i < jsonData.length; i += 1) {
        let tc = jsonData[i];
        if (!tc.message.params) {
            tc.message["params"] = ""
        }

        it("Create Transaction : " + tc.description, () => {
            if (tc.valid) {
                // Valid doesn't throw
                try {
                  var result = filecoin_signer.transactionSerialize(tc.message);
                } catch (e) {
                  assert(e.message, /protocol not supported./);
                  return;
                }
                assert.strictEqual(tc.encoded_tx_hex, result);
            } else {
                // Not valid throw error
                // TODO: Add error type to manual_testvectors.json file
                assert.throws(
                    () => filecoin_signer.transactionSerialize(tc.message),
                    /Error/
                );
            }
        });
    }
});

describe('Transaction Deserialization - Parameterized', function () {
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
                try {
                  var result = filecoin_signer.transactionParse(tc.encoded_tx_hex, tc.testnet);
                } catch (e) {
                  assert(e.message, /protocol not supported./);
                  return;
                }
                assert.deepStrictEqual(tc.message, result);
            } else {
                // Not valid throw error
                // TODO: Add error type to manual_testvectors.json file
                assert.throws(
                    () => filecoin_signer.transactionParse(tc.encoded_tx_hex, tc.testnet),
                    /(error|^Error)/
                );
            }
        })
    }
});
