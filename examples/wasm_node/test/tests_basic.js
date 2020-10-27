// Test twice for wasm version and pure js version
if (process.env.PURE_JS) {
  var filecoin_signer = require('@zondax/filecoin-signing-tools/js');
} else {
  var filecoin_signer = require('@zondax/filecoin-signing-tools');
}

const bip39 = require('bip39');
const bip32 = require('bip32');
const {getDigest, getDigestVoucher, blake2b256} = require('./utils');
const secp256k1 = require('secp256k1');
const fs = require('fs');
const assert = require('assert');
const cbor = require("ipld-dag-cbor").util;
const { 
  EXAMPLE_MNEMONIC,
  EXAMPLE_CBOR_TX,
  EXAMPLE_ADDRESS_MAINNET,
  EXAMPLE_TRANSACTION,
  EXAMPLE_TRANSACTION_MAINNET,
  MASTER_KEY,
  MASTER_NODE,
} = require('./constants.js');

let describeCall = describe;
if (process.env.PURE_JS) { describeCall = describe.skip }

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

describeCall("keyRecoverBLS", function() {
  it("should derive the key and return a BLS address", function() {
    let recoveredKey = filecoin_signer.keyRecoverBLS("P2pSgkvsZSgi0LOczuHmSXT1+l/hvSs3fVBb4y8OgVo=", true);

    console.log("Public Key Raw         :", recoveredKey.public_raw);
    console.log("Public Key             :", recoveredKey.public_hexstring);
    console.log("Private                :", recoveredKey.private_hexstring);
    console.log("Address                :", recoveredKey.address);

    assert.strictEqual(recoveredKey.address, "t3uxb75vcy3ilwbsaavao52v7gfnfh6aics4a7nj26dwpcmj4mxxgnzholkupuplafdrbd55frpoolfnm7wlda");
  })
})

describe("transactionSerialize", function() {
  it("should serialize transaction", function() {
    assert.strictEqual(EXAMPLE_CBOR_TX, filecoin_signer.transactionSerialize(EXAMPLE_TRANSACTION));
  });

  let itCall = describe;
  if (process.env.PURE_JS) { itCall = it.skip }
  itCall("should serialize transaction with serialize params", function() {
    let swap_params = {
        From: "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
        To: "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
    }

    let serialized_swap_params = filecoin_signer.serializeParams(swap_params);

    console.log(Buffer.from(serialized_swap_params).toString('base64'))

    let params = {
        To: "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
        Value: "0",
        Method: 7,
        Params: Buffer.from(serialized_swap_params).toString('base64')
    }

    let serialized_params = filecoin_signer.serializeParams(params);

    let transaction = {
        to: "t01002",
        from: "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
        nonce: 1,
        value: "100000",
        gaslimit: 25000,
        gasfeecap: "1",
        gaspremium: "1",
        method: 7,
        params: Buffer.from(serialized_params).toString('base64')
    };

    console.log(filecoin_signer.transactionSerialize(transaction));

    assert.strictEqual(
      "845501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c6284007582d825501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855011eaf1c8a4bbfeeb0870b1745b1f57503470b7116",
      Buffer.from(serialized_params).toString('hex')
    )
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

  it("should fail to parse because of extra bytes", function () {
      let cbor_transaction_extra_bytes = EXAMPLE_CBOR_TX + "00";

      assert.throws(
          () => filecoin_signer.transactionParse(cbor_transaction_extra_bytes, false),
          /(CBOR error: 'trailing data at offset 64'|Extraneous CBOR data found beyond initial top-level object)/
      );
  });

  it("should fail to parse because of extra bytes (non null)", function () {
      let cbor_transaction_extra_bytes = EXAMPLE_CBOR_TX + "39";

      assert.throws(
          () => filecoin_signer.transactionParse(cbor_transaction_extra_bytes, false),
          /(CBOR error: 'trailing data at offset 64'|Failed to parse)/
      );
  });
})

describe("transactionSign", function() {
  it("should sign transaction", function() {
    const example_key = MASTER_NODE.derivePath("m/44'/461'/0/0/0");

    var signed_tx = filecoin_signer.transactionSign(EXAMPLE_TRANSACTION, example_key.privateKey.toString("base64"));
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
    assert.strictEqual(0x00, signature[64]);
  })
})

describe("transactionSignLotus", function() {
  it("should sign transaction and return a Lotus compatible json string", function() {
    const example_key = MASTER_NODE.derivePath("m/44'/461'/0/0/0");

    var signed_tx = filecoin_signer.transactionSignLotus(EXAMPLE_TRANSACTION, example_key.privateKey.toString("base64"));

    console.log(signed_tx)

    // Order is important...
    assert.deepStrictEqual(JSON.parse(signed_tx),{
      "Message": {
        "From": "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
        "GasLimit": 25000,
        "GasPremium": "1",
        "GasFeeCap": "1",
        "Method": 0,
        "Nonce": 1,
        "Params": "",
        "To": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
        "Value": "100000"
      },
      "Signature": {
        "Data": "nFuTI7MxEXqTQ0QmmQTmqbUsNZfHFXlNjz+susVDkAk1SrRCdJKxlVZZrM4vUtVBSYgtMIeigNfpqdKGIFhoWQA=",
        "Type": 1
      }
    });
  })
})

describe("transactionSignRaw", function() {
  it("should sign transaction and return raw signature", function() {
    const example_key = MASTER_NODE.derivePath("m/44'/461'/0/0/0");

    let signature = filecoin_signer.transactionSignRaw(EXAMPLE_TRANSACTION, example_key.privateKey.toString("base64"));
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
    assert.strictEqual(0x00, signature[64]);
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

describeCall('SerializeParams', function () {
  it('serialize parameters to cbor data', function () {
    let addresses = ["t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy","t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"];

    let constructor_params = { signers: addresses, num_approvals_threshold: 1, unlock_duration: 0 }

    let params = {
        code_cid: 'fil/1/multisig',
        constructor_params: Buffer.from(filecoin_signer.serializeParams(constructor_params)).toString('base64')
    }

    let serialized_params = filecoin_signer.serializeParams(params);

    console.log(Buffer.from(serialized_params).toString('hex'));

    assert.strictEqual(
      "82d82a53000155000e66696c2f312f6d756c7469736967583083825501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855011eaf1c8a4bbfeeb0870b1745b1f57503470b71160100",
      Buffer.from(serialized_params).toString('hex')
    )
  })

  it('serialize parameters to cbor data test with PascalCase', function () {
    let addresses = ["t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy","t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"];

    let constructor_params = { Signers: addresses, NumApprovalsThreshold: 1, UnlockDuration: 0 }

    let params = {
        CodeCid: 'fil/1/multisig',
        ConstructorParams: Buffer.from(filecoin_signer.serializeParams(constructor_params)).toString('base64')
    }

    let serialized_params = filecoin_signer.serializeParams(params);

    console.log(Buffer.from(serialized_params).toString('hex'));

    assert.strictEqual(
      "82d82a53000155000e66696c2f312f6d756c7469736967583083825501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855011eaf1c8a4bbfeeb0870b1745b1f57503470b71160100",
      Buffer.from(serialized_params).toString('hex')
    )
  })

  it('serialize parameters to cbor data test with PascalCase (2)', function () {
    let addresses = ["t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy","t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"];

    let params = {
        To: "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
        Value: "1000",
        Method: 0,
        Params: ""
    }

    let serialized_params = filecoin_signer.serializeParams(params);

    console.log(Buffer.from(serialized_params).toString('hex'));

    assert.strictEqual(
      "845501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c628430003e80040",
      Buffer.from(serialized_params).toString('hex')
    )
  })

  it('serialize parameters to cbor data test with PascalCase (3)', function () {

    let swap_params = {
        From: "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
        To: "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
    }

    let serialized_swap_params = filecoin_signer.serializeParams(swap_params);

    console.log(Buffer.from(serialized_swap_params).toString('base64'))

    let params = {
        To: "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
        Value: "0",
        Method: 7,
        Params: Buffer.from(serialized_swap_params).toString('base64')
    }

    let serialized_params = filecoin_signer.serializeParams(params);

    console.log(Buffer.from(serialized_params).toString('hex'));

    assert.strictEqual(
      "845501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c6284007582d825501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855011eaf1c8a4bbfeeb0870b1745b1f57503470b7116",
      Buffer.from(serialized_params).toString('hex')
    )
  })
})

describeCall('DeserializeParams', function () {
  it('deserialize cbor base64 string parameters (Swap parameters)', function () {
    let cbor_base64 = "glUB/R0PTfzX6Zr8uZqDJrfcRZ0yxihVAR6vHIpLv+6whwsXRbH1dQNHC3EW"
    let swap_params_expected = {
        from: "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
        to: "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
    }
    
    let params = filecoin_signer.deserializeParams(cbor_base64, "fil/1/multisig", 7)
    
    assert.deepStrictEqual(swap_params_expected, params)
  })
  
  it('deserialize params should fail with wrong actor type for method', function () {
    let cbor_base64 = "glUB/R0PTfzX6Zr8uZqDJrfcRZ0yxihVAR6vHIpLv+6whwsXRbH1dQNHC3EW"

    assert.throws(() => {
          filecoin_signer.deserializeParams(cbor_base64, "fil/1/paymentchannel", 7)
        },
        /Unknown method fo actor 'fil\/1\/paymentchannel'./
    );
  })
  
  it('deserialize params should fail with unknown actor type', function () {
    let cbor_base64 = "glUB/R0PTfzX6Zr8uZqDJrfcRZ0yxihVAR6vHIpLv+6whwsXRbH1dQNHC3EW"

    assert.throws(() => {
          filecoin_signer.deserializeParams(cbor_base64, "fil/2/paymentchannel", 7)
        },
        /Actor type not supported./
    );
  })
})

describeCall('DeserializeConstructorParams', function () {
  it('deserialize cbor base64 string parameters (Swap parameters)', function () {
    let cbor_base64 = "glUB/R0PTfzX6Zr8uZqDJrfcRZ0yxihVAR6vHIpLv+6whwsXRbH1dQNHC3EW"
    let constructor_params_expected = {
        from: "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
        to: "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
    }
    
    let params = filecoin_signer.deserializeConstructorParams(cbor_base64, "fil/1/paymentchannel")
    
    assert.deepStrictEqual(constructor_params_expected, params)
  })
  
  it('deserialize params should fail with wrong code cid', function () {
    let cbor_base64 = "glUB/R0PTfzX6Zr8uZqDJrfcRZ0yxihVAR6vHIpLv+6whwsXRbH1dQNHC3EW"

    assert.throws(() => {
          filecoin_signer.deserializeConstructorParams(cbor_base64, "fil/2/multisig")
        },
        /Code CID not supported./
    );
  })
})

describeCall('GetCid', function () {
  it('get cid from signed message', function () {
    let signedMessage = {
      message: {
        to: "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
        from: "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
        nonce: 1,
        value: "100000",
        gas_limit: 2500000,
        gas_fee_cap: "1",
        gas_premium: "1",
        method: 0,
        params: "",
      },
      signature: {
        type: 1,
        data: "0wRrFJZFIVh8m0JD+f5C55YrxD6YAWtCXWYihrPTKdMfgMhYAy86MVhs43hSLXnV+47UReRIe8qFdHRJqFlreAE=",
      }
    }
    
    let cid = filecoin_signer.getCid(signedMessage)
    
    assert.strictEqual(
      "bafy2bzacebaiinljwwctblf7czp4zxwhz4747z6tpricgn5cumd4xhebftcvu",
      cid
    )
    
  })
})

/* ------------------------------------------------------------------------------------------------- */

const bls_tests_vectors_path = "../generated_test_cases.json";
let rawBLSData = fs.readFileSync(bls_tests_vectors_path);
let jsonBLSData = JSON.parse(rawBLSData);

describeCall('BLS support', function () {

    for (let i = 0; i < jsonBLSData.length; i += 1) {
        let tc = jsonBLSData[i];

        it(`BLS signing test case n°${i}`, function () {
            var signed_tx = filecoin_signer.transactionSign(tc.message, Buffer.from(tc.sk, "hex").toString("base64"));

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

        if (tc.not_implemented) {
          // FIXME: cbor negative value
          continue
        }

        it("Create Transaction : " + tc.description, () => {
            if (tc.valid) {
                // Valid doesn't throw
                try {
                  var result = filecoin_signer.transactionSerialize(tc.message);
                } catch (e) {
                  assert.match(e.message, /protocol not supported./);
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
                  assert.match(e.message, /protocol not supported./);
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
