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

const EXAMPLE_MNEMONIC = "equip will roof matter pink blind book anxiety banner elbow sun young";
const EXAMPLE_CBOR_TX = "8A005501FD1D0F4DFCD7E99AFCB99A8326B7DC459D32C62855011EAF1C8A4BBFEEB0870B1745B1F57503470B71160144000186A01961A84200014200010040".toLowerCase();
const EXAMPLE_ADDRESS_MAINNET = "f1rovwtiuo5ncslpmpjftzu5akswbgsgighjazxoi";
const EXAMPLE_TRANSACTION = {
    "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
    "from": "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
    "nonce": 1,
    "value": "100000",
    "gaslimit": 25000,
    "gasfeecap": "1",
    "gaspremium": "1",
    "method": 0,
    "params": ""
};

const EXAMPLE_TRANSACTION_MAINNET = {
    "to": "f17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
    "from": "f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
    "nonce": 1,
    "value": "100000",
    "gaslimit": 25000,
    "gasfeecap": "1",
    "gaspremium": "1",
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

let describeCall = describe;
if (process.env.PURE_JS) { describeCall = describe.skip }

describeCall("createMultisig", function() {
  it("should return a create multisig transaction", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let addresses = [recoveredKey.address,"t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"];
    let sender_address = recoveredKey.address;

    let constructor_params = {
      signers: addresses,
      num_approvals_threshold: 1,
      unlock_duration: 0,
    };

    let exec_params = {
      code_cid: 'fil/1/multisig',
      constructor_params: Buffer.from(filecoin_signer.serializeParams(constructor_params)).toString('base64'),
    };

    let expected = {
      to: 't01',
      from: recoveredKey.address,
      nonce: 1,
      value: '1000',
      gaslimit: 1000000,
      gasfeecap: '2500',
      gaspremium: '2500',
      method: 2,
      params: Buffer.from(filecoin_signer.serializeParams(exec_params)).toString('base64')
    };

    let create_multisig_transaction = filecoin_signer.createMultisig(sender_address, addresses, "1000", 1, 1, BigInt(0));

    console.log(create_multisig_transaction);

    assert.deepStrictEqual(expected, create_multisig_transaction);
  });

  it("should return a create multisig transaction with duration -1", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let addresses = [recoveredKey.address,"t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"];
    let sender_address = recoveredKey.address;

    let constructor_params = {
      signers: addresses,
      num_approvals_threshold: 1,
      unlock_duration: -1,
    };

    let exec_params = {
      code_cid: 'fil/1/multisig',
      constructor_params: Buffer.from(filecoin_signer.serializeParams(constructor_params)).toString('base64'),
    };

    let expected = {
      to: 't01',
      from: recoveredKey.address,
      nonce: 1,
      value: '1000',
      gaslimit: 1000000,
      gasfeecap: '2500',
      gaspremium: '2500',
      method: 2,
      params: Buffer.from(filecoin_signer.serializeParams(exec_params)).toString('base64')
    };

    let create_multisig_transaction = filecoin_signer.createMultisig(sender_address, addresses, "1000", 1, 1, BigInt(-1));

    console.log(create_multisig_transaction);

    assert.deepStrictEqual(expected, create_multisig_transaction);
  });


  it("should return a serialized version of the create multisig transaction", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let addresses = [recoveredKey.address,"t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"];
    let sender_address = recoveredKey.address;
    let expected = "8A004200015501DFE49184D46ADC8F89D44638BEB45F78FCAD259001430003E81A000F4240430009C4430009C402584982D82A53000155000E66696C2F312F6D756C7469736967583083825501DFE49184D46ADC8F89D44638BEB45F78FCAD259055011EAF1C8A4BBFEEB0870B1745B1F57503470B71160100".toLowerCase();

    let create_multisig_transaction = filecoin_signer.createMultisig(sender_address, addresses, "1000", 1, 1, BigInt(0));

    let serialized_create_multisig_transaction = filecoin_signer.transactionSerialize(create_multisig_transaction);

    console.log(serialized_create_multisig_transaction);

    assert.strictEqual(expected, serialized_create_multisig_transaction);
  });

  it("should return a signature of the create multisig transaction", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let addresses = [recoveredKey.address,"t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"];
    let sender_address = recoveredKey.address;

    let expected = {
      "Message":{
        "From":recoveredKey.address,
        "GasLimit":1000000,
        "GasFeeCap":"2500",
        "GasPremium":"2500",
        "Method":2,
        "Nonce":1,
        "Params":"gtgqUwABVQAOZmlsLzEvbXVsdGlzaWdYMIOCVQHf5JGE1Grcj4nURji+tF94/K0lkFUBHq8ciku/7rCHCxdFsfV1A0cLcRYBAA==",
        "To":"t01",
        "Value":"1000"
      },
      "Signature":{
        "Data":"8pj9RPIe5qC6kQAfQN5s9EO4uj1TnyNvOyxRylFMWq4axjBpbu7/GfKnhpWx5OX/RMLj8N6905yPGyY+Rh7GYwE=",
        "Type":1
      }
    }

    let create_multisig_transaction = filecoin_signer.createMultisig(sender_address, addresses, "1000", 1, 1, BigInt(0));

    let signature = filecoin_signer.transactionSignLotus(create_multisig_transaction, privateKey);

    console.log(signature);

    assert.deepStrictEqual(expected, JSON.parse(signature));
  });
})

describeCall("proposeMultisig", function() {
  it("should return a propose multisig transaction", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let to_address = recoveredKey.address;
    let from_address = recoveredKey.address;

    let params = {
      to: recoveredKey.address,
      value: '1000',
      method: 0,
      params: ''
    };

    let params_base64 = Buffer.from(filecoin_signer.serializeParams(params)).toString('base64');

    let expected = {
      to: 't01004',
      from: recoveredKey.address,
      nonce: 1,
      value: '0',
      gaslimit: 1000000,
      gasfeecap: '2500',
      gaspremium: '2500',
      method: 2,
      params: params_base64
    }

    let propose_multisig_transaction = filecoin_signer.proposeMultisig("t01004", to_address, from_address, "1000", 1);

    console.log(propose_multisig_transaction);

    assert.deepStrictEqual(expected, propose_multisig_transaction);
  });

  it("should return a serialized version of the propose multisig transaction", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let to_address = recoveredKey.address;
    let from_address = recoveredKey.address;

    let expected = "8a004300ec075501dfe49184d46adc8f89d44638beb45f78fcad259001401a000f4240430009c4430009c402581d845501dfe49184d46adc8f89d44638beb45f78fcad2590430003e80040";

    let propose_multisig_transaction = filecoin_signer.proposeMultisig("t01004", to_address, from_address, "1000", 1);

    let serialized_propose_multisig_transaction = filecoin_signer.transactionSerialize(propose_multisig_transaction);

    console.log(serialized_propose_multisig_transaction);

    assert.strictEqual(expected, serialized_propose_multisig_transaction);
  });

  it("should return a signature of the create multisig transaction", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let to_address = recoveredKey.address;
    let from_address = recoveredKey.address;

    let expected = {
      "Message":{
        "From":recoveredKey.address,
        "GasLimit":1000000,
        "GasPremium":"2500",
        "GasFeeCap":"2500",
        "Method":2,
        "Nonce":1,
        "Params":"hFUB3+SRhNRq3I+J1EY4vrRfePytJZBDAAPoAEA=",
        "To":"t01004",
        "Value":"0"
      },
      "Signature":{
        "Data":"2bXhOIt6j7FM3jppLghaB29ZPrRSYjOEpz/2ZxVQQz09nC/Nlasnz4Eff6Ii5FIMd8bl7Z9ZcadhT9r+jqkN7wE=",
        "Type":1
      }
    }

    let propose_multisig_transaction = filecoin_signer.proposeMultisig("t01004", to_address, from_address, "1000", 1);

    let signature = filecoin_signer.transactionSignLotus(propose_multisig_transaction, privateKey);

    console.log(signature);

    assert.deepStrictEqual(expected, JSON.parse(signature));
  });
})

describeCall("approveMultisig", function() {
  it("should return an approval multisig transaction", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let to_address = recoveredKey.address;
    let from_address = recoveredKey.address;
    let proposer_address = recoveredKey.address;

    let proposal_params = {
      requester: recoveredKey.address,
      to: recoveredKey.address,
      value: '1000',
      method: 0,
      params: ''
    };

    let txn_id_params = {
      txn_id: 1234,
      proposal_hash_data: Buffer.from(blake2b256(filecoin_signer.serializeParams(proposal_params))).toString('base64')
    }

    let expected = {
      to: 't01004',
      from: recoveredKey.address,
      nonce: 1,
      value: '0',
      gaslimit: 1000000,
      gasfeecap: '2500',
      gaspremium: '2500',
      method: 3,
      params: Buffer.from(filecoin_signer.serializeParams(txn_id_params)).toString('base64')
    }

    let approve_multisig_transaction = filecoin_signer.approveMultisig("t01004", 1234, proposer_address, to_address, "1000", to_address, 1);

    console.log(approve_multisig_transaction);

    assert.deepStrictEqual(expected, approve_multisig_transaction);
  });

  it("should return a serialized version of the approval multisig transaction", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let to_address = recoveredKey.address;
    let from_address = recoveredKey.address;
    let proposer_address = recoveredKey.address;

    let expected = "8a004300ec075501dfe49184d46adc8f89d44638beb45f78fcad259001401a000f4240430009c4430009c4035842821904d2982018fa18b418c218e2187218e30f18d118de188b18ed183618c31896183718c118be1894181e1618dd189218ed18ae0f185418b606187c18ff184218ff";

    let approve_multisig_transaction = filecoin_signer.approveMultisig("t01004", 1234, proposer_address, to_address, "1000", to_address, 1);

    let serialized_approve_multisig_transaction = filecoin_signer.transactionSerialize(approve_multisig_transaction);

    console.log(serialized_approve_multisig_transaction);

    assert.strictEqual(expected, serialized_approve_multisig_transaction);
  });

  it("should return a signature of the approve multisig transaction", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let to_address = recoveredKey.address;
    let from_address = recoveredKey.address;
    let proposer_address = recoveredKey.address;

    let expected = {
      "Message":{
        "From":recoveredKey.address,
        "GasLimit":1000000,
        "GasFeeCap":"2500",
        "GasPremium":"2500",
        "Method":3,
        "Nonce":1,
        "Params":"ghkE0pggGPoYtBjCGOIYchjjDxjRGN4YixjtGDYYwxiWGDcYwRi+GJQYHhYY3RiSGO0Yrg8YVBi2Bhh8GP8YQhj/",
        "To":"t01004",
        "Value":"0"
      },
      "Signature":{
        "Data":"/Zsjx5hBMUoxTSsPl3Xl1ejNwYEjGbdgAFR85hC8Cy4AAp4zgCu1S7X6Udl7B1N6qmUPZCPv4Qfau7pToHiYHQA=",
        "Type":1
      }
    }

    let approve_multisig_transaction = filecoin_signer.approveMultisig("t01004", 1234, proposer_address, to_address, "1000", to_address, 1);

    let signature = filecoin_signer.transactionSignLotus(approve_multisig_transaction, privateKey);

    console.log(signature);

    assert.deepStrictEqual(expected, JSON.parse(signature));
  });
})

describeCall("cancelMultisig", function() {
  it("should return a cancel multisig transaction", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let to_address = recoveredKey.address;
    let from_address = recoveredKey.address;
    let proposer_address = recoveredKey.address;

    let proposal_params = {
      requester: recoveredKey.address,
      to: recoveredKey.address,
      value: '1000',
      method: 0,
      params: ''
    };

    let txn_id_params = {
      txn_id: 1234,
      proposal_hash_data: Buffer.from(blake2b256(filecoin_signer.serializeParams(proposal_params))).toString('base64')
    }

    let expected = {
      to: 't01004',
      from: recoveredKey.address,
      nonce: 1,
      value: '0',
      gaslimit: 1000000,
      gasfeecap: '2500',
      gaspremium: '2500',
      method: 4,
      params: Buffer.from(filecoin_signer.serializeParams(txn_id_params)).toString('base64')
    }

    let cancel_multisig_transaction = filecoin_signer.cancelMultisig("t01004", 1234, proposer_address, to_address, "1000", to_address, 1);

    console.log(cancel_multisig_transaction);

    assert.deepStrictEqual(expected, cancel_multisig_transaction);
  });

  it("should return a serialized version of the cancel multisig transaction", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let to_address = recoveredKey.address;
    let from_address = recoveredKey.address;
    let proposer_address = recoveredKey.address;

    let expected = "8a004300ec075501dfe49184d46adc8f89d44638beb45f78fcad259001401a000f4240430009c4430009c4045842821904d2982018fa18b418c218e2187218e30f18d118de188b18ed183618c31896183718c118be1894181e1618dd189218ed18ae0f185418b606187c18ff184218ff";

    let cancel_multisig_transaction = filecoin_signer.cancelMultisig("t01004", 1234, proposer_address, to_address, "1000", to_address, 1);

    let serialized_cancel_multisig_transaction = filecoin_signer.transactionSerialize(cancel_multisig_transaction);

    console.log(serialized_cancel_multisig_transaction);

    assert.strictEqual(expected, serialized_cancel_multisig_transaction);
  });

  it("should return a signature of the cancel multisig transaction", function() {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    let to_address = recoveredKey.address;
    let from_address = recoveredKey.address;
    let proposer_address = recoveredKey.address;

    let expected = {
      "Message":{
        "From":recoveredKey.address,
        "GasLimit":1000000,
        "GasPremium":"2500",
        "GasFeeCap":"2500",
        "Method":4,
        "Nonce":1,
        "Params":"ghkE0pggGPoYtBjCGOIYchjjDxjRGN4YixjtGDYYwxiWGDcYwRi+GJQYHhYY3RiSGO0Yrg8YVBi2Bhh8GP8YQhj/",
        "To":"t01004",
        "Value":"0"
      },
      "Signature":{
        "Data":"UYVNvKAbGqF4TE02Y4/7dXOM123y/w3QzZY0dwM4YG1F85Lb/ZeiqxbNXmcTnMo1dkuGCKG856A17AscbqBMkgE=",
        "Type":1
      }
    }

    let cancel_multisig_transaction = filecoin_signer.cancelMultisig("t01004", 1234, proposer_address, to_address, "1000", to_address, 1);

    let signature = filecoin_signer.transactionSignLotus(cancel_multisig_transaction, privateKey);

    console.log(signature);

    assert.deepStrictEqual(expected, JSON.parse(signature));
  });
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

describeCall('createPymtChan', function () {
  it('create payment channel transaction and sign (SECP256K1)', function () {
    const privateKey = "+UXJi0663hCExYMxZVb9J+wKyFWhhX51jnG7WXkeAw0=";

    const recover = filecoin_signer.keyRecover(privateKey, true);

    const from = recover.address;
    const to = "t3smdzzt2fbrzalmfi5rskc3tc6wpwcj2zbgyu5engqtkkzrxteg2oyqpukqzrhqqfvzqadh7mtqye443liejq";

    let serializedParams

    if (!process.env.PURE_JS) {
      const createParams = {
        From: from,
        To: to,
      }

      serializedParams = Buffer.from(filecoin_signer.serializeParams(createParams));

      let execParams = {
          CodeCid: 'fil/1/paymentchannel',
          ConstructorParams: serializedParams.toString('base64')
      }

      serializedParams = Buffer.from(filecoin_signer.serializeParams(execParams)).toString("base64");
    } else {
      serializedParams = "gtgqWBkAAVUAFGZpbC8xL3BheW1lbnRjaGFubmVsWEqCVQElRUfDOAbbTJ6ACbjr2cTS5fIBglgxA5MHnM9FDHIFsKjsZKFuYvWfYSdZCbFOkaaE1KzG8yG07EH0VDMTwgWuYAGf7JwwTg==";
    }

    const expected = {
      Message: {
        From: from,
        GasLimit: 200000000,
        GasFeeCap: '2500',
        GasPremium: '2500',
        Method: 2,
        Nonce: 1,
        Params: serializedParams,
        To: 't01',
        Value: '10000000000'
      },
    }

    let create_pymtchan = filecoin_signer.createPymtChan(from, to, "10000000000", 1);

    console.log(create_pymtchan)

    let signedMessage = filecoin_signer.transactionSignLotus(create_pymtchan, privateKey);
    signedMessage = JSON.parse(signedMessage)

    console.log(signedMessage);

    assert.deepStrictEqual(expected.Message, signedMessage.Message);

    const signature = Buffer.from(signedMessage.Signature.Data, "base64");

    const serializedMessage = filecoin_signer.transactionSerialize(create_pymtchan);

    const messageDigest = getDigest(Buffer.from(serializedMessage, 'hex'));

    // Remove the V value from the signature (last byte)
    assert(secp256k1.ecdsaVerify(signature.slice(0, -1), messageDigest, recover.public_raw))

  })
  it('create payment channel transaction and sign (BLS)', function () {
    let privateKey = "8niW4fUBoKNo3GMDVfWu0oari11js4t1QpwXVBpEpFA=";
    let from = "t3smdzzt2fbrzalmfi5rskc3tc6wpwcj2zbgyu5engqtkkzrxteg2oyqpukqzrhqqfvzqadh7mtqye443liejq";
    let to = "t1evcupqzya3nuzhuabg4oxwoe2ls7eamcu3uw4cy";

    let serializedParams

    if (!process.env.PURE_JS) {
      const createParams = {
        From: from,
        To: to,
      }

      serializedParams = Buffer.from(filecoin_signer.serializeParams(createParams));

      let execParams = {
          CodeCid: 'fil/1/paymentchannel',
          ConstructorParams: serializedParams.toString('base64')
      }

      serializedParams = Buffer.from(filecoin_signer.serializeParams(execParams)).toString('base64');
      console.log(serializedParams)
    } else {
      serializedParams = "gtgqWBkAAVUAFGZpbC8xL3BheW1lbnRjaGFubmVsWEqCWDEDkwecz0UMcgWwqOxkoW5i9Z9hJ1kJsU6RpoTUrMbzIbTsQfRUMxPCBa5gAZ/snDBOVQElRUfDOAbbTJ6ACbjr2cTS5fIBgg==";
    }

    console.log(serializedParams)

    const expected = {
      Message: {
        From: from,
        GasLimit: 200000000,
        GasFeeCap: '2500',
        GasPremium: '2500',
        Method: 2,
        Nonce: 1,
        Params: serializedParams,
        To: 't01',
        Value: '10000000000'
      }
    }

    let create_pymtchan = filecoin_signer.createPymtChan(from, to, "10000000000", 1)

    console.log(create_pymtchan)

    let signedMessage = filecoin_signer.transactionSignLotus(create_pymtchan, privateKey);
    signedMessage = JSON.parse(signedMessage);

    assert.deepStrictEqual(expected.Message, signedMessage.Message);

    // TODO: verify signature
    // but with which lib ?

  })
})

describeCall('updatePymtChan', function () {
  it('update payment channel transaction and sign', function () {
    const privateKey = "+UXJi0663hCExYMxZVb9J+wKyFWhhX51jnG7WXkeAw0=";

    const recover = filecoin_signer.keyRecover(privateKey, true);

    const from = recover.address;

    const signedVoucherBase64 = "i1UCP53KVzJUi7wjUUapT5IVPBQn/BcZBNIAQPYAAUQAAYagAYBYQgFyEfwyxLoQd7Vr3+BbaVvfRhvAP74X7YFEhRNTKRnP1Tqe36cZ9vjVh/SzLY19pOjPwiX8aYO2cYJ6m7+ezuc3AQ==";

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    let serializedParams

    if (!process.env.PURE_JS) {

      let updateChannelStateParams = {
        Sv: signedVoucherBase64,
        Secret: [],
        Proof: [],
      }

      serializedParams = Buffer.from(filecoin_signer.serializeParams(updateChannelStateParams)).toString('base64');
    } else {
      serializedParams = "g4oZBNIAQPYAAUQAAYagAYBYQgGKqPFMze+bytqgOI/JJY3VI6Gu4UElA6qS1w+/SmM6xm9TK+EcCJw/9Y/kOoWQTfvaoEZyphNO8ty7HOUPRTKeAUBA";
    }

    const expected = {
      Message : {
        From: from,
        GasLimit: 200000000,
        GasFeeCap: '2500',
        GasPremium: '2500',
        Method: 2,
        Nonce: 1,
        Params: serializedParams,
        To: 't01003',
        Value: '0'
      }
    }

    let update_pymtchan = filecoin_signer.updatePymtChan("t01003", recoveredKey.address, signedVoucherBase64, 1)

    console.log(update_pymtchan)

    let signedMessage = filecoin_signer.transactionSignLotus(update_pymtchan, privateKey);
    signedMessage = JSON.parse(signedMessage)

    assert.deepStrictEqual(expected.Message, signedMessage.Message);

    const signature = Buffer.from(signedMessage.Signature.Data, "base64");

    const serializedMessage = filecoin_signer.transactionSerialize(update_pymtchan);

    const messageDigest = getDigest(Buffer.from(serializedMessage, 'hex'));

    // Remove the V value from the signature (last byte)
    assert(secp256k1.ecdsaVerify(signature.slice(0, -1), messageDigest, recover.public_raw));
  })
})

describeCall('settlePymtChan', function () {
  it('settle payment channel and sign', function () {
    const privateKey = "+UXJi0663hCExYMxZVb9J+wKyFWhhX51jnG7WXkeAw0=";
    const recover = filecoin_signer.keyRecover(privateKey, true);
    const from = recover.address;
    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    const expected = {
      Message : {
        From: from,
        GasLimit: 20000000,
        GasFeeCap: '2500',
        GasPremium: '2500',
        Method: 3,
        Nonce: 1,
        Params: "",
        To: 't01003',
        Value: '0'
      }
    }
    let settle_pymtchan = filecoin_signer.settlePymtChan("t01003", recoveredKey.address, 1)

    console.log(settle_pymtchan)

    let signedMessage = filecoin_signer.transactionSignLotus(settle_pymtchan, privateKey);
    signedMessage = JSON.parse(signedMessage);

    assert.deepStrictEqual(expected.Message, signedMessage.Message);

    const signature = Buffer.from(signedMessage.Signature.Data, "base64");
    const serializedMessage = filecoin_signer.transactionSerialize(settle_pymtchan);
    const messageDigest = getDigest(Buffer.from(serializedMessage, 'hex'));

    // Remove the V value from the signature (last byte)
    assert(secp256k1.ecdsaVerify(signature.slice(0, -1), messageDigest, recover.public_raw));
  })
})

describeCall('collectPymtChan', function () {
  it('settle payment channel and sign', function () {
    const privateKey = "+UXJi0663hCExYMxZVb9J+wKyFWhhX51jnG7WXkeAw0=";
    const recover = filecoin_signer.keyRecover(privateKey, true);
    const from = recover.address;
    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    const expected = {
      Message : {
        From: from,
        GasLimit: 20000000,
        GasFeeCap: '2500',
        GasPremium: '2500',
        Method: 4,
        Nonce: 1,
        Params: "",
        To: 't01003',
        Value: '0'
      }
    }

    let collect_pymtchan = filecoin_signer.collectPymtChan("t01003", recoveredKey.address, 1)
    let signedMessage = filecoin_signer.transactionSignLotus(collect_pymtchan, privateKey);
    signedMessage = JSON.parse(signedMessage);

    assert.deepStrictEqual(expected.Message, signedMessage.Message);

    const signature = Buffer.from(signedMessage.Signature.Data, "base64");
    const serializedMessage = filecoin_signer.transactionSerialize(collect_pymtchan);
    const messageDigest = getDigest(Buffer.from(serializedMessage, 'hex'));

    // Remove the V value from the signature (last byte)
    assert(secp256k1.ecdsaVerify(signature.slice(0, -1), messageDigest, recover.public_raw));
  })
})

describeCall('createVoucher', function () {
  it('create a voucher', function () {
    const voucher = filecoin_signer.createVoucher(
      "t2h6o4uvzsksf3yi2ri2uu7eqvhqkcp7axmg3mski",
      BigInt(1234),
      BigInt(0),
      "100000",
      BigInt(0),
      BigInt(1),
      BigInt(1),
    );

    const expected = "i1UCP53KVzJUi7wjUUapT5IVPBQn/BcZBNIAQPYAAUQAAYagAYD2";

    assert.strictEqual(expected, voucher);
  })
})

describeCall('signVoucher', function () {
  it('sign a voucher', function () {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    const voucher = "i1UCP53KVzJUi7wjUUapT5IVPBQn/BcZBNIAQPYAAUQAAYagAYD2";

    const signedVoucher = filecoin_signer.signVoucher(voucher, privateKey);

    console.log(signedVoucher)

    let signature = cbor.deserialize(Buffer.from(signedVoucher, 'base64'))[10];

    signature = signature.slice(1,-1);
    console.log(signature.toString("base64"))

    const messageDigest = getDigestVoucher(Buffer.from(voucher, 'base64'));

    assert(secp256k1.ecdsaVerify(signature, messageDigest, recoveredKey.public_raw));
  })

  it('sign a voucher (2)', function () {
    let child = MASTER_NODE.derivePath("44'/1'/0/0/0");
    let privateKey = child.privateKey.toString("base64");

    let recoveredKey = filecoin_signer.keyRecover(privateKey, true);

    console.log(recoveredKey.address)

    const voucher = filecoin_signer.createVoucher(
      "t24acjqhdetck7irsvmn2p6jpuwnouzjxuoa22rva",
      BigInt(0),
      BigInt(0),
      "10000",
      BigInt(1),
      BigInt(1),
      BigInt(0),
    );

    /*
    {"jsonrpc":"2.0","result":{"ChannelAddr":"t24acjqhdetck7irsvmn2p6jpuwnouzjxuoa22rva","TimeLockMin":0,"TimeLockMax":0,"SecretPreimage":null,"Extra":null,"Lane":1,"Nonce":1,"Amount":"10000","MinSettleHeight":0,"Merges":null,"Signature":{"Type":1,"Data":"ZEPtUQzGHPmFZaDocdXBEzp1GZ2RBaOxFfrz5Y/PrNJmBwqftyItNZooaAF6CR+vixe2HCmqSLub4ySOoFiuawE="}},"id":1}
    */
    let expectedSignature = "ZEPtUQzGHPmFZaDocdXBEzp1GZ2RBaOxFfrz5Y/PrNJmBwqftyItNZooaAF6CR+vixe2HCmqSLub4ySOoFiuawE=";

    const signedVoucher = filecoin_signer.signVoucher(voucher, privateKey);

    let signedVoucherCBOR = cbor.deserialize(Buffer.from(signedVoucher, 'base64'));

    console.log(signedVoucherCBOR)
    let signature = signedVoucherCBOR[10]
    console.log(Buffer.from(expectedSignature, 'base64'))
    console.log(signature.slice(1, -1).toString('base64'))

    assert.strictEqual(signature.slice(1).toString('base64'), expectedSignature);

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
