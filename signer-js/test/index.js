const assert = require('assert');
const bip32 = require('bip32');
const bip39 = require('bip39');
const filecoin_signer = require('../src');

const EXAMPLE_MNEMONIC = "equip will roof matter pink blind book anxiety banner elbow sun young";
const MASTER_KEY = "xprv9s21ZrQH143K49QgrAgAVELf6ue2tZNHYUc7yfj8JGZY9SpZ38u8EfhWi85GsA6grUeB36wXrbNTkjX9EfGP1ybbPRG4sdP2EPfY1SZ2BF5";
const MASTER_NODE = bip32.fromBase58(MASTER_KEY);

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
    assert.strictEqual(keypair.address, "f1rovwtiuo5ncslpmpjftzu5akswbgsgighjazxoi");
  });

  it("should derive key from mnemonic and return a testnet address", () => {
      const keypair = filecoin_signer.keyDerive(EXAMPLE_MNEMONIC, "m/44'/1'/0/0/1", "");

      console.log("Public Key Raw         :", keypair.public_raw);
      console.log("Public Key             :", keypair.public_hexstring);
      console.log("Private                :", keypair.private_hexstring);
      console.log("Address                :", keypair.address);

      const expected_keys = MASTER_NODE.derivePath("m/44'/1'/0/0/1");
      assert.strictEqual(keypair.private_hexstring, expected_keys.privateKey.toString("hex"));
      assert(keypair.address.startsWith('t'));
  });

  it('should fail because of missing password', () => {
      assert.throws(() => {
              filecoin_signer.keyDerive(EXAMPLE_MNEMONIC, "m/44'/461'/0/0/1")
          },
          /argument must be of type string or an instance of Buffer or ArrayBuffer. Received undefined/
      );
  });

  it('should derive key with the password', () => {
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

  it('should not match the key with the different password', () => {
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
    assert(false)
  })
})

describe("keyRecover", function() {
  it("should recover key", function() {
    assert(false)
  })
})

describe("transactionSerialize", function() {
  it("should serialize transaction", function() {
    assert(false)
  })
})

describe("transactionSerializeRaw", function() {
  it("should serialize raw transaction", function() {
    assert(false)
  })
})

describe("transactionParse", function() {
  it("should parse transaction", function() {
    assert(false)
  })
})

describe("transactionSign", function() {
  it("should sign transaction", function() {
    assert(false)
  })
})

describe("transactionSignLotus", function() {
  it("should sign transaction and return a Lotus compatible json string", function() {
    assert(false)
  })
})

describe("transactionSignRaw", function() {
  it("should sign transaction and return raw signature", function() {
    assert(false)
  })
})

describe("verifySignature", function() {
  it("should verify signature", function() {
    assert(false)
  })
})
