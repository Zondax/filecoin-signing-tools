# API

Wasm api for filecoin signer service.


## mnemonic_generate

Generate a 24 english words mnemonic.

```javascript
const signer_wasm = require('@zondax/filecoin-signer-wasm');
// or for browser
// import * as signer_wasm from "@zondax/filecoin-signer-wasm";

const mnemonic = signer_wasm.mnemonic_generate();

//
console.log(mnemonic);
```

## key_derive

Derive a child key from a mnemonic following a [BIP44 path](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki).

Arguments :
* **mnemonic**: a string containing the words;
* **path**: a BIP44 path;
* **password**: for encrypted seed if none use an empty string (e.g "")

```javascript
const signer_wasm = require('@zondax/filecoin-signer-wasm');
// or for browser
// import * as signer_wasm from "@zondax/filecoin-signer-wasm";

const mnemonic = "equip will roof matter pink blind book anxiety banner elbow sun young";

const path = "m/44'/461'/0/0/1";

const keypair = signer_wasm.key_derive(mnemonic, path, "");

console.log(keypair);
```

## key_derive_from_seed

Derive a child key from a seed following a [BIP44 path](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki).

Arguments :
* **seed**: a seed as a hex string;
* **path**: a BIP44 path;

```javascript
const signer_wasm = require('@zondax/filecoin-signer-wasm');
// or for browser
// import * as signer_wasm from "@zondax/filecoin-signer-wasm";
const bip39 = require('bip39');

const mnemonic = "equip will roof matter pink blind book anxiety banner elbow sun young";

const seed = bip39.mnemonicToSeedSync(mnemonic).toString('hex');

const path = "m/44'/461'/0/0/1";

const keypair = signer_wasm.key_derive_from_seed(seed, "m/44'/461'/0/0/1");

console.log(keypair);
```

## key_recover

Recover a extended key from a private key.

Arguments :
* **privateKey**: a private key as a hex string;
* **testnet**: a boolean value. Indicate if you wnat testnet or mainnet address;

```javascript
const signer_wasm = require('@zondax/filecoin-signer-wasm');
// or for browser
// import * as signer_wasm from "@zondax/filecoin-signer-wasm";

let privateKey = "private_key_hexstring";

const testnet = true;

const keypair = signer_wasm.key_recover(privateKey, testnet);

console.log(keypair);
```

## transaction_serialize

Serialize a transaction and return a CBOR hexstring.

Arguments :
* **transaction**: a filecoin transaction;

```javascript
const signer_wasm = require('@zondax/filecoin-signer-wasm');
// or for browser
// import * as signer_wasm from "@zondax/filecoin-signer-wasm";

const transaction = {
    "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
    "from": "t1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka",
    "nonce": 1,
    "value": "100000",
    "gasprice": "2500",
    "gaslimit": 25000,
    "method": 0,
    "params": ""
};

const cbor_transaction =  signer_wasm.transaction_serialize(JSON.stringify(transaction));

//
console.log(cbor_transaction);
```

## transaction_parse

Parse a CBOR hextring into a filecoin transaction.

Arguments:
* **hexstring**: the cbor hexstring to parse;
* **testnet**: boolean value `true` if testnet or `false` for mainnet;

```javascript
const signer_wasm = require('@zondax/filecoin-signer-wasm');
// or for browser
// import * as signer_wasm from "@zondax/filecoin-signer-wasm";

const cbor_transaction = "885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855010f323f4709e8e4db0c1d4cd374f9f35201d26fb20144000186a0430009c41961a80040";

const testnet = true;

const transaction = signer_wasm.transaction_parse(cbor_transaction, testnet);

//
console.log(transaction);
```

## transaction_sign

Sign a transaction and return the signature (RSV format).

Arguments:
* **transaction**: a filecoin transaction;
* **privatekey**: a private key as hexstring;

```javascript
const signer_wasm = require('@zondax/filecoin-signer-wasm');
// or for browser
// import * as signer_wasm from "@zondax/filecoin-signer-wasm";
const bip32 = require('bip32');

// Use your private key
const MASTER_KEY = "xprv424242424242424242";

let MASTER_NODE = bip32.fromBase58(MASTER_KEY);
const example_key = MASTER_NODE.derivePath("m/44'/461'/0/0/0");

const signed_tx = signer_wasm.transaction_sign(EXAMPLE_TRANSACTION, example_key.privateKey.toString("hex"));

console.log(signed_tx);
```

## verify_signature

Verify a signature.

Arguments :
* **signature**: RSV format signature;
* **CBOR transaction**: the CBOR transaction;

```javascript
const signer_wasm = require('@zondax/filecoin-signer-wasm');
// or for browser
// import * as signer_wasm from "@zondax/filecoin-signer-wasm";


// RSV format signature
// r value [32 bits]
// s value [32 bits]
// v recovering id [1 bit]
const signatureRSV = "541025ca93d7d15508854520549f6a3c1582fbde1a511f21b12dcb3e49e8bdff3eb824cd8236c66b120b45941fd07252908131ffb1dffa003813b9f2bdd0c2f601";

const cbor_transaction = "885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855010f323f4709e8e4db0c1d4cd374f9f35201d26fb20144000186a0430009c41961a80040";


const result = signer_wasm.verify_signature(signatureRSV, cbor_transaction);

// true
console.log(result);
```
