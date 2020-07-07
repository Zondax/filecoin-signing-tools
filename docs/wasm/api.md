# API

Wasm api for filecoin signer service.


## generateMnemonic

Generate a 24 english words mnemonic.

```javascript
const signer_wasm = require('@zondax/filecoin-signer');
// or for browser
// import * as signer_wasm from "@zondax/filecoin-signer";

const mnemonic = signer_wasm.generateMnemonic();

//
console.log(mnemonic);
```

## keyDerive

Derive a child key from a mnemonic following a [BIP44 path](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki).

Arguments :
* **mnemonic**: a string containing the words;
* **path**: a BIP44 path;
* **password**: for encrypted seed if none use an empty string (e.g "")

```javascript
const signer_wasm = require('@zondax/filecoin-signer');
// or for browser
// import * as signer_wasm from "@zondax/filecoin-signer";

const mnemonic = "equip will roof matter pink blind book anxiety banner elbow sun young";

const path = "m/44'/461'/0/0/1";

const keypair = signer_wasm.keyDerive(mnemonic, path, "");

console.log(keypair);
```

## keyDeriveFromSeed

Derive a child key from a seed following a [BIP44 path](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki).

Arguments :
* **seed**: a seed (hexstring or Buffer);
* **path**: a BIP44 path;

```javascript
const signer_wasm = require('@zondax/filecoin-signer');
// or for browser
// import * as signer_wasm from "@zondax/filecoin-signer";
const bip39 = require('bip39');

const mnemonic = "equip will roof matter pink blind book anxiety banner elbow sun young";

const seed = bip39.mnemonicToSeedSync(mnemonic).toString('hex');

const path = "m/44'/461'/0/0/1";

const keypair = signer_wasm.keyDeriveFromSeed(seed, "m/44'/461'/0/0/1");

console.log(keypair);
```

## keyRecover

Recover a extended key from a private key.

Arguments :
* **privateKey**: a private key (hexstring or Buffer);
* **testnet**: a boolean value. Indicate if you want testnet or mainnet address;

```javascript
const signer_wasm = require('@zondax/filecoin-signer');
// or for browser
// import * as signer_wasm from "@zondax/filecoin-signer";

let privateKey = "private_key_hexstring";

const testnet = true;

const keypair = signer_wasm.keyRecover(privateKey, testnet);

console.log(keypair);
```

## transactionSerialize

Serialize a transaction and return a CBOR hexstring.

Arguments :
* **transaction**: a filecoin transaction;

```javascript
const signer_wasm = require('@zondax/filecoin-signer');
// or for browser
// import * as signer_wasm from "@zondax/filecoin-signer";

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

const cbor_transaction =  signer_wasm.transactionSerialize(transaction);

//
console.log(cbor_transaction);
```

## transaction\_serialize\_raw

Serialize a transaction and return teh CBOR equivalent as a Uint8Array.

Arguments :
* **transaction**: a filecoin transaction;

```javascript
const signer_wasm = require('@zondax/filecoin-signer');
// or for browser
// import * as signer_wasm from "@zondax/filecoin-signer";

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

const cbor_transaction =  signer_wasm.transactionSerialize(transaction);

//
console.log(cbor_transaction);
```

## transactionSerializeRaw

Serialize a transaction and return a CBOR buffer.

Arguments :
* **transaction**: a filecoin transaction;

```javascript
const signer_wasm = require('@zondax/filecoin-signer');
// or for browser
// import * as signer_wasm from "@zondax/filecoin-signer";

const transaction = {
    "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
    "from": "t1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka",
    "nonce": 1,
    "value": "100000",
    "gasprice": "2500",
    "gaslimit": "25000",
    "method": 0,
    "params": ""
};

const cbor_transaction =  signer_wasm.transactionSerializeRaw(JSON.stringify(transaction));

//
console.log(cbor_buffer);
```


## transactionParse

Parse a CBOR hextring into a filecoin transaction.

Arguments:
* **cbor_transaction**: the cbor (hexstring or Buffer);
* **testnet**: boolean value `true` if testnet or `false` for mainnet;

```javascript
const signer_wasm = require('@zondax/filecoin-signer');
// or for browser
// import * as signer_wasm from "@zondax/filecoin-signer";

const cbor_transaction = "885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855010f323f4709e8e4db0c1d4cd374f9f35201d26fb20144000186a0430009c41961a80040";

const testnet = true;

const transaction = signer_wasm.transactionParse(cbor_transaction, testnet);

//
console.log(transaction);
```

## transactionSign

Sign a transaction and return the signature (RSV format).

Arguments:
* **transaction**: a filecoin transaction;
* **privatekey**: a private key (hexstring or buffer);

```javascript
const signer_wasm = require('@zondax/filecoin-signer');
// or for browser
// import * as signer_wasm from "@zondax/filecoin-signer";
const bip32 = require('bip32');

// Use your private key
const MASTER_KEY = "xprv424242424242424242";

let MASTER_NODE = bip32.fromBase58(MASTER_KEY);
const example_key = MASTER_NODE.derivePath("m/44'/461'/0/0/0");

const signed_tx = signer_wasm.transactionSign(EXAMPLE_TRANSACTION, example_key.privateKey.toString("hex"));

console.log(signed_tx);
```

## transactionSignLotus (support Lotus schema)

Sign a transaction and return a JSON string of the signed transaction which can then be sent to a lotus node.

Arguments:
* **transaction**: a filecoin transaction;
* **privatekey**: a private key (hexstring or buffer);

```javascript
const signer_wasm = require('@zondax/filecoin-signer');
// or for browser
// import * as signer_wasm from "@zondax/filecoin-signer";
const bip32 = require('bip32');

// Use your private key
const MASTER_KEY = "xprv424242424242424242";

let MASTER_NODE = bip32.fromBase58(MASTER_KEY);
const example_key = MASTER_NODE.derivePath("m/44'/461'/0/0/0");

const signed_tx_json = signer_wasm.transactionSignLotus(EXAMPLE_TRANSACTION, example_key.privateKey.toString("hex"));

console.log(signed_tx_json);
```

## verifySignature

Verify a signature.

Arguments :
* **signature**: RSV format signature;
* **CBOR transaction**: the CBOR transaction;

```javascript
const signer_wasm = require('@zondax/filecoin-signer');
// or for browser
// import * as signer_wasm from "@zondax/filecoin-signer";


// RSV format signature
// r value [32 bits]
// s value [32 bits]
// v recovering id [1 bit]
const signatureRSV = "541025ca93d7d15508854520549f6a3c1582fbde1a511f21b12dcb3e49e8bdff3eb824cd8236c66b120b45941fd07252908131ffb1dffa003813b9f2bdd0c2f601";

const cbor_transaction = "885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855010f323f4709e8e4db0c1d4cd374f9f35201d26fb20144000186a0430009c41961a80040";


const result = signer_wasm.verifySignature(signatureRSV, cbor_transaction);

// true
console.log(result);
```

## createMultisig

Return a create multisig transaction.

Arguments :
* **Sender address**: the one in the `From` field;
* **Addresses**: the list of addresses taking part in the multisig contract;
* **Amount**: amount to start the multisig with;
* **Required signatures**: minimal number of signatures required;

```javascript
const signer_wasm = require('@zondax/filecoin-signer');
// or for browser
// import * as signer_wasm from "@zondax/filecoin-signer";


let addresses = ["t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy","t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"];
let sender_address = "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy";

let create_multisig_transaction = filecoin_signer.createMultisig(sender_address, addresses, "1000", 1);

console.log(create_multisig_transaction);
```

## proposeMultisig

Return a proposal multisig transaction.

Arguments :
* **ID address**: tthe id address;
* **To address**: address to which the funds are being moved from the multisig;
* **From address**: the one in the `From` field;
* **Amount**: amount to start the multisig with;

```javascript
const signer_wasm = require('@zondax/filecoin-signer');
// or for browser
// import * as signer_wasm from "@zondax/filecoin-signer";


let to_address = "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy";
let from_address = "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy";

let propose_multisig_transaction = filecoin_signer.proposeMultisig("t01", to_address, from_address, "1000");

console.log(propose_multisig_transaction);
```

## approveMultisig

Return an approval multisig transaction.

Arguments :
* **ID address**: the id address;
* **TxnID**: the idea of the proposal transaction;
* **Proposer address**: address of the proposer;
* **To address**: address to which the funds are being moved from the multisig;
* **Amount**: amount to start the multisig with;
* **From address**: the one in the `From` field;

```javascript
const signer_wasm = require('@zondax/filecoin-signer');
// or for browser
// import * as signer_wasm from "@zondax/filecoin-signer";


let to_address = "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy";
let from_address = "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy";
let proposer_address = "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy";

let approve_multisig_transaction = filecoin_signer.approveMultisig("t01", 1234, proposer_address, to_address, "1000", from_address);

console.log(approve_multisig_transaction);
```

## cancelMultisig

Return a cancel multisig transaction.

Arguments :
* **ID address**: the id address;
* **TxnID**: the idea of the proposal transaction;
* **Proposer address**: address of the proposer;
* **To address**: address to which the funds are being moved from the multisig;
* **Amount**: amount to start the multisig with;
* **From address**: the one in the `From` field;

```javascript
const signer_wasm = require('@zondax/filecoin-signer');
// or for browser
// import * as signer_wasm from "@zondax/filecoin-signer";


let to_address = "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy";
let from_address = "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy";
let proposer_address = "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy";

let approve_multisig_transaction = filecoin_signer.cancelMultisig("t01", 1234, proposer_address, to_address, "1000", from_address);

console.log(approve_multisig_transaction);
```

## serializeParams

Serialize parameters into cbor data.

Arguments :
* **params**: params object;

```javascript
const signer_wasm = require('@zondax/filecoin-signer');
// or for browser
// import * as signer_wasm from "@zondax/filecoin-signer";

let addresses = ["t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy","t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"];

let params = {
    code_cid: 'fil/1/multisig',
    constructor_params: { signers: addresses, num_approvals_threshold: 1 }
}

let serialized_params = filecoin_signer.serializeParams(params);

console.log(serialized_params);
```
