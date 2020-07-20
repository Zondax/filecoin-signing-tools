# API

JSON RPC api for filecoin service.

## key\_generate\_mnemonic

Generate a 24 english words mnemonic.

```javascript
const axios = require("axios");

const URL = "http://127.0.0.1:3030/v0";
const JWT = "blablablablablabla";

const response = await await axios.post(
  URL,
  {
    jsonrpc: "2.0",
    method: "key_generate_mnemonic",
    params: [],
    id: 1,
  },
  {
    headers: {
      "Content-Type": "application/json",
      Accept: "*/*",
      Authorization: `Bearer ${JWT}`,
    },
  },
);

//
console.log(response.result);
```

## key_derive

Derive a child key from a mnemonic following a [BIP44 path](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki).

Arguments :
* **mnemonic**: a string containing the words;
* **path**: a BIP44 path;
* **password (optional)**: for encrypted seed;

```javascript
const axios = require("axios");

const URL = "http://127.0.0.1:3030/v0";
const JWT = "blablablablablabla";

const params = [
  // mnemonic
  "equip will roof matter pink blind book anxiety banner elbow sun young",
  // path
  "m/44'/461'/0/0/0"
];

const response = await await axios.post(
  URL,
  {
    jsonrpc: "2.0",
    method: "key_derive",
    params,
    id: 1,
  },
  {
    headers: {
      "Content-Type": "application/json",
      Accept: "*/*",
      Authorization: `Bearer ${JWT}`,
    },
  },
);

//
console.log(response.result);
```

## key\_derive\_from\_seed

Derive a child key from a seed following a [BIP44 path](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki).

Arguments :
* **seed**: a seed as a hex string;
* **path**: a BIP44 path;

```javascript
const axios = require("axios");
const bip39 = require('bip39');

const mnemonic = "equip will roof matter pink blind book anxiety banner elbow sun young";

const seed = bip39.mnemonicToSeedSync(mnemonic).toString('hex');

const URL = "http://127.0.0.1:3030/v0";
const JWT = "blablablablablabla";

const params = [
  // seed
  seed,
  // path
  "m/44'/461'/0/0/0"
];

const response = await await axios.post(
  URL,
  {
    jsonrpc: "2.0",
    method: "key_derive_from_seed",
    params,
    id: 1,
  },
  {
    headers: {
      "Content-Type": "application/json",
      Accept: "*/*",
      Authorization: `Bearer ${JWT}`,
    },
  },
);

//
console.log(response.result);
```

## transaction_serialize

Serialize a transaction and return a CBOR hexstring.

Arguments :
* **transaction**: a filecoin transaction;

```javascript
const axios = require("axios");

const URL = "http://127.0.0.1:3030/v0";
const JWT = "blablablablablabla";

const transaction = {
  to: "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
  from: "t1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka",
  nonce: 1,
  value: "100000",
  gas_price: "2500",
  gas_limit: 25000,
  method: 0,
  params: "",
};

const response = await await axios.post(
  URL,
  {
    jsonrpc: "2.0",
    method: "transaction_serialize",
    params: transaction,
    id: 1,
  },
  {
    headers: {
      "Content-Type": "application/json",
      Accept: "*/*",
      Authorization: `Bearer ${JWT}`,
    },
  },
);

//
console.log(response.result);
```

## transaction_parse

Parse a CBOR hextring into a filecoin transaction.

Arguments:
* **hexstring**: the cbor hexstring to parse;
* **testnet**: boolean value `true` if testnet or `false` for mainnet;

```javascript
const axios = require("axios");

const URL = "http://127.0.0.1:3030/v0";
const JWT = "blablablablablabla";

const params = [
  // cbor hexstring
  "885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855010f323f4709e8e4db0c1d4cd374f9f35201d26fb20144000186a0430009c41961a80040",
  // testnet
  true];

const response = await await axios.post(
  URL,
  {
    jsonrpc: "2.0",
    method: "transaction_parse",
    params,
    id: 1,
  },
  {
    headers: {
      "Content-Type": "application/json",
      Accept: "*/*",
      Authorization: `Bearer ${JWT}`,
    },
  },
);

//
console.log(response.result);
```

## sign_transaction

Sign a transaction and return the signature (RSV format).

Arguments:
* **transaction**: a filecoin transaction;
* **privatekey**: a private key as hexstring;

```javascript
const axios = require("axios");

const URL = "http://127.0.0.1:3030/v0";
const JWT = "blablablablablabla";

const params = [
  // filecoin transaction
  {
    to: "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
    from: "t1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka",
    nonce: 1,
    value: "100000",
    gas_price: "2500",
    gas_limit: 25000,
    method: 0,
    params: "",
  }
  // privatekey hexstring
  "f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a"];

const response = await await axios.post(
  URL,
  {
    jsonrpc: "2.0",
    method: "sign_transaction",
    params,
    id: 1,
  },
  {
    headers: {
      "Content-Type": "application/json",
      Accept: "*/*",
      Authorization: `Bearer ${JWT}`,
    },
  },
);

//
console.log(response.result);
```

## verify_signature

Verify a signature.

Arguments :
* **signature**: RSV format signature;
* **CBOR transaction**: the CBOR transaction;

```javascript
const axios = require("axios");

const URL = "http://127.0.0.1:3030/v0";
const JWT = "blablablablablabla";

const params = [
  // signature
  "8869ed25fb3f97ae0b28e6a472acf4291309da3f5962b3c957abce418d30b46c065baa56e71ca9848830f72272fd47a4270ecb7b57f3413a72e443455c6ee2b500",
  // CBOR transaction
  "885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855015d77a86f78f72f2f71edc37ce67cb344417ea1520243002710430009c4430061a80040"
];

const response = await await axios.post(
  URL,
  {
    jsonrpc: "2.0",
    method: "verify_signature",
    params,
    id: 1,
  },
  {
    headers: {
      "Content-Type": "application/json",
      Accept: "*/*",
      Authorization: `Bearer ${JWT}`,
    },
  },
);

//
console.log(response.result);
```

## get_status

Get the status of a transaction.

Arguments :
* **message cid**: message cid of the transaction;


```javascript
const axios = require("axios");

const URL = "http://127.0.0.1:3030/v0";
const JWT = "blablablablablabla";

const params = [
  // message cid
  "bafy2bzacea2ob4bctlucgp2okbczqvk5ctx4jqjapslz57mbcmnnzyftgeqgu"
];

const response = await await axios.post(
  URL,
  {
    jsonrpc: "2.0",
    method: "get_status",
    params,
    id: 1,
  },
  {
    headers: {
      "Content-Type": "application/json",
      Accept: "*/*",
      Authorization: `Bearer ${JWT}`,
    },
  },
);

//
console.log(response.result);
```

## get_nonce

Get the nonce of an account.

Arguments :
* **account**: the account from which we want the nonce;

```javascript
const axios = require("axios");

const URL = "http://127.0.0.1:3030/v0";
const JWT = "blablablablablabla";

const params = [
  // account
  "t1lv32q33y64xs64pnyn6om7ftirax5ikspkumwsa"
];

const response = await await axios.post(
  URL,
  {
    jsonrpc: "2.0",
    method: "get_nonce",
    params,
    id: 1,
  },
  {
    headers: {
      "Content-Type": "application/json",
      Accept: "*/*",
      Authorization: `Bearer ${JWT}`,
    },
  },
);

//
console.log(response.result);
```

## send\_signed\_tx

Send a signed transaction to a filecoin node.

Arguments :
* **signed tx**: a transaction and its signature;

```javascript
const axios = require("axios");

const URL = "http://127.0.0.1:3030/v0";
const JWT = "blablablablablabla";

const params = [
  // account
  {
    message: {
      to: "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
      from: "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
      nonce: 2,
      value: "10000",
      gas_price: "2500",
      gas_limit: 25000,
      method: 0,
      params: "",
    },
    signature: "8869ed25fb3f97ae0b28e6a472acf4291309da3f5962b3c957abce418d30b46c065baa56e71ca9848830f72272fd47a4270ecb7b57f3413a72e443455c6ee2b500",
  }
];

const response = await await axios.post(
  URL,
  {
    jsonrpc: "2.0",
    method: "send_signed_tx",
    params,
    id: 1,
  },
  {
    headers: {
      "Content-Type": "application/json",
      Accept: "*/*",
      Authorization: `Bearer ${JWT}`,
    },
  },
);

//
console.log(response.result);
```
