# Getting Started

You will need to install [`@zondax/filecoin-signer`](https://www.npmjs.com/package/@zondax/filecoin-signer) npm package.

This library is an utility library for filecoin composed of a wasm api and an wrapper for hardware wallet (like ledger).

To start using load the library :

```javascript
const signer = require('@zondax/filecoin-signer');
// or for browser
import * as signer from "@zondax/filecoin-signer";
```

::: warning
In browser `generateMnemonic` use the javascript `crypto` lib.
:::
