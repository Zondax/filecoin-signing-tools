# Getting Started

You will need to install [`@zondax/filecoin-signer-wasm`](https://www.npmjs.com/package/@zondax/filecoin-signer-wasm) npm package.

This library is wasm library that can work both in node and browser.

To start using load the library :

```javascript
const signer_wasm = require('@zondax/filecoin-signer-wasm');
// or for browser
import * as signer_wasm from "@zondax/filecoin-signer-wasm";
```

::: warning
In browser `mnemonic_generate` use the javascript `crypto` lib.
:::
