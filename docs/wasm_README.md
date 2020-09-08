# Getting Started

You will need to install [`@zondax/filecoin-signing-tools`](https://www.npmjs.com/package/@zondax/filecoin-signing-tools) npm package.

This library is an utility library for filecoin composed of a wasm api and an wrapper for hardware wallet (like ledger).

To start using load the library :

```javascript
const signer = require('@zondax/filecoin-signing-tools');
// or for browser
import * as signer from "@zondax/filecoin-signing-tools";
```

::: warning
In browser `generateMnemonic` use the javascript `crypto` lib.
:::
