# Filecoin Signing Tools - npm package

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CircleCI](https://circleci.com/gh/Zondax/filecoin-signing-tools.svg?style=shield&circle-token=51b2d5fe68c0eb73436dace6f47fa0a387169ef5)](https://circleci.com/gh/Zondax/filecoin-signing-tools)
[![npm version](https://badge.fury.io/js/%40zondax%2Ffilecoin-signing-tools.svg)](https://badge.fury.io/js/%40zondax%2Ffilecoin-signing-tools)

This is part of the [Filecoin Signing Tools](https://github.com/Zondax/filecoin-signing-tools) project

This library provides both WASM and Pure JS implementations.

You can find usage examples [here](https://github.com/Zondax/filecoin-signing-tools/tree/master/examples/wasm_node)

```
    "test": "mocha",
    "test:js": "env PURE_JS=True mocha",
```

## Structure

* `ledger-filecoin-js` refers to https://github.com/Zondax/ledger-filecoin-js
* `src` rust bindings for javascript
* `pkg` ready to distribute wasm module
* `tests` rust tests
* `dist` usable files
