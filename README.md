# Filecoin Signer

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CircleCI](https://circleci.com/gh/Zondax/filecoin-rs.svg?style=shield&circle-token=51b2d5fe68c0eb73436dace6f47fa0a387169ef5)](https://circleci.com/gh/Zondax/filecoin-rs)

**library names are subject to change**

This repository provides the following:

- Filecoin service
- Filecoin signing library
- JS Integration examples

# Filecoin service

Provides a backend service that will be typically used by exchanges. 

### Main features:

- JSON RPC Server
    - Exposes most of the functions available in the signing library
- JSON RPC Client. Lotus integration. 
    - Support is limited to only required methods:
        - determine testnet vs mainnet 
        - retrieve nonce
        - submit signed transaction
        - retrieve tx status

# Filecoin signing library

### Main features:

- CBOR <-> JSON serialization and deserialization
- Secp256k1 signing, etc.
- Can be compiled as WASM
- API specs (work in progress)

# Examples (Work in progress)

- *examples/jsonrpc* minimal JS examples/integration tests for signing service
- *examples/www* how to use the signing library when compiled as WASM from a browser
- *examples/wasm* integration tests written in JS for WASM

