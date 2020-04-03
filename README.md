# Filecoin Signing Tools

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CircleCI](https://circleci.com/gh/Zondax/filecoin-rs.svg?style=shield&circle-token=51b2d5fe68c0eb73436dace6f47fa0a387169ef5)](https://circleci.com/gh/Zondax/filecoin-rs)
[![npm version](https://badge.fury.io/js/%40zondax%2Ffilecoin-signer-wasm.svg)](https://badge.fury.io/js/%40zondax%2Ffilecoin-signer-wasm)

You can find more information in the [Documentation Site](https://zondax.github.io/filecoin-rs/)

- Rust Native Library
  - Secp256k1
  - Multisig (Work in progress)
  - BLS (Work in progress)
  - Hardware Wallet support (Ledger Nano S/X)
  - Filecoin transactions (CBOR <> JSON serialization)
- WASM Library
  - Secp256k1
  - Multisig (Work in progress)
  - BLS (Work in progress)
  - Hardware Wallet support (Ledger Nano S/X)
  - Filecoin transactions (CBOR <> JSON serialization)
- JSON RPC Server
  - Focus: Exchange integration
  - Exposes most of the functions available in the signing library
  - Lotus integration:
    - nonce caching
    - determine testnet vs mainnet
    - retrieve nonce
    - submit signed transaction
    - retrieve tx status
- Examples

  | From            | To              | Status                           |                          |
  | --------------- | --------------- | -------------------------------- | ------------------------ |
  | Node.js         | JSONRPC Service | Ready :heavy_check_mark:         | [Link](examples/jsonrpc) |
  |                 |                 |                                  |                          |
  | Browser         | WASM            | Ready :heavy_check_mark:         | [Link](examples/www)     |
  | Browser         | WASM + Ledger   | Planned :hourglass_flowing_sand: | [Soon]()                 |
  | Node.js / Mocha | WASM            | Ready :heavy_check_mark:         | [Link](examples/wasm)    |
  |                 |                 |                                  |                          |
  | Rust            | Rust + Ledger   | Planned :hourglass_flowing_sand: | [Soon]()                 |
  | C/C++           | Rust            | Planned :hourglass_flowing_sand: | [Soon]()                 |
  | Java            | Rust            | Planned :hourglass_flowing_sand: | [Soon]()                 |
  | Kotlin          | Rust            | Planned :hourglass_flowing_sand: | [Soon]()                 |
  | Go              | Rust            | Planned :hourglass_flowing_sand: | [Soon]()                 |
  | Objective-C     | Rust            | Planned :hourglass_flowing_sand: | [Soon]()                 |
  | Swift           | Rust            | Planned :hourglass_flowing_sand: | [Soon]()                 |
  | React Native    | Rust            | Planned :hourglass_flowing_sand: | [Soon]()                 |
  | Flutter         | Rust            | Planned :hourglass_flowing_sand: | [Soon]()                 |
