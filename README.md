# Filecoin Signing Tools

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CircleCI](https://circleci.com/gh/Zondax/filecoin-signing-tools.svg?style=shield&circle-token=51b2d5fe68c0eb73436dace6f47fa0a387169ef5)](https://circleci.com/gh/Zondax/filecoin-signing-tools)
[![npm version](https://badge.fury.io/js/%40zondax%2Ffilecoin-signing-tools.svg)](https://badge.fury.io/js/%40zondax%2Ffilecoin-signing-tools)

You can find more information in the [Documentation Site](https://zondax.github.io/filecoin-signing-tools/)

- Rust Native Library
  - Secp256k1
  - Multisig (Work in progress)
  - BLS
  - Hardware Wallet support (Ledger Nano S/X)
  - Filecoin transactions (CBOR <> JSON serialization)
- WASM Library
  - Secp256k1
  - Multisig (Work in progress)
  - BLS
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

  | Caller          | Callee          | Status                           |                                  |
  |-----------------|-----------------|----------------------------------|----------------------------------|
  | Node.js         | JSONRPC Service | Ready :heavy_check_mark:         | [Link](examples/service_jsonrpc) |
  |                 |                 |                                  |                                  |
  | Browser         | WASM            | Ready :heavy_check_mark:         | [Link](examples/wasm_browser)    |
  | Browser         | WASM + Ledger   | Ready :heavy_check_mark:         | [Link](examples/wasm_node)       |
  | Node.js / Mocha | WASM            | Ready :heavy_check_mark:         | [Link](examples/wasm_node)       |
  |                 |                 |                                  |                                  |
  | Rust            | Rust + Ledger   | Ready :heavy_check_mark:         | [Link](examples/wasm_ledger)     |
  | C               | Rust            | Ready :heavy_check_mark:         | [Link](examples/ffi/c)           |
  | C++             | Rust            | Ready :heavy_check_mark:         | [Link](examples/ffi/c++)         |
  | Java            | Rust            | Ready :heavy_check_mark:         | [Link](examples/ffi/java)        |
  | Kotlin          | Rust            | Ready :heavy_check_mark:         | [Link](examples/ffi/kotlin)      |
  | Go              | Rust            | Ready :heavy_check_mark:         | [Link](examples/ffi/go)          |
  | Objective-C     | Rust            | Ready :heavy_check_mark:         | [Link](examples/ffi/objective-c) |
  | Swift           | Rust            | Ready :heavy_check_mark:         | [Link](examples/ffi/swift)       |
  | Flutter         | Rust            | Ready :heavy_check_mark:         | [Link](examples/ffi/flutter)     |
  | React Native    | Rust            | Planned :hourglass_flowing_sand: | [Soon]()                         |

## Running tests and examples

> TIP: A good place to look for reproducible steps is the circleci configuration of this project

### Installing dependencies

```bash
make deps
```

### Rust

```bash
cargo test -p filecoin-signer
```

### Service

To run these tests, you need to set two environment variables first so tests can reach a Lotus node:

|                  |          |
|------------------|----------|
| LOTUS_SECRET_URL | some_url |
| LOTUS_SECRET_JWT | some_jwt |

Then you can run:

```bash
cargo test -p filecoin-signer
```

### WASM

Build WASM and link it locally so examples are linked to the local version:

```bash
make link_wasm
```

After this, you can run the following tests / examples:

| Command                  | Description               |
|--------------------------|---------------------------|
| `make test_wasm_unit`    | Unit tests                |
| `make test_wasm_node`    | Node integration tests    |
| `make test_wasm_browser` | Browser integration tests |
| `make test_wasm_ledger`  | Ledger integration tests  |
