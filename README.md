# Filecoin Signing Tools

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![GithubActions](https://github.com/zondax/filecoin-signing-tools/actions/workflows/main.yaml/badge.svg)](https://github.com/Zondax/filecoin-signing-tools/blob/main/.github/workflows/main.yaml)
[![npm version](https://badge.fury.io/js/%40zondax%2Ffilecoin-signing-tools.svg)](https://badge.fury.io/js/%40zondax%2Ffilecoin-signing-tools)

You can find more information in the [Documentation Site](https://zondax.ch/projects/filecoin-signing-tools/)

- Rust Native Library
  - Secp256k1
  - Multisig (Work in progress)
  - BLS
  - Filecoin transactions (CBOR <> JSON serialization)
- WASM Library
  - Secp256k1
  - Multisig (Work in progress)
  - BLS
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
  | Node.js / Mocha | WASM            | Ready :heavy_check_mark:         | [Link](examples/wasm_node)       |
  |                 |                 |                                  |                                  |
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

You will need [rust](https://www.rust-lang.org/tools/install) installed.

```bash
# Install wasm-pack in your system
$ make install_wasmpack
# Install some utilitary tools
$ make install_deps_rust
```

Note: wasm  parck are required if you want to use the wasm version of the lib.

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
make build_npm
```

After this, you can run the following tests / examples:

| Command                  | Description               |
|--------------------------|---------------------------|
| `make test_npm_unit`     | Unit tests                |
| `make test_npm_node`     | Node integration tests    |
| `make test_npm_browser`  | Browser integration tests |
