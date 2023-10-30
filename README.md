# Filecoin Signing Tools

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![GithubActions](https://github.com/zondax/filecoin-signing-tools/actions/workflows/main.yaml/badge.svg)](https://github.com/Zondax/filecoin-signing-tools/blob/main/.github/workflows/main.yaml)
[![npm version](https://badge.fury.io/js/%40zondax%2Ffilecoin-signing-tools.svg)](https://badge.fury.io/js/%40zondax%2Ffilecoin-signing-tools)

---

![zondax_light](docs/assets/zondax_light.png#gh-light-mode-only)
![zondax_dark](docs/assets/zondax_dark.png#gh-dark-mode-only)

_Please visit our website at [zondax.ch](https://www.zondax.ch)_

---

---
## 🚫 PROJECT MAINTENANCE NOTICE 🚫

This package will continue to be actively maintained until **2023-12-31**. After this date, it will no longer receive updates or bug fixes. Users are encouraged to seek alternative solutions after this period and are welcome to fork the project for continued development.

--- 

## :warning: Relevant Note :warning:
We are excited to announce that we have created a new package called [izari-filecoin :link:](https://github.com/zondax/izari-filecoin), 
which will be the successor to filecoin-signing-tools. Izari Filecoin is an advanced and 
user-friendly package that includes several new features and improvements that were not 
available in this project. The new package is also better organized and easier to use. 
While this project will continue to be maintained, no new features will be added to it. 
Therefore, we strongly recommend that you switch to Izari Filecoin to take advantage of 
its new features and benefits.

---

You can find more information in the [Documentation Site](https://docs.zondax.ch/filecoin-signing-tools)

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
    
- Examples

| Caller          | Callee          | Status                           |                                  |
|-----------------|-----------------|----------------------------------|----------------------------------|
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
