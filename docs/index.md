# Filecoin Signing Tools

Filecoin signing tools offer basic functionalities for signing Filecoin transactions.

There is several implementations :
 * Rust
 * Javascript (pure javascript and wasm)

Notes: The pure Javascript implementation is less complete than the Rust and Wasm one.

Examples:

  | Caller          | Callee          | Status                           |                                  |
  |-----------------|-----------------|----------------------------------|----------------------------------|
  |                 |                 |                                  |                                  |
  | Browser         | WASM            | Ready :heavy_check_mark:         | [Link](https://github.com/Zondax/filecoin-signing-tools/blob/master/examples/wasm_browser)    |
  | Node.js / Mocha | WASM            | Ready :heavy_check_mark:         | [Link](https://github.com/Zondax/filecoin-signing-tools/blob/master/examples/wasm_node)       |
  |                 |                 |                                  |                                  |
  | C               | Rust            | Ready :heavy_check_mark:         | [Link](https://github.com/Zondax/filecoin-signing-tools/blob/master/examples/ffi/c)           |
  | C++             | Rust            | Ready :heavy_check_mark:         | [Link](https://github.com/Zondax/filecoin-signing-tools/blob/master/examples/ffi/c++)         |
  | Java            | Rust            | Ready :heavy_check_mark:         | [Link](https://github.com/Zondax/filecoin-signing-tools/blob/master/examples/ffi/java)        |
  | Kotlin          | Rust            | Ready :heavy_check_mark:         | [Link](https://github.com/Zondax/filecoin-signing-tools/blob/master/examples/ffi/kotlin)      |
  | Go              | Rust            | Ready :heavy_check_mark:         | [Link](https://github.com/Zondax/filecoin-signing-tools/blob/master/examples/ffi/go)          |
  | Objective-C     | Rust            | Ready :heavy_check_mark:         | [Link](https://github.com/Zondax/filecoin-signing-tools/blob/master/examples/ffi/objective-c) |
  | Swift           | Rust            | Ready :heavy_check_mark:         | [Link](https://github.com/Zondax/filecoin-signing-tools/blob/master/examples/ffi/swift)       |
  | Flutter         | Rust            | Ready :heavy_check_mark:         | [Link](https://github.com/Zondax/filecoin-signing-tools/blob/master/examples/ffi/flutter)     |
  | React Native    | Rust            | Planned :hourglass_flowing_sand: | [Soon](https://github.com/Zondax/filecoin-signing-tools/)                         |