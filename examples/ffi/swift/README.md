# Swift bindingds

To use this example, download the latest header and library or compile the `signer-ffi` directory.

# Running

Assuming that the header and library are in the same directory.

```bash
swiftc -import-objc-header filecoin_signer_ffi.h main.swift libfilecoin_signer_ffi.so -o ./main
LD_LIBRARY_PATH=. ./main
```