# Swift bindingds

Currently, we don't provide compiled artifacts, threfore, manual steps to build and orchestrate the libraries and headers are necessary.

# Running

Assuming that the header and library are in the same directory.

```bash
swiftc -import-objc-header filecoin_signer_ffi.h main.swift libfilecoin_signer_ffi.so -o ./main
LD_LIBRARY_PATH=. ./main
```