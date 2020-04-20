# Objective-C bindings

Currently, we don't provide compiled artifacts, threfore, manual steps to build and orchestrate the libraries and headers are necessary.

# Running

Assuming that the header and library are in the same directory.

```bash
gcc ./main.m `gnustep-config --objc-flags` `gnustep-config --objc-libs` -L. -lfilecoin_signer_ffi -lgnustep-base -o ./main
LD_LIBRARY_PATH=. ./main
```
