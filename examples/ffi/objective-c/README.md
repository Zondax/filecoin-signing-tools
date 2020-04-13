# Objective-C bindingds

To use this example, download the latest header and library or compile the `signer-ffi` directory.

# Running

Assuming that the header and library are in the same directory.

```bash
gcc ./main.m `gnustep-config --objc-flags` `gnustep-config --objc-libs` -L. -lfilecoin_signer_ffi -lgnustep-base -o ./main
LD_LIBRARY_PATH=. ./main
```