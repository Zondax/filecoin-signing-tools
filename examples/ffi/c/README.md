# C bindingds

To use this example, download the latest header and library or compile the `signer-ffi` directory.

# Running

Assuming that the header and library are in the same directory.

```bash
gcc main.c -L. -lfilecoin_signer_ffi -o main
LD_LIBRARY_PATH=. ./main
```