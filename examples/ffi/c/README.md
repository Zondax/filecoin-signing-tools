# C bindingds

To use this example, download the latest header and the library or compile the `signer-ffi` directory.

# Example

Assuming that the library and the header are in the same directory.

```bash
gcc main.c -L. -lfilecoin_signer_ffi -o main
LD_LIBRARY_PATH=. ./main
```