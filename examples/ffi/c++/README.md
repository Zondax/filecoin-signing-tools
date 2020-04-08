# C++ bindings

Taking the c++ header aside, this example uses the same bindings provided for C.

# Running 

Assuming that the header and library are in the same directory.

```bash
g++ main.cpp -L. -lfilecoin_signer_ffi -o main
LD_LIBRARY_PATH=. ./main
```
