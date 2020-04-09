mkdir $OUT_DIR
cp -r ./examples/ffi/c++/* $OUT_DIR
cd $OUT_DIR
cp /tmp/filecoin_signer_ffi_cpp.h ./filecoin_signer_ffi.h
cp /tmp/libfilecoin_signer_ffi.so .
g++ main.cpp -L. -lfilecoin_signer_ffi -o ./main
LD_LIBRARY_PATH=. ./main
LD_LIBRARY_PATH=. valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose ./main