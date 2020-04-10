mkdir $OUT_DIR
cp -r ./examples/ffi/go/* $OUT_DIR
cd $OUT_DIR
cp /tmp/filecoin_signer_ffi.h ./filecoin_signer_ffi.h
cp /tmp/libfilecoin_signer_ffi.so .
LD_LIBRARY_PATH=. go run main.go