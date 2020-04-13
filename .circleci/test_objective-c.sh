mkdir $OUT_DIR
cp -r ./examples/ffi/objective-c/* $OUT_DIR
cd $OUT_DIR;
cp /tmp/filecoin_signer_ffi.h .
cp /tmp/libfilecoin_signer_ffi.so .
gcc ./main.m `gnustep-config --objc-flags` `gnustep-config --objc-libs` -L. -lfilecoin_signer_ffi -lgnustep-base -o ./main
LD_LIBRARY_PATH=. ./main
