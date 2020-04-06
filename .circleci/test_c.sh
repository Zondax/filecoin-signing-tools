cp -r ../examples/ffi/c $OUT_DIR
cbindgen --config cbindgen.toml --crate filecoin-signer-ffi --lang c --output $OUT_DIR/filecoin_signer_ffi.h
cargo build
cp ../target/debug/libfilecoin_signer_ffi.so $OUT_DIR
( cd $OUT_DIR; gcc main.c -L. -lfilecoin_signer_ffi -o main )
LD_LIBRARY_PATH=$OUT_DIR $OUT_DIR/main
LD_LIBRARY_PATH=$OUT_DIR valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose $OUT_DIR/main