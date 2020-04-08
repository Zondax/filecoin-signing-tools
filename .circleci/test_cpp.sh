cd signer-ffi
mkdir $OUT_DIR
cp -r ../examples/ffi/c++/* $OUT_DIR
rustup default nightly
cbindgen --config cbindgen.toml --crate filecoin-signer-ffi --lang c++ --output $OUT_DIR/filecoin_signer_ffi.h
rustup default stable
cargo build
cp ../target/debug/libfilecoin_signer_ffi.so $OUT_DIR
( cd $OUT_DIR; g++ main.cpp -L. -lfilecoin_signer_ffi -o main )
LD_LIBRARY_PATH=$OUT_DIR $OUT_DIR/main
LD_LIBRARY_PATH=$OUT_DIR valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose $OUT_DIR/main