cd signer-ffi
mkdir $OUT_DIR
cp -r ../examples/ffi/java/* $OUT_DIR
cp -r java/* $OUT_DIR
javac -h $OUT_DIR java/src/main/java/ch/zondax/FilecoinSigner.java 
cargo build --features with-jni
cp ../target/debug/libfilecoin_signer_ffi.so $OUT_DIR
javac -d $OUT_DIR $OUT_DIR/src/main/java/ch/zondax/FilecoinSigner.java
javac -cp $OUT_DIR $OUT_DIR/Main.java
( cd $OUT_DIR; java -Djava.library.path="." -ea Main )