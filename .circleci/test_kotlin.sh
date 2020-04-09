wget -O sdk.install.sh "https://get.sdkman.io"
bash sdk.install.sh
. ~/.sdkman/bin/sdkman-init.sh
sdk install kotlin

cd signer-ffi
mkdir $OUT_DIR
cp -r ../examples/ffi/kotlin/* $OUT_DIR
cp -r java/* $OUT_DIR
javac -h $OUT_DIR java/src/main/java/ch/zondax/FilecoinSigner.java 
cargo build --features with-jni
cp ../target/debug/libfilecoin_signer_ffi.so $OUT_DIR
javac -d $OUT_DIR $OUT_DIR/src/main/java/ch/zondax/FilecoinSigner.java
kotlinc -cp $OUT_DIR $OUT_DIR/Main.kt -include-runtime -d $OUT_DIR
( cd $OUT_DIR; kotlin -Djava.library.path="." -J-ea MainKt )