wget -O sdk.install.sh "https://get.sdkman.io"
bash sdk.install.sh
export SDKMAN_DIR=/tmp
. /tmp/bin/sdkman-init.sh
sdk install kotlin

mkdir $OUT_DIR
cp -r ./examples/ffi/kotlin/* $OUT_DIR
cp -r ./signer-ffi/java/* $OUT_DIR
cd $OUT_DIR
cp /tmp/filecoin_signer_ffi.h .
cp /tmp/libfilecoin_signer_ffi_java.so ./libfilecoin_signer_ffi.so
javac -d . -h . ./src/main/java/ch/zondax/FilecoinSigner.java 
kotlinc -cp . ./Main.kt -include-runtime -d .
kotlin -Djava.library.path="." -J-ea MainKt