mkdir $OUT_DIR
cp -r ./examples/ffi/java/* $OUT_DIR
cp -r ./signer-ffi/java/* $OUT_DIR
cd $OUT_DIR
cp /tmp/filecoin_signer_ffi.h .
cp /tmp/libfilecoin_signer_ffi_java.so ./libfilecoin_signer_ffi.so
javac -d . -h . ./src/main/java/ch/zondax/FilecoinSigner.java 
javac -cp . ./Main.java
java -Djava.library.path="." -ea Main