wget https://swift.org/builds/swift-5.2.1-release/ubuntu1804/swift-5.2.1-RELEASE/swift-5.2.1-RELEASE-ubuntu18.04.tar.gz
tar xzf swift-5.2.1-RELEASE-ubuntu18.04.tar.gz
mv swift-5.2.1-RELEASE-ubuntu18.04 ~/.swift

mkdir $OUT_DIR
cp -r ./examples/ffi/swift/* $OUT_DIR
cd $OUT_DIR;
cp /tmp/filecoin_signer_ffi.h .
cp /tmp/libfilecoin_signer_ffi.so .
~/.swift/usr/bin/swiftc -import-objc-header filecoin_signer_ffi.h main.swift libfilecoin_signer_ffi.so -o ./main
LD_LIBRARY_PATH=. ./main
