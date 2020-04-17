# Flutter

This example assumes that the `flutter` example and the `signer-ffi/flutter/filecoin` flutter plugin are in the same directory.

# Android example

1. Currently, we don't provide compiled artifacts, so you will have to build the `signer-ffi` crate specifying the desired target using the NDK:

```bash
cargo build --target aarch64-linux-android
```

2. Copy and paste the resulting library into the jniLib directory of the `filecoin` plugin. For example, the standard directory for ARMv8 targets is `android/src/jniLibs/arm64-v8a`:

```bash
cp `$GENERATED_LIB_DIR/libfilecoin_signer_ffi.so` `$EXAMPLE_DIR/android/src/jniLibs/arm64-v8a`
```

3. Run the example using the SDK:

```bash
flutter run
```
