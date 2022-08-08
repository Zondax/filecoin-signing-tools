# Flutter

This example assumes that the `flutter` example and the `signer-ffi/flutter/filecoin` flutter plugin are in the same
directory.

## Android example

1. Currently, we don't provide compiled artifacts, so you will have to build the `signer-ffi` crate specifying the
   desired target using the NDK:

```bash
cargo build --target aarch64-linux-android
```

2. Copy and paste the resulting library into the jniLib directory of the `filecoin` plugin. For example, the standard
   directory for ARMv8 targets is `android/src/jniLibs/arm64-v8a`:

```bash
cp `$GENERATED_LIB_DIR/libfilecoin_signer_ffi.so` `$EXAMPLE_DIR/android/src/jniLibs/arm64-v8a`
```

3. Run the example using the SDK:

```bash
flutter run
```

## Troubleshooting

## Lots of error when running `cargo build --target aarch64-linux-android`.

This should fix it.
```
$ rustup target add aarch64-linux-android
```

### Is `aarch64-linux-android-clang` installed?

Error:
```
  error occurred: Failed to find tool. Is `aarch64-linux-android-clang` installed?
```

Install android and NDK (follow this https://mozilla.github.io/firefox-browser-architecture/experiments/2017-09-21-rust-on-android.html).

```
$ export ANDROID_HOME=/home/$USER/Android/Sdk
$ export NDK_HOME=$ANDROID_HOME/ndk/25.0.8775105/
```

```
$ CC_aarch64_linux_android=/home/lola/Workspace/Zondax/filecoin-signing-tools/signer-ffi/NDK/arm64/bin/aarch64-linux-android-clang AR_aarch64_linux_android=/home/lola/Workspace/Zondax/filecoin-signing-tools/signer-ffi/NDK/arm64/bin/aarch64-linux-android-ar cargo build --target aarch64-linux-android
```


### could not compile `fil_actor_miner` due to previous error

After running `cargo build --target x86_64-linux-android`

```
error: linking with `cc` failed: exit status: 1
  |
  = note: "cc" "-Wl,--version-script=/tmp/rustct7t2AL/list" "-m64" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/fil_actor_miner-5b88b11f61fbfd8f.fil_actor_miner.3da75037-cgu.0.rcgu.o" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/fil_actor_miner-5b88b11f61fbfd8f.fil_actor_miner.3da75037-cgu.1.rcgu.o" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/fil_actor_miner-5b88b11f61fbfd8f.fil_actor_miner.3da75037-cgu.10.rcgu.o" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/fil_actor_miner-5b88b11f61fbfd8f.fil_actor_miner.3da75037-cgu.11.rcgu.o" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/fil_actor_miner-5b88b11f61fbfd8f.fil_actor_miner.3da75037-cgu.12.rcgu.o" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/fil_actor_miner-5b88b11f61fbfd8f.fil_actor_miner.3da75037-cgu.13.rcgu.o" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/fil_actor_miner-5b88b11f61fbfd8f.fil_actor_miner.3da75037-cgu.14.rcgu.o" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/fil_actor_miner-5b88b11f61fbfd8f.fil_actor_miner.3da75037-cgu.15.rcgu.o" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/fil_actor_miner-5b88b11f61fbfd8f.fil_actor_miner.3da75037-cgu.2.rcgu.o" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/fil_actor_miner-5b88b11f61fbfd8f.fil_actor_miner.3da75037-cgu.3.rcgu.o" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/fil_actor_miner-5b88b11f61fbfd8f.fil_actor_miner.3da75037-cgu.4.rcgu.o" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/fil_actor_miner-5b88b11f61fbfd8f.fil_actor_miner.3da75037-cgu.5.rcgu.o" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/fil_actor_miner-5b88b11f61fbfd8f.fil_actor_miner.3da75037-cgu.6.rcgu.o" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/fil_actor_miner-5b88b11f61fbfd8f.fil_actor_miner.3da75037-cgu.7.rcgu.o" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/fil_actor_miner-5b88b11f61fbfd8f.fil_actor_miner.3da75037-cgu.8.rcgu.o" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/fil_actor_miner-5b88b11f61fbfd8f.fil_actor_miner.3da75037-cgu.9.rcgu.o" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/fil_actor_miner-5b88b11f61fbfd8f.2imhcfsn8vfrbl73.rcgu.o" "-Wl,--as-needed" "-L" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps" "-L" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/debug/deps" "-L" "/home/lola/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-linux-android/lib" "-Wl,-Bstatic" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libfil_actors_runtime-026ebb39a54a9e84.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libfvm_sdk-308711e44627565c.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/liblog-a6575baf39713108.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libfvm_ipld_hamt-2a13a28b470aa28a.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/liblibipld_core-1e202d689d4e528e.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libforest_hash_utils-03fc45320cd510a3.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libfvm_ipld_amt-61d065750fd78657.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libahash-85b8d972b50b1a27.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libgetrandom-3d36ffba9b43becf.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/liblibc-5236982874b99843.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libonce_cell-fad4a24e4a96ca38.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libitertools-b1128c0b50716b82.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libeither-9a656947b232b3c7.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libfvm_shared-a49c8422ad921c08.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libfvm_ipld_encoding-6d484d8bb9827f92.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libserde_ipld_dagcbor-8f8b57a63069eeaf.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libhalf-c252177bb1fa514e.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libbimap-7c7348bf3705b520.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libnum_bigint-4ea3eb34290ba9b7.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libnum_integer-f674cb3c2d6f0cdd.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libnum_traits-c6828301b79563e7.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/liblazy_static-7fed5edb6411ef54.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libbyteorder-2bb827939d78900e.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libfvm_ipld_bitfield-3fa1c5a12b18b564.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libfvm_ipld_encoding-9f52c5483080a110.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libserde_tuple-ca2b3665f543afa8.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libserde_ipld_dagcbor-0576a9c5ce5b9988.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libscopeguard-8484d751df44c7b0.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libcbor4ii-7fc25760f1bca209.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libfvm_ipld_blockstore-3c4c43589b3e1cb1.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libcid-c9a2aac7a35f9552.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libserde_bytes-1676757c40ccde84.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libmultihash-1f262412732f2e41.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libsha3-5cfc038908ab71df.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libkeccak-84c7b3267f7ece43.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libsha2-a6265b9ad4307ee4.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libcpufeatures-c056d04aef8051af.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libblake3-9346de4a25392784.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libcfg_if-5793e77332b075b3.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libblake2s_simd-f410d7ba74b2e33c.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libblake2b_simd-434f0f2695753957.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libconstant_time_eq-1214e65a0b1660b6.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libarrayvec-e8fca62c54b05f18.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libarrayref-2a29db2967dd8913.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libdigest-03c1d9b950eab612.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libblock_buffer-8d8aad4c0d8fda2e.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libcrypto_common-25eafbc631072980.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libgeneric_array-e52c4087bb6eee0b.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libtypenum-c333a3f3d4319768.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libserde_big_array-2bc6f6f18960ebe6.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libunsigned_varint-b89bbc7a4ab84343.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libmultibase-a29daa215a1ca2b1.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libbase_x-3aef9f64dd859f86.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libdata_encoding_macro-b8c50dc0b0e4075e.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libdata_encoding-27b13958cf31c7cd.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libcs_serde_bytes-71a61f649d7f0745.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libserde-5aff81ec215411dc.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libthiserror-cd4d595995a2ee95.rlib" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libanyhow-f4c95afa858c6df7.rlib" "-Wl,--start-group" "/home/lola/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-linux-android/lib/libstd-e4af387e2a98768b.rlib" "/home/lola/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-linux-android/lib/libpanic_unwind-24bdf460637be679.rlib" "/home/lola/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-linux-android/lib/libobject-2de8ba4a868048b2.rlib" "/home/lola/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-linux-android/lib/libmemchr-63105309a700bf7d.rlib" "/home/lola/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-linux-android/lib/libaddr2line-9e478a7ccab284a0.rlib" "/home/lola/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-linux-android/lib/libgimli-49a1dd07a01df6bd.rlib" "/home/lola/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-linux-android/lib/librustc_demangle-dac673123078f744.rlib" "/home/lola/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-linux-android/lib/libstd_detect-81c107266c23cfb5.rlib" "/home/lola/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-linux-android/lib/libhashbrown-54b66d64a7b4fd79.rlib" "/home/lola/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-linux-android/lib/libminiz_oxide-234999ba27f1ff86.rlib" "/home/lola/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-linux-android/lib/libadler-d4ceff29f5b21cd6.rlib" "/home/lola/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-linux-android/lib/librustc_std_workspace_alloc-bf25bc611d14661d.rlib" "/home/lola/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-linux-android/lib/libunwind-bb47424296d71308.rlib" "/home/lola/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-linux-android/lib/libcfg_if-ae57011a52451f96.rlib" "/home/lola/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-linux-android/lib/liblibc-4d407d153bab6d77.rlib" "/home/lola/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-linux-android/lib/liballoc-95f4d5daad7e5f59.rlib" "/home/lola/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-linux-android/lib/librustc_std_workspace_core-46ccb41368285b0a.rlib" "/home/lola/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-linux-android/lib/libcore-f942279edcbb15a2.rlib" "-Wl,--end-group" "/home/lola/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-linux-android/lib/libcompiler_builtins-ffa56b3f89ee2e2f.rlib" "-Wl,-Bdynamic" "-ldl" "-llog" "-lgcc" "-ldl" "-lc" "-lm" "-Wl,--eh-frame-hdr" "-Wl,-znoexecstack" "-L" "/home/lola/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-linux-android/lib" "-o" "/home/lola/Workspace/Zondax/filecoin-signing-tools/target/x86_64-linux-android/debug/deps/libfil_actor_miner-5b88b11f61fbfd8f.so" "-Wl,--gc-sections" "-shared" "-Wl,-zrelro,-znow" "-nodefaultlibs"
  = note: /usr/bin/ld: cannot find -llog
          collect2: error: ld returned 1 exit status
          

error: could not compile `fil_actor_miner` due to previous error
```

Install
```
$ apt install libgcc-10-dev 
```

And need a `build.rs` file in the `builtin_actors` repo under the `miner` actor.
```
fn main() {
    let target = env::var("TARGET").unwrap();
    if target == "x86_64-linux-android" {
        // Tell cargo to look for shared libraries in the specified directory
        println!("cargo:rustc-link-search=/usr/lib/x86_64-linux-gnu/android/");
    }
}
```