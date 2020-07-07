# Fuzzing

This crate uses `honggfuzz-rs`, a wrapper around the `Honggfuzz` fuzzer developed by Google.

### Set-up

If you are using Ubuntu, install the following system dependencies:

```
sudo apt install build-essential binutils-dev libunwind-dev libblocksruntime-dev
```

Then the `honggfuzz-rs` CLI application:

```
cargo install honggfuzz
```

### Running

There are two main steps: Fuzzing and Debug. Start fuzzing a desirable target:

```
HFUZZ_RUN_ARGS="--exit_upon_crash" cargo hfuzz run unsigned-message
```

And finally debug the application with the generated input to figure out where the problem is coming from:

```
HFUZZ_DEBUGGER="rust-gdb" cargo hfuzz run-debug unsigned-message hfuzz_workspace/unsigned-message/*.fuzz
```

Take a look at the `honggfuzz-rs` repository for more optional parameters.
