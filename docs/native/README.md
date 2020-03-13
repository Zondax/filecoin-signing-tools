# Native

The Rust package can be located at: [crates.io](https://crates.io/) and documentation at [docs.rs](https://docs.rs)

::: warning filecoin_signer
The library name will probably change in the near future
:::

[[toc]]

## key_generate_mnemonic

Generate a 24 english words mnemonic.

```rust
use signer::key_generate_mnemonic;

let mnemonic = key_generate_mnemonic().unwrap();
println!("{}", mnemonic);
```

## key_derive

...
