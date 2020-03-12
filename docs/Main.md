# Signing Library

## Native

The Rust package can be located at: [crates.io](https://crates.io/) and documentation at [docs.rs](https://docs.rs)

::: warning filecoin_signer
The library name will probably change in the near future
:::

```
key_generate_mnemonic()
key_derive(mnemonic, path)
transaction_serialize(unsigned_message: UnsignedMessageUserAPI) ->
```

## WASM

::: warning fcawasmsigner
The library name will probably change in the near future
:::


## JSONRPC Service

### Typical workflows

<!---
Reference for mermaid
https://mermaid-js.github.io/mermaid/#/sequenceDiagram
-->


#### Address Generation

<mermaid>
sequenceDiagram
    rect rgb(0, 255, 0, .1)
        User->>+Exchange: Deposit Request
        Exchange-->>+Service: key_generate()
        Service-->>-Exchange: mnemonic
        Exchange-->>+Service: key_derive(mnemonic, path)
        Service-->>-Exchange: public_key, private_key address
        Exchange->>+User: Address
    end
    % This is not covered
    Note over Exchange,Node: This is not covered
    Exchange->>+Node: Monitor Address
    Node-->>-Exchange: change event
    Exchange->>+Node: Get_balance(address)
    Node-->>-Exchange: balance  
</mermaid>

#### Signing

<mermaid>
sequenceDiagram
    Note over Exchange,Node: COMPLETE
</mermaid>

::: danger Old diagrams
Work in progress
:::

```asciidoc
    /-----------/           /--------------/        /---------/
    /   USER    /           /   EXCHANGE   /        /  NODE   /
    /-----------/           /--------------/        /---------/
          |                        |                     |
          |------Sell Request----->|                     |
          |                        | key_derive()        |
          |<-----Address-----------|                     |
          |                        |                     |
          |------------------Send Transaction----------->|
          |                        |                     |
          |                        |<-----Notify---------|
          |                        |                     |
          |<------Success----------|                     |

    /-----------/           /--------------/        /---------/
    /   USER    /           /   EXCHANGE   /        /  NODE   /
    /-----------/           /--------------/        /---------/
          |                        |                     |
          |------Buy (address)---->|                     |
          |                        | key_derive()        |
          |                        | tx_create()         |
          |                        | sign_transaction()  |
          |                        |                     |
          |                        |-----Sentd Tx ------>|
          |                        |                     |
          |                        |                     |
          |                        |<-----Notify---------|
          |                        |                     |
          |<------Success----------|                     |

```

## Examples

```js
func myTest() {
    return 42;
}
```
