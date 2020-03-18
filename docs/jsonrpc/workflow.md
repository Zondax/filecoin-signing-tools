# Typical workflows

<!---
Reference for mermaid
https://mermaid-js.github.io/mermaid/#/sequenceDiagram
-->


## Address Generation

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

## Sending transaction

<mermaid>
sequenceDiagram
    User->>+Exchange: filecoin_address
    Exchange-->>+Service: sign_transaction(tx, prvkey)
    Service-->>-Exchange: signed_message
    Exchange-->>+Service: send_signed_tx(signed_message)
    Service-->>-Node: broadcast signed transaction
    Node-->>+Service: cid_message
    Service-->>+Exchange: cid_message
    Exchange->>User: cid_message
</mermaid>

::: tip
A message in filecoin is also a transaction.
:::
