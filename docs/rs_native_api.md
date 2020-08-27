# API

Documentation for the rust api.

## key_generate_mnemonic

Generate a 24 english words mnemonic.

```rust
use signer::key_generate_mnemonic;

let mnemonic = key_generate_mnemonic().unwrap();
println!("{}", mnemonic);
```

## key_derive

Derive a child key from a mnemonic following a [BIP44 path](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki).

Arguments :
* **mnemonic**: a string containing the words;
* **path**: a BIP44 path;
* **password**: for encrypted seed if none use an empty string (e.g "")

```rust
use signer::key_derive;
use bip39::{Mnemonic, MnemonicType, Language};

let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
let path = "m/44'/461'/0/0/1";

let extended_key = key_derive(mnemonic.phrase(), path, "").unwrap();

println!("{:?}", extended_key);
```

## key_derive_from_seed

Derive a child key from a seed following a [BIP44 path](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki).

Arguments :
* **seed**: a seed;
* **path**: a BIP44 path;

```rust
use signer::key_derive_from_seed;
use bip39::{Mnemonic, MnemonicType, Language, Seed};

let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
let path = "m/44'/461'/0/0/1".to_string();

let mnemonic = Mnemonic::from_phrase(&mnemonic.0, Language::English).unwrap();

let seed = Seed::new(&mnemonic, "");

let extended_key = key_derive_from_seed(seed.as_bytes(), path).unwrap();

println!("{:?}", extended_key);
```

## key_recover

Get extended private key from private key.

Arguments:
* **PrivateKey**: A `PrivateKey`.
* **testnet**: A boolean value that indicate if testnet (`true`) or mainnet (`false`);

```rust
use signer::{key_recover, PrivateKey};

let private_key = PrivateKey::try_from("8VcW07ADswS4BV2cxi5rnIadVsyTDDhY1NfDH19T8Uo=").unwrap();

let extended_key = key_recover(private_key, true).unwrap();

println!("{:?}", extended_key);
```

## transaction_serialize

Serialize a transaction and return the CBOR equivalent.

Arguments :
* **transaction**: a filecoin transaction;

```rust
use signer::transaction_serialize;
use signer::api::UnsignedMessageAPI;

const transaction: &str = r#"
    {
        "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
        "from": "t1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka",
        "nonce": 1,
        "value": "100000",
        "gasprice": "2500",
        "gaslimit": 25000,
        "method": 0,
        "params": ""
    }"#;

let message_user_api: UnsignedMessageAPI = serde_json::from_str(transaction).unwrap();

let cbor_transaction = transaction_serialize(message_user_api).unwrap();

println!("{:?}", cbor_transaction);
```

## transaction_parse

Parse a CBOR transaction into a filecoin transaction (signed or unsigned).

Arguments:
* **cbor_data**: the CBOR transaction;
* **testnet**: boolean value `true` if testnet or `false` for mainnet;

```rust
use signer::{transaction_parse, CborBuffer};
use signer::api::MessageTxAPI;


let cbor_data = CborBuffer(hex::decode("885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855010f323f4709e8e4db0c1d4cd374f9f35201d26fb20144000186a0430009c41961a80040").unwrap());


let transaction = transaction_parse(&cbor_data, true).unwrap();

match transaction {
        MessageTxAPI::UnsignedMessageAPI(unsigned_tx) => println!("To address in unsigned message : {}", unsigned_tx.to.to_string()),
        MessageTxAPI::SignedMessageAPI(signed_tx) => println!("To address in signed message : {}", signed_tx.message.to.to_string()),
    }
```

## transaction\_sign\_raw

Sign a transaction and return a raw signature. Now support `Secp256k1` signing (RSV format) and `BLS` signing. The type of signature chosen will be dictated by the protocol of the `from` field of the transaction.

e.g :

* "t**1**b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka" is a [protocol 1 address](https://filecoin-project.github.io/specs/#protocol-1-libsecpk1-elliptic-curve-public-keys) therefore `transaction_sign_raw` will attempt to the sign the transaction using `Secp256k1`.

* "t**3**vxrizeiel2e2bxg3jhk62dlcutyc26fjnw6ua2sptu32dtjpwxbjawg666nqdngrkvvn45h7yb4qiya6ls7q" is a [protocol 3 address](https://filecoin-project.github.io/specs/#protocol-3-bls). Here we will use `BLS` signing scheme.

Arguments:
* **transaction**: a filecoin transaction;
* **privatekey**: a`PrivateKey` (should be the associated private key of `from` address of the transaction);

```rust
use signer::{transaction_sign_raw, PrivateKey};
use signer::api::UnsignedMessageAPI;

const transaction: &str = r#"
    {
        "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
        "from": "t1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka",
        "nonce": 1,
        "value": "100000",
        "gasprice": "2500",
        "gaslimit": 25000,
        "method": 0,
        "params": ""
    }"#;

let message_user_api: UnsignedMessageAPI = serde_json::from_str(transaction).unwrap();

let private_key = PrivateKey::try_from("8VcW07ADswS4BV2cxi5rnIadVsyTDDhY1NfDH19T8Uo=").unwrap();

let raw_signature = transaction_sign_raw(&message_user_api, &private_key).unwrap();

println!("{:?}", raw_signature);
```

## transaction_sign

Sign a transaction and return a signed message (message + signature). Now support `Secp256k1` signing (RSV format) and `BLS` signing. The type of signature chosen will be dictated by the protocol of the `from` field of the transaction.

e.g :

* "t**1**b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka" is a [protocol 1 address](https://filecoin-project.github.io/specs/#protocol-1-libsecpk1-elliptic-curve-public-keys) therefore `transaction_sign_raw` will attempt to the sign the transaction using `Secp256k1`.

* "t**3**vxrizeiel2e2bxg3jhk62dlcutyc26fjnw6ua2sptu32dtjpwxbjawg666nqdngrkvvn45h7yb4qiya6ls7q" is a [protocol 3 address](https://filecoin-project.github.io/specs/#protocol-3-bls). Here we will use `BLS` signing scheme.

```rust
pub struct SignedMessageAPI {
    pub message: UnsignedMessageAPI,
    pub signature: SignatureAPI,
}
```

Arguments:
* **transaction**: a filecoin transaction;
* **privatekey**: a `PrivateKey` (should match the address of the `from` field);

```rust
use signer::{transaction_sign, PrivateKey};
use signer::api::UnsignedMessageAPI;

const transaction: &str = r#"
    {
        "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
        "from": "t1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka",
        "nonce": 1,
        "value": "100000",
        "gasprice": "2500",
        "gaslimit": 25000,
        "method": 0,
        "params": ""
    }"#;

let message_user_api: UnsignedMessageAPI = serde_json::from_str(transaction).unwrap();

let private_key = PrivateKey::try_from("8VcW07ADswS4BV2cxi5rnIadVsyTDDhY1NfDH19T8Uo=").unwrap();

let raw_signature = transaction_sign(&message_user_api, &private_key).unwrap();

println!("{:?}", raw_signature);
```

## verify_signature

Verify a signature. Return a boolean. Now support `Secp256k1` and `BLS` scheme.

Arguments :
* **signature**: RSV format signature;
* **CBOR transaction**: the CBOR transaction;

```rust
use signer::{transaction_sign_raw, verify_signature};

let cbor_data = CborBuffer(hex::decode("885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855010f323f4709e8e4db0c1d4cd374f9f35201d26fb20144000186a0430009c41961a80040").unwrap());

let private_key = PrivateKey::try_from("8VcW07ADswS4BV2cxi5rnIadVsyTDDhY1NfDH19T8Uo=".to_string()).unwrap();

const transaction: &str = r#"
    {
        "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
        "from": "t1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka",
        "nonce": 1,
        "value": "100000",
        "gasprice": "2500",
        "gaslimit": 25000,
        "method": 0,
        "params": ""
    }"#;

let message_user_api: UnsignedMessageAPI =
    serde_json::from_str(transaction).unwrap();

let mut signature = transaction_sign_raw(&message_user_api, &private_key).unwrap();

let result = verify_signature(&signature, &cbor_data).unwrap()

println!("{}", result);
```

## create_multisig

Utilitary function to create a create multisig message. Return an unsigned message.

Arguments:
* **sender_address**: A string address;
* **addresses**: List of string addresses of the multisig;
* **value**: Value to send on the multisig;
* **required**: Number of required signatures required;
* **nonce**: Nonce of the message;
* **duration**: Duration of the multisig;

```rust
use signer::create_multisig;

let result = create_multisig(
    "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba".to_string(),
    vec![
        "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba".to_string(),
        "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy".to_string(),
    ],
    "1000".to_string(),
    1,
    1,
    0,
)
.unwrap();

println!("{}", result);

```

## proposal_multisig_message

Utilitary function to create a proposal multisig message. Return an unsigned message.

Arguments:
* **multisig_address**: A string address;
* **to_address**: A string address;
* **from_address**: A string address;
* **amount**: Amount of the transaction;
* **nonce**: Nonce of the message;

```rust
use signer::proposal_multisig_message;

let result = proposal_multisig_message(
    "t01".to_string(),
    "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy".to_string(),
    "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba".to_string(),
    "1000".to_string(),
    1,
)
.unwrap();

println!("{}", result);

```

## approve_multisig_message

Utilitary function to create an approve multisig message. Return an unsigned message.

Arguments
* **multisig_address**: A string address
* **message_id**: message id
* **proposer_address**: A string address
* **to_address**: A string address
* **amount**: Amount of the transaction
* **from_address**: A string address
* **nonce**: Nonce of the message

```rust
use signer::approve_multisig_message;

let result = approve_multisig_message(
    "t01".to_string(),
    1234,
    "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba".to_string(),
    "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy".to_string(),
    "1000".to_string(),
    "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba".to_string(),
    1,
)
.unwrap();

println!("{}", result);

```

## cancel_multisig_message

Utilitary function to create a cancel multisig message. Return an unsigned message.

Arguments
* **multisig_address**: A string address
* **message_id**: message id
* **proposer_address**: A string address
* **to_address**: A string address
* **amount**: Amount of the transaction
* **from_address**: A string address
* **nonce**: Nonce of the message

```rust
use signer::cancel_multisig_message;

let result = cancel_multisig_message(
    "t01".to_string(),
    1234,
    "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba".to_string(),
    "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy".to_string(),
    "1000".to_string(),
    "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba".to_string(),
    1,
)
.unwrap();

println!("{}", result);

```

## verify\_aggregated\_signature

Verify BLS aggragated signature.

Arguments :
* **signature**: BLS aggregated signature;
* **CBOR transactions**: An array of CBOR transactions to verify;

```rust
// sign 3 messages
let num_messages = 3;

let mut rng = ChaCha8Rng::seed_from_u64(12);

// generate private keys
let private_keys: Vec<_> = (0..num_messages)
    .map(|_| bls_signatures::PrivateKey::generate(&mut rng))
    .collect();

// generate messages
let messages: Vec<UnsignedMessageAPI> = (0..num_messages)
    .map(|i| {
        //Prepare transaction
        let bls_public_key = private_keys[i].public_key();
        let bls_address = Address::new_bls(&bls_public_key.as_bytes()).unwrap();

        UnsignedMessageAPI {
            to: "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy".to_string(),
            from: bls_address.to_string(),
            nonce: 1,
            value: "100000".to_string(),
            gas_price: "2500".to_string(),
            gas_limit: 25000,
            method: 0,
            params: "".to_string(),
        }
    })
    .collect();

// sign messages
let sigs: Vec<bls_signatures::Signature>;
sigs = messages
    .par_iter()
    .zip(private_keys.par_iter())
    .map(|(message, pk)| {
        let private_key = PrivateKey::try_from(pk.as_bytes()).unwrap();
        let raw_sig = transaction_sign_bls_raw(message, &private_key).unwrap();

        bls_signatures::Serialize::from_bytes(&raw_sig.0).unwrap()
    })
    .collect::<Vec<bls_signatures::Signature>>();

// serialize messages
let cbor_messages: Vec<CborBuffer>;
cbor_messages = messages
    .par_iter()
    .map(|message| transaction_serialize(message).unwrap())
    .collect::<Vec<CborBuffer>>();

let aggregated_signature = bls_signatures::aggregate(&sigs).unwrap();

let sig = SignatureBLS::try_from(aggregated_signature.as_bytes()).unwrap();

assert!(verify_aggregated_signature(&sig, &cbor_messages[..]).unwrap());
```
