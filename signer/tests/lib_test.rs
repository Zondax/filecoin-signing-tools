use std::convert::TryFrom;
use std::str::FromStr;

use bip39::{Language, Seed};
use bls_signatures::Serialize;
use fvm_ipld_encoding::{to_vec, Cbor, RawBytes};
use fvm_shared::bigint::BigInt;
use fvm_shared::message::Message;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rayon::prelude::*;

use cid::multihash::MultihashDigest;
use fil_actor_multisig as multisig;
use filecoin_signer::api::{MessageParams, MessageTxAPI};
use filecoin_signer::*;
use fvm_ipld_encoding::DAG_CBOR;
use fvm_shared::address::Address;
use fvm_shared::address::Network;
use fvm_shared::address::{current_network, set_current_network};
use fvm_shared::crypto::signature::Signature;
use fvm_shared::econ::TokenAmount;

mod common;

const SIGNED_MESSAGE_CBOR: &str =
    "828a005501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855011eaf1c8a4bbfeeb0870b1745b1f57503470b71160144000186a01909c4420001420001004058420106398485060ca2a4deb97027f518f45569360c3873a4303926fa6909a7299d4c55883463120836358ff3396882ee0dc2cf15961bd495cdfb3de1ee2e8bd3768e01";

#[test]
fn decode_key() {
    let test_value = common::load_test_vectors("../test_vectors/wallet.json").unwrap();
    let private_key = test_value["private_key"].as_str().unwrap();

    let pk = PrivateKey::try_from(private_key.to_string()).unwrap();
    assert_eq!(base64::encode(&pk.0), private_key.to_string());
}

#[test]
fn generate_mnemonic() {
    let mnemonic = key_generate_mnemonic().expect("could not generate mnemonic");
    println!("{}", mnemonic.0);

    let word_count = mnemonic.0.split_ascii_whitespace().count();
    assert_eq!(word_count, 24)
}

#[test]
fn derive_key() {
    let test_value = common::load_test_vectors("../test_vectors/wallet.json").unwrap();
    let mnemonic = test_value["mnemonic"].as_str().unwrap();
    let private_key = test_value["private_key"].as_str().unwrap();
    let language_code = test_value["language_code"].as_str().unwrap();

    let extended_key = key_derive(mnemonic, "m/44'/461'/0/0/0", "", language_code).unwrap();

    assert_eq!(
        base64::encode(&extended_key.private_key.0),
        private_key.to_string()
    );
}

#[test]
fn derive_key_password() {
    let test_value = common::load_test_vectors("../test_vectors/wallet.json").unwrap();
    let mnemonic = test_value["mnemonic"].as_str().unwrap();
    let password = "password".to_string();
    let path = "m/44'/461'/0/0/0".to_string();
    let language_code = test_value["language_code"].as_str().unwrap();

    let m = bip39::Mnemonic::from_phrase(mnemonic, Language::English).unwrap();

    let seed = Seed::new(&m, &password);

    let extended_key_expected = key_derive_from_seed(seed.as_bytes(), &path).unwrap();

    let extended_key = key_derive(mnemonic, &path, &password, language_code).unwrap();

    assert_eq!(
        base64::encode(&extended_key.private_key.0),
        base64::encode(&extended_key_expected.private_key.0)
    );
}

#[test]
fn derive_key_from_seed() {
    let test_value = common::load_test_vectors("../test_vectors/wallet.json").unwrap();
    let mnemonic = Mnemonic(test_value["mnemonic"].as_str().unwrap().to_string());
    let private_key = test_value["private_key"].as_str().unwrap();

    let mnemonic = bip39::Mnemonic::from_phrase(&mnemonic.0, Language::English).unwrap();

    let seed = Seed::new(&mnemonic, "");

    let extended_key = key_derive_from_seed(seed.as_bytes(), "m/44'/461'/0/0/0").unwrap();

    assert_eq!(
        base64::encode(&extended_key.private_key.0),
        private_key.to_string()
    );
}

#[test]
fn test_key_recover_testnet() {
    let test_value = common::load_test_vectors("../test_vectors/wallet.json").unwrap();
    let private_key = test_value["private_key"].as_str().unwrap();

    let pk = PrivateKey::try_from(private_key.to_string()).unwrap();
    let testnet = true;

    let recovered_key = key_recover(&pk, testnet).unwrap();

    assert_eq!(
        base64::encode(&recovered_key.private_key.0),
        private_key.to_string()
    );

    assert_eq!(
        &recovered_key.address,
        "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"
    );
}

#[test]
fn test_key_recover_mainnet() {
    let test_value = common::load_test_vectors("../test_vectors/wallet.json").unwrap();
    let private_key = test_value["private_key"].as_str().unwrap();
    let address = test_value["childs"][3]["address"].as_str().unwrap();

    let pk = PrivateKey::try_from(private_key.to_string()).unwrap();
    let testnet = false;

    let recovered_key = key_recover(&pk, testnet).unwrap();

    assert_eq!(
        base64::encode(&recovered_key.private_key.0),
        private_key.to_string()
    );

    assert_eq!(&recovered_key.address, &address);
}

#[test]
fn parse_unsigned_transaction() {
    let test_value = common::load_test_vectors("../test_vectors/txs.json").unwrap();
    let cbor = test_value[0]["cbor"].as_str().unwrap();

    let to_expected = Network::Testnet
        .parse_address(test_value[0]["transaction"]["To"].as_str().unwrap())
        .unwrap();

    let cbor_data = hex::decode(&cbor).unwrap();

    let unsigned_tx = transaction_parse(&cbor_data, true).expect("FIX ME");
    let to = match unsigned_tx {
        MessageTxAPI::Message(tx) => tx.to,
        MessageTxAPI::SignedMessage(_) => panic!("Should be a Unsigned Message!"),
    };

    assert_eq!(to, to_expected);
}

#[test]
fn parse_signed_transaction() {
    // TODO: new test vector
    let cbor_data = hex::decode(SIGNED_MESSAGE_CBOR).unwrap();

    let signed_tx = transaction_parse(&cbor_data, true).expect("Could not parse");
    let signature = match signed_tx {
        MessageTxAPI::Message(_) => panic!("Should be a Signed Message!"),
        MessageTxAPI::SignedMessage(tx) => tx.signature,
    };

    assert_eq!(
        hex::encode(&signature.bytes),
        "06398485060ca2a4deb97027f518f45569360c3873a4303926fa6909a7299d4c55883463120836358ff3396882ee0dc2cf15961bd495cdfb3de1ee2e8bd3768e01".to_string()
    );
}

#[test]
fn parse_transaction_with_network() {
    let test_value = common::load_test_vectors("../test_vectors/txs.json").unwrap();
    let tc = test_value[1].to_owned();
    let cbor = tc["cbor"].as_str().unwrap();
    let testnet = tc["testnet"].as_bool().unwrap();

    let mut to_expected: Address;
    let mut from_expected: Address;

    if testnet {
        to_expected = Network::Testnet
            .parse_address(tc["transaction"]["To"].as_str().unwrap())
            .unwrap();
        from_expected = Network::Testnet
            .parse_address(tc["transaction"]["From"].as_str().unwrap())
            .unwrap();
    } else {
        to_expected = Network::Mainnet
            .parse_address(tc["transaction"]["To"].as_str().unwrap())
            .unwrap();
        from_expected = Network::Mainnet
            .parse_address(tc["transaction"]["From"].as_str().unwrap())
            .unwrap();
    }

    let cbor_data = RawBytes::new(hex::decode(&cbor).unwrap());

    let unsigned_tx_mainnet = transaction_parse(&cbor_data, testnet).expect("Could not parse");
    let (to, from) = match unsigned_tx_mainnet {
        MessageTxAPI::Message(tx) => (tx.to, tx.from),
        MessageTxAPI::SignedMessage(_) => panic!("Should be a Unsigned Message!"),
    };

    assert_eq!(to, to_expected);
    assert_eq!(from, from_expected);
}

#[test]
fn parse_transaction_with_network_testnet() {
    let test_value = common::load_test_vectors("../test_vectors/txs.json").unwrap();
    let tc = test_value[0].to_owned();
    let cbor = tc["cbor"].as_str().unwrap();
    let testnet = tc["testnet"].as_bool().unwrap();

    let mut to_expected: Address;
    let mut from_expected: Address;

    if testnet {
        to_expected = Network::Testnet
            .parse_address(tc["transaction"]["To"].as_str().unwrap())
            .unwrap();
        from_expected = Network::Testnet
            .parse_address(tc["transaction"]["From"].as_str().unwrap())
            .unwrap();
    } else {
        to_expected = Network::Mainnet
            .parse_address(tc["transaction"]["To"].as_str().unwrap())
            .unwrap();
        from_expected = Network::Mainnet
            .parse_address(tc["transaction"]["From"].as_str().unwrap())
            .unwrap();
    }

    let cbor_data = RawBytes::new(hex::decode(&cbor).unwrap());

    let unsigned_tx_testnet = transaction_parse(&cbor_data, testnet).expect("Could not parse");
    let (to, from) = match unsigned_tx_testnet {
        MessageTxAPI::Message(tx) => (tx.to, tx.from),
        MessageTxAPI::SignedMessage(_) => panic!("Should be a Message!"),
    };

    assert_eq!(to, to_expected);
    assert_eq!(from, from_expected);
}

#[test]
fn parse_transaction_signed_with_network() {
    // TODO: test vector for signed message
    let cbor_data = RawBytes::new(hex::decode(SIGNED_MESSAGE_CBOR).unwrap());

    let signed_tx_mainnet = transaction_parse(&cbor_data, false).expect("Could not parse");
    let (to, from) = match signed_tx_mainnet {
        MessageTxAPI::Message(_) => panic!("Should be a Signed Message!"),
        MessageTxAPI::SignedMessage(tx) => (tx.message.to, tx.message.from),
    };

    assert_eq!(
        to,
        Network::Mainnet
            .parse_address("f17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy")
            .unwrap()
    );
    assert_eq!(
        from,
        Network::Mainnet
            .parse_address("f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba")
            .unwrap()
    );
}

#[test]
fn parse_transaction_signed_with_network_testnet() {
    // TODO: test vector for signed message
    let cbor_data = RawBytes::new(hex::decode(SIGNED_MESSAGE_CBOR).unwrap());

    let signed_tx_testnet = transaction_parse(&cbor_data, true).expect("Could not parse");
    let (to, from) = match signed_tx_testnet {
        MessageTxAPI::Message(_) => panic!("Should be a Signed Message!"),
        MessageTxAPI::SignedMessage(tx) => (tx.message.to, tx.message.from),
    };

    assert_eq!(
        to,
        Network::Testnet
            .parse_address("t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy")
            .unwrap()
    );
    assert_eq!(
        from,
        Network::Testnet
            .parse_address("t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba")
            .unwrap()
    );
}

#[test]
fn verify_invalid_signature() {
    let test_value = common::load_test_vectors("../test_vectors/verify_signature.json").unwrap();
    let private_key = test_value["verify_invalid_signature"]["private_key"]
        .as_str()
        .unwrap();
    let message = test_value["verify_invalid_signature"]["message"].to_owned();

    // Path 44'/461'/0/0/0
    let pk = PrivateKey::try_from(private_key.to_string()).unwrap();
    let message_user_api: MessageTxAPI =
        serde_json::from_value(message).expect("Could not serialize unsigned message");

    // Sign
    let signature = transaction_sign_raw(&message_user_api.get_message(), &pk).unwrap();

    // Verify
    let message_cbor = to_vec(&message_user_api.get_message()).unwrap();

    let valid_signature = verify_signature(&signature, &message_cbor);
    assert!(valid_signature.unwrap());

    // Tampered signature and look if it valid
    let mut sig = signature.bytes;
    sig[5] = 0x01;
    sig[34] = 0x00;

    let tampered_signature = Signature::new_secp256k1(sig);

    let valid_signature = verify_signature(&tampered_signature, &message_cbor);
    assert!(valid_signature.is_err() || !valid_signature.unwrap());
}

#[test]
fn sign_bls_transaction() {
    let test_value = common::load_test_vectors("../test_vectors/bls_wallet.json").unwrap();

    // Get address
    let bls_pubkey = hex::decode(test_value["bls_public_key"].as_str().unwrap()).unwrap();
    let bls_address = Address::new_bls(bls_pubkey.as_slice()).unwrap();

    // Get BLS private key
    let bls_key =
        PrivateKey::try_from(test_value["bls_private_key"].as_str().unwrap().to_string()).unwrap();

    dbg!(bls_address.to_string());

    // Prepare message with BLS address
    let message = Message {
        version: 0,
        to: Network::Testnet
            .parse_address("t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy")
            .unwrap(),
        from: bls_address,
        sequence: 1,
        value: TokenAmount::from_atto(BigInt::from_str("100000").unwrap()),
        gas_limit: 25000,
        gas_fee_cap: TokenAmount::from_atto(BigInt::from_str("2500").unwrap()),
        gas_premium: TokenAmount::from_atto(BigInt::from_str("2500").unwrap()),
        method_num: 0,
        params: RawBytes::new(vec![]),
    };

    let raw_sig = transaction_sign_raw(&message, &bls_key).unwrap();

    dbg!(hex::encode(raw_sig.bytes()));

    let sig = bls_signatures::Signature::from_bytes(raw_sig.bytes()).expect("FIX ME");

    let bls_pk = bls_signatures::PublicKey::from_bytes(&bls_pubkey).unwrap();

    let message_cbor = to_vec(&message).expect("FIX ME");

    dbg!(hex::encode(&message_cbor));

    let hash = cid::multihash::Code::Blake2b256.digest(&message_cbor);
    let message_cid = cid::Cid::new_v1(DAG_CBOR, hash);

    assert!(bls_pk.verify(sig, &message_cid.to_bytes()));
}

#[test]
fn test_verify_bls_signature() {
    let test_value = common::load_test_vectors("../test_vectors/bls_signature.json").unwrap();

    let sig = Signature::new_bls(hex::decode(test_value["sig"].as_str().unwrap()).unwrap());
    let message = RawBytes::new(hex::decode(test_value["cbor"].as_str().unwrap()).unwrap());

    let result = verify_signature(&sig, &message).unwrap();

    assert!(result);
}

#[test]
fn test_verify_aggregated_signature() {
    // sign 3 messages
    let num_messages = 3;

    let mut rng = ChaCha8Rng::seed_from_u64(12);

    // generate private keys
    let private_keys: Vec<_> = (0..num_messages)
        .map(|_| bls_signatures::PrivateKey::generate(&mut rng))
        .collect();

    // generate messages
    let messages: Vec<Message> = (0..num_messages)
        .map(|i| {
            //Prepare transaction
            let bls_public_key = private_keys[i].public_key();
            let bls_address = Address::new_bls(&bls_public_key.as_bytes()).unwrap();

            Message {
                version: 0,
                to: Network::Testnet
                    .parse_address("t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy")
                    .unwrap(),
                from: bls_address,
                sequence: 1,
                value: TokenAmount::from_atto(BigInt::from_str("100000").unwrap()),
                gas_limit: 25000,
                gas_fee_cap: TokenAmount::from_atto(BigInt::from_str("2500").unwrap()),
                gas_premium: TokenAmount::from_atto(BigInt::from_str("2500").unwrap()),
                method_num: 0,
                params: RawBytes::new(vec![]),
            }
        })
        .collect();

    // sign messages
    let sigs: Vec<bls_signatures::Signature> = messages
        .par_iter()
        .zip(private_keys.par_iter())
        .map(|(message, pk)| {
            let private_key = PrivateKey::try_from(pk.as_bytes()).expect("FIX ME");
            let raw_sig = transaction_sign_raw(message, &private_key).unwrap();

            bls_signatures::Serialize::from_bytes(&raw_sig.bytes).expect("FIX ME")
        })
        .collect::<Vec<bls_signatures::Signature>>();

    // serialize messages
    let cbor_messages: Vec<Vec<u8>> = messages
        .par_iter()
        .map(|message| transaction_serialize(message).unwrap())
        .collect::<Vec<Vec<u8>>>();

    let aggregated_signature = bls_signatures::aggregate(&sigs).expect("FIX ME");

    let sig = Signature::new_bls(aggregated_signature.as_bytes());

    assert!(verify_aggregated_signature(&sig, &cbor_messages[..]).unwrap());
}

#[test]
fn payment_channel_creation_secp256k1_signing() {
    let test_value = common::load_test_vectors("../test_vectors/payment_channel.json").unwrap();
    let tc_creation_secp256k1 = test_value["creation"]["secp256k1"].to_owned();

    let from_key = tc_creation_secp256k1["private_key"]
        .as_str()
        .unwrap()
        .to_string();
    let privkey = PrivateKey::try_from(from_key).unwrap();

    dbg!(&tc_creation_secp256k1["message"].to_owned());

    let pch_create_message_api: MessageTxAPI =
        serde_json::from_value(tc_creation_secp256k1["message"].to_owned())
            .expect("Could not serialize unsigned message");

    let pch_create_message = match pch_create_message_api {
        MessageTxAPI::Message(msg) => msg,
        _ => panic!("Should be a Message"),
    };

    let signed_message_result = transaction_sign(&pch_create_message, &privkey).unwrap();
    // TODO:  how do I check the signature of a transaction_sign() result

    // Check the raw bytes match the test vector cbor
    let _cbor_result_unsigned_msg = transaction_serialize(&signed_message_result.message).unwrap();
}

#[test]
fn test_sign_voucher() {
    let wallet = common::load_test_vectors("../test_vectors/wallet.json").unwrap();
    // TODO: the privatekey should be added to voucher.json to keep test vectors seperated
    let mnemonic = wallet["mnemonic"].as_str().unwrap();
    let language_code = wallet["language_code"].as_str().unwrap();

    let extended_key = key_derive(mnemonic, "m/44'/461'/0/0/0", "", language_code).unwrap();

    let test_value = common::load_test_vectors("../test_vectors/voucher.json").unwrap();
    let voucher_value = test_value["sign"]["voucher"].to_owned();

    let voucher = create_voucher(
        voucher_value["payment_channel_address"]
            .as_str()
            .unwrap()
            .to_string(),
        voucher_value["time_lock_min"].as_i64().unwrap(),
        voucher_value["time_lock_max"].as_i64().unwrap(),
        voucher_value["amount"].as_str().unwrap().to_string(),
        voucher_value["lane"].as_u64().unwrap(),
        voucher_value["nonce"].as_u64().unwrap(),
        voucher_value["min_settle_height"].as_i64().unwrap(),
    )
    .unwrap();

    let signed_voucher = sign_voucher(voucher, &extended_key.private_key).unwrap();

    assert_eq!(
        signed_voucher,
        test_value["sign"]["signed_voucher_base64"]
            .as_str()
            .unwrap()
    );
}

#[test]
fn test_verify_voucher_signature() {
    let test_value = common::load_test_vectors("../test_vectors/voucher.json").unwrap();

    let voucher_base64_string = test_value["verify"]["signed_voucher_base64"]
        .as_str()
        .unwrap()
        .to_string();
    let address_signer = test_value["verify"]["address_signer"]
        .as_str()
        .unwrap()
        .to_string();

    let result = verify_voucher_signature(voucher_base64_string, address_signer).expect("FIX ME");

    assert!(result);
}

#[test]
fn test_get_cid() {
    let test_value = common::load_test_vectors("../test_vectors/get_cid.json").unwrap();

    let expected_cid = test_value["cid"].as_str().unwrap().to_string();
    let message_api: MessageTxAPI = serde_json::from_value(test_value["signed_message"].to_owned())
        .expect("couldn't serialize signed message");

    let cid = get_cid(message_api).unwrap();

    assert_eq!(cid, expected_cid);
}

#[test]
fn test_multisig_v1_deserialize() {
    let expected_params = multisig::ConstructorParams {
        signers: vec![Address::from_bytes(
            &hex::decode("01D75AB2B78BB2FEB1CF86B1412E96916D805B40C3").unwrap(),
        )
        .unwrap()],
        num_approvals_threshold: 1,
        unlock_duration: 0,
        start_epoch: 0,
    };

    let params = deserialize_constructor_params(
        "g4FVAddasreLsv6xz4axQS6WkW2AW0DDAQA=".to_string(),
        "fil/1/multisig".to_string(),
    )
    .unwrap();

    match params {
        MessageParams::MultisigConstructorParams(p) => {
            assert_eq!(p.signers, expected_params.signers);
            assert_eq!(
                p.num_approvals_threshold,
                expected_params.num_approvals_threshold
            );
            assert_eq!(p.unlock_duration, expected_params.unlock_duration);
            assert_eq!(p.start_epoch, expected_params.start_epoch);
        }
        _ => {
            panic!("Not matching");
        }
    }
}

#[test]
fn test_serialize() {
    let expected_params = multisig::ChangeNumApprovalsThresholdParams { new_threshold: 2 };

    println!("{:?}", serde_json::to_string(&expected_params).unwrap());

    let json_params = r#"{ "NewThreshold": 2}"#;
    let params: MessageParams = serde_json::from_str(json_params).unwrap();

    let params_multisig = match params {
        MessageParams::ChangeNumApprovalsThresholdParams(params) => params,
        _ => {
            panic!("Something went wrong")
        }
    };

    assert_eq!(params_multisig.new_threshold, expected_params.new_threshold);
}

#[test]
fn test_serialize_f4_address() {
    let _address = Network::Mainnet
        .parse_address("f410f2qreez6evnfbqs6rvidgwm3b44hpxpvpeuoddga")
        .unwrap();

    assert!(true);
}
