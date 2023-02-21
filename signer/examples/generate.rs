use bls_signatures::Serialize;
use bls_signatures::*;
use fvm_shared::bigint::BigInt;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rayon::prelude::*;

use cid::multihash::MultihashDigest;
use fvm_ipld_encoding::to_vec;
use fvm_ipld_encoding::RawBytes;
use fvm_ipld_encoding::DAG_CBOR;
use fvm_shared::address::Address;
use fvm_shared::econ::TokenAmount;
use fvm_shared::message::Message;
use std::str::FromStr;

use hex::encode;
use std::fs;

#[derive(serde::Serialize)]
struct TestCase {
    pub pk: String,
    pub sk: String,
    pub sig: String,
    pub message: Message,
}

//////////////////////////////
//
// Script to generate test case for BLS support.
// The test cases wil be used in wasm node tests series.
// `cargo run --example generate --release`
//
//////////////////////////////

fn run(num_messages: usize) {
    println!("Generate {} test case", num_messages);

    let mut rng = ChaCha8Rng::seed_from_u64(12);

    // generate private keys
    let private_keys: Vec<_> = (0..num_messages)
        .map(|_| PrivateKey::generate(&mut rng))
        .collect();

    // generate messages
    let messages: Vec<_> = private_keys
        .par_iter()
        .map(|sk| Message {
            version: 0,
            to: fvm_shared::address::Address::from_str("t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy")
                .unwrap(),
            from: Address::new_bls(&sk.public_key().as_bytes()).unwrap(),
            sequence: 1,
            value: TokenAmount::from_atto(BigInt::from_str("100000").unwrap()),
            gas_limit: 25000,
            gas_fee_cap: TokenAmount::from_atto(BigInt::from_str("1").unwrap()),
            gas_premium: TokenAmount::from_atto(BigInt::from_str("1").unwrap()),
            method_num: 0,
            params: RawBytes::new(vec![]),
        })
        .collect();

    // sign messages
    let sigs: Vec<Signature> = messages
        .par_iter()
        .zip(private_keys.par_iter())
        .map(|(message, sk)| {
            let message_ser = to_vec(&message).unwrap();
            let hash = cid::multihash::Code::Blake2b256.digest(&message_ser);
            let message_cid = cid::Cid::new_v1(DAG_CBOR, hash);
            let sign_bytes = message_cid.to_bytes();

            sk.sign(sign_bytes)
        })
        .collect::<Vec<Signature>>();

    // let public_keys = private_keys
    //     .par_iter()
    //     .map(|sk| sk.public_key())
    //     .collect::<Vec<_>>();

    let test_cases = sigs
        .par_iter()
        .zip(private_keys.par_iter())
        .zip(messages.par_iter())
        .map(|((sig, sk), message_api)| {
            let pk = sk.public_key();

            TestCase {
                pk: encode(pk.as_bytes()),
                sk: encode(sk.as_bytes()),
                sig: encode(sig.as_bytes()),
                message: message_api.to_owned(),
            }
        })
        .collect::<Vec<_>>();

    fs::write(
        "generated_test_cases.json",
        serde_json::to_string_pretty(&test_cases).unwrap(),
    )
    .expect("Unable to write file");
}

fn main() {
    run(10);
}
