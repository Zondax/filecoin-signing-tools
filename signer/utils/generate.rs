use bls_signatures::Serialize;
use bls_signatures::*;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rayon::prelude::*;

use filecoin_signer::api::UnsignedMessageAPI;
use forest_address::Address;
use forest_encoding::to_vec;
use forest_message::UnsignedMessage;
use std::convert::TryFrom;

use hex::encode;
use std::fs;

#[derive(serde::Serialize)]
struct TestCase {
    pub pk: String,
    pub sk: String,
    pub sig: String,
    pub message: UnsignedMessageAPI,
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
        .map(|sk| UnsignedMessageAPI {
            to: "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy".to_string(),
            from: Address::new_bls(&sk.public_key().as_bytes())
                .unwrap()
                .to_string(),
            nonce: 1,
            value: "100000".to_string(),
            gas_limit: 25000,
            gas_fee_cap: "1".to_string(),
            gas_premium: "1".to_string(),
            method: 0,
            params: "".to_owned(),
        })
        .collect();

    // sign messages
    let sigs: Vec<Signature>;
    sigs = messages
        .par_iter()
        .zip(private_keys.par_iter())
        .map(|(message_api, sk)| {
            let message = UnsignedMessage::try_from(message_api).expect("FIXME");

            let message_cbor = to_vec(&message).expect("Cbor serialization failed");

            sk.sign(message_cbor)
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
