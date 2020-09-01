use extras::paych::SignedVoucher;
use filecoin_signer::{utils, PrivateKey};
use forest_address::Address;
use forest_encoding::{from_slice, to_vec};
use num_bigint_chainsafe::BigInt;
use secp256k1::{recover, sign, verify, Message, RecoveryId};
use std::convert::TryFrom;
use std::str::FromStr;

fn main() {
    let private_key =
        PrivateKey::try_from("YbDPh1vq3fBClzbiwDt6WjniAdZn8tNcCwcBO2hDwyk=".to_string()).unwrap();
    let secret_key = secp256k1::SecretKey::parse_slice(&private_key.0).unwrap();

    let v = SignedVoucher {
        channel_addr: Address::from_str("t2h6o4uvzsksf3yi2ri2uu7eqvhqkcp7axmg3mski").unwrap(),
        time_lock_min: 1234,
        time_lock_max: 0,
        secret_pre_image: Vec::new(),
        extra: None,
        lane: 0,
        nonce: 1,
        amount: BigInt::parse_bytes("100000".as_bytes(), 10).unwrap(),
        min_settle_height: 1,
        merges: Vec::new(),
        signature: None,
    };

    /*println!("{:?}", v.signing_bytes().unwrap());*/
    println!("{:?}", v);
    println!("{:?}", base64::encode(to_vec(&v).unwrap()));

    let svb = v.signing_bytes().unwrap();
    let digest = utils::get_digest(&svb).unwrap();

    let blob_to_sign = Message::parse_slice(&digest).unwrap();

    let (signature_rs, _recovery_id) = sign(&blob_to_sign, &secret_key);

    println!("{:?}", base64::encode(signature_rs.serialize().to_vec()));

    let decoded_voucher = base64::decode(base64::encode(to_vec(&v).unwrap())).unwrap();
    let voucher: SignedVoucher = from_slice(&decoded_voucher).unwrap();

    println!("{:?}", voucher);
}
