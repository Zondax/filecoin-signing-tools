use core::convert::TryFrom;
use filecoin_signer::signature::{Signature, SignatureBLS, SignatureSECP256K1};

fn main() {
    loop {
        honggfuzz::fuzz!(|data: Vec<u8>| {
            let signature = if let Ok(r) = Signature::try_from(data) {
                r
            } else {
                return;
            };

            match signature {
                Signature::SignatureBLS(s) => {
                    if let Ok(bls) = SignatureBLS::try_from(s.to_string()) {
                        assert_eq!(&s.0[..], &bls.0[..]);
                    }
                }
                Signature::SignatureSECP256K1(s) => {
                    if let Ok(secp256k1) = SignatureSECP256K1::try_from(s.to_string()) {
                        assert_eq!(&s.0[..], &secp256k1.0[..]);
                    }
                }
            }
        });
    }
}
