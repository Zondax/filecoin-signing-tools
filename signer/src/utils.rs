use blake2b_simd::Params;
use core::{array::TryFromSliceError, convert::TryInto};

static CID_PREFIX: &[u8] = &[0x01, 0x71, 0xa0, 0xe4, 0x02, 0x20];

pub fn blake2b_256(ingest: &[u8]) -> [u8; 32] {
    let digest = Params::new()
        .hash_length(32)
        .to_state()
        .update(ingest)
        .finalize();

    let mut ret = [0u8; 32];
    ret.clone_from_slice(digest.as_bytes());
    ret
}

/// transform a message into a hashed message ready to be signed and following Filecoin standard
pub fn get_digest(message: &[u8]) -> Result<[u8; 32], TryFromSliceError> {
    let message_hashed = Params::new()
        .hash_length(32)
        .to_state()
        .update(message)
        .finalize();

    let cid_hashed = Params::new()
        .hash_length(32)
        .to_state()
        .update(CID_PREFIX)
        .update(message_hashed.as_bytes())
        .finalize();

    cid_hashed.as_bytes().try_into()
}

/// transform a voucher into a hashed message ready to be signed and following Filecoin standard
pub fn get_digest_voucher(message: &[u8]) -> Result<[u8; 32], TryFromSliceError> {
    let message_hashed = Params::new()
        .hash_length(32)
        .to_state()
        .update(message)
        .finalize();

    message_hashed.as_bytes().try_into()
}

#[cfg(test)]
mod tests {
    use crate::utils::get_digest;
    use hex::{decode, encode};

    #[test]
    fn test_digest_message() {
        const EXAMPLE_CBOR_DATA: &str =
            "885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c6285501b882619d46558f3d9e316d11b48dcf211327025a0144000186a0430009c4430061a80040";

        let message_digest = get_digest(&decode(EXAMPLE_CBOR_DATA.as_bytes()).unwrap()).unwrap();

        assert_eq!(
            encode(message_digest),
            "5a51287d2e5401b75014da0f050c8db96fe0bacdad75fce964520ca063b697e1"
        );
    }

    #[test]
    fn empty() {
        // FIXME:
    }
}
