use libsecp256k1::util::{COMPRESSED_PUBLIC_KEY_SIZE, FULL_PUBLIC_KEY_SIZE, SECRET_KEY_SIZE};
use libsecp256k1::{PublicKey, SecretKey};

use crate::error::SignerError;
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha512;
use std::convert::TryFrom;
use std::fmt;
use zeroize::Zeroize;
use zx_bip44::BIP44Path;

const HMAC_SEED: &[u8; 12] = b"Bitcoin seed";
const HARDENED_BIT: u32 = 1 << 31;

#[derive(Zeroize, Debug)]
#[zeroize(drop)]
struct ChainCode([u8; 32]);

pub struct ExtendedSecretKey {
    secret_key: SecretKey,
    chain_code: ChainCode,
}

type HmacSha512 = Hmac<Sha512>;

impl fmt::Display for ExtendedSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SecretKey/ChainCode:  {:?}/{:?}",
            hex::encode(&self.secret_key()),
            hex::encode(&self.chain_code.0)
        )
    }
}

impl TryFrom<&[u8]> for ExtendedSecretKey {
    type Error = SignerError;

    fn try_from(seed: &[u8]) -> Result<ExtendedSecretKey, Self::Error> {
        let mut hmac = HmacSha512::new_varkey(HMAC_SEED)?;
        hmac.update(seed);

        let hmac_code = hmac.finalize().into_bytes();
        let (master_private_key, master_chain_code) = hmac_code.split_at(32);

        ExtendedSecretKey::new(
            SecretKey::parse_slice(master_private_key)?,
            master_chain_code,
        )
    }
}

impl ExtendedSecretKey {
    pub fn new(secret_key: SecretKey, chain_code: &[u8]) -> Result<Self, SignerError> {
        let mut tmp = ChainCode(Default::default());
        tmp.0.copy_from_slice(chain_code);

        Ok(ExtendedSecretKey {
            secret_key,
            chain_code: tmp,
        })
    }

    #[inline]
    pub fn secret_key(&self) -> [u8; SECRET_KEY_SIZE] {
        self.secret_key.serialize()
    }

    #[inline]
    #[allow(dead_code)]
    pub fn chain_code(&self) -> [u8; SECRET_KEY_SIZE] {
        self.chain_code.0
    }

    #[inline]
    pub fn public_key(&self) -> [u8; FULL_PUBLIC_KEY_SIZE] {
        let pubkey = PublicKey::from_secret_key(&self.secret_key);
        pubkey.serialize()
    }

    #[inline]
    fn public_key_compressed(&self) -> [u8; COMPRESSED_PUBLIC_KEY_SIZE] {
        let pubkey = PublicKey::from_secret_key(&self.secret_key);
        pubkey.serialize_compressed()
    }

    pub fn derive_child_key(&self, child_index: u32) -> Result<ExtendedSecretKey, SignerError> {
        let mut hmac = Hmac::<Sha512>::new_varkey(&self.chain_code.0)?;

        if child_index & HARDENED_BIT == 0 {
            // Not hardened
            hmac.update(&self.public_key_compressed());
            hmac.update(&child_index.to_be_bytes());
        } else {
            // Hardened
            hmac.update(&[0u8]);
            hmac.update(&self.secret_key());
            hmac.update(&child_index.to_be_bytes());
        }

        let hmac_result = hmac.finalize().into_bytes();
        let (secret_key_shift, child_chain_code) = hmac_result.split_at(32);

        let mut child_secret_key = self.secret_key;
        child_secret_key.tweak_add_assign(&SecretKey::parse_slice(secret_key_shift)?)?;

        ExtendedSecretKey::new(child_secret_key, child_chain_code)
    }

    pub fn derive_bip44(&self, path: &BIP44Path) -> Result<ExtendedSecretKey, SignerError> {
        let child0 = self.derive_child_key(path.0[0])?;
        let child1 = child0.derive_child_key(path.0[1])?;
        let child2 = child1.derive_child_key(path.0[2])?;
        let child3 = child2.derive_child_key(path.0[3])?;
        let child4 = child3.derive_child_key(path.0[4])?;

        Ok(child4)
    }
}

#[cfg(test)]
mod tests {
    use crate::extended_key::ExtendedSecretKey;
    use bip39::{Language, Mnemonic, Seed};
    use hex::encode;
    use std::convert::TryFrom;
    use zx_bip44::BIP44Path;

    const HARDENED_BIT: u32 = 1 << 31;

    #[test]
    fn generate_mnemonic() {
        let phrase = "census rose wild tray fine produce recall hint chalk second try outer antique gain wait topple west indoor pond total dentist change avoid vault";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        let seed = Seed::new(&mnemonic, "");

        let master = ExtendedSecretKey::try_from(seed.as_bytes()).unwrap();

        println!("{}", master);
        assert_eq!(
            encode(master.secret_key()),
            "fe2445a3beb060041a7bb0fdb5d4438c21db408bd71294066381798d96b75221"
        );
    }

    #[test]
    fn derive_child() {
        let phrase = "pumpkin sell climb ten list proof embark finish zero voyage congress outdoor domain city cannon leave select visual know waste tonight sauce load lift";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        let seed = Seed::new(&mnemonic, "");
        assert_eq!(encode(&seed), "bf9504117d7c06bcdd0a4b4c41f3537faf13a27618a6b9a314cdb6c920ba44acf87b2cf1e2ba8a241833a55fda7b545a925f728b35ea2040a1d3a367ea45933a",);

        let master = ExtendedSecretKey::try_from(seed.as_bytes()).unwrap();
        assert_eq!(
            encode(&master.secret_key()),
            "570761185bfbbfaad56a33b21b42cb3ca73c7fbf1137db99e0fa0e2758cb2a9a",
        );

        // Derive child 5

        let esk = master.derive_child_key(5).unwrap();
        assert_eq!(
            encode(esk.secret_key()),
            "df2801c6d9b373fa5a84d615817bac957ef198addaa98d0e542063dd5ab0f1de",
        );

        assert_eq!(
            encode(esk.chain_code()),
            "dace38fba7999a8266534c868f4c936beb6aec4d795c216b35d7d865081c6eb1",
        );

        // Derive child 5'

        let esk2 = master.derive_child_key(5 + 0x8000_0000).unwrap();
        assert_eq!(
            encode(esk2.secret_key()),
            "437fe078795f5782521ad38dd4c763d11d71e4e83bee7cfdd4e299aca9aad094",
        );

        assert_eq!(
            encode(esk2.chain_code()),
            "6626140ef161658292d5d08d36d56ddd0be32fb3a4b699f8bf466cd5235f2444",
        );
    }

    #[test]
    fn derive_example_path() {
        let phrase = "pumpkin sell climb ten list proof embark finish zero voyage congress outdoor domain city cannon leave select visual know waste tonight sauce load lift";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        let seed = Seed::new(&mnemonic, "");
        let master = ExtendedSecretKey::try_from(seed.as_bytes()).unwrap();

        let path = BIP44Path::from_string("m/44'/461'/0/0/0").unwrap();
        let esk = master.derive_bip44(&path).unwrap();

        println!("{}", esk);
        assert_eq!(
            encode(esk.secret_key()),
            "7d9c686593de943b08dea26bf21dcfa871ce956a578167d5adb2107d62b32a58",
        );

        assert_eq!(
            encode(esk.chain_code()),
            "d25494e91a66b91a82ed18e80857d7615b08aedbc9fca4ae1b6f6be769f09bbe",
        );
    }

    #[test]
    fn create_derive_path() {
        let path_string = "m/44'/461'/0/0/0";

        let result = BIP44Path::from_string(path_string).unwrap();

        assert_eq!(result.0[0], (44 | HARDENED_BIT));
        assert_eq!(result.0[1], (461 | HARDENED_BIT));
        assert_eq!(result.0[2], 0);
        assert_eq!(result.0[3], 0);
        assert_eq!(result.0[4], 0);
    }
}
