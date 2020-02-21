use secp256k1::util::{COMPRESSED_PUBLIC_KEY_SIZE, SECRET_KEY_SIZE};
use secp256k1::{PublicKey, SecretKey};

use crate::error::SignerError;
use bip39::Seed;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::convert::TryFrom;
use std::fmt;
use zeroize::Zeroize;

const HARDENED_BIT: u32 = 1 << 31;

pub struct Bip44Path(pub [u32; 5]);

impl Bip44Path {
    pub fn from_slice(path: &[u32]) -> Result<Bip44Path, SignerError> {
        let mut path_array: [u32; 5] = Default::default();
        if path.len() != 5 {
            return Err(SignerError::GenericString(
                "Invalid length for path".to_string(),
            ));
        };

        path_array.copy_from_slice(path);

        Ok(Bip44Path(path_array))
    }

    pub fn from_string(path: String) -> Result<Bip44Path, SignerError> {
        let mut path = path.split('/');

        if path.next() != Some("m") {
            return Err(SignerError::GenericString(
                "Path should start with `m`".to_string(),
            ));
        };

        let result = path
            .map(|index| {
                let (index_to_parse, mask) = if index.ends_with('\'') {
                    // Remove the last character and harden index
                    (&index[..index.len() - 1], HARDENED_BIT)
                } else {
                    (index, 0)
                };

                // FIX ME
                let child_index = index_to_parse.parse::<u32>()?;

                Ok(child_index | mask)

            }).collect::<Result<Vec<u32>, std::num::ParseIntError>>()?;

        let bip44Path = Bip44Path::from_slice(&result)?;

        Ok(bip44Path)
    }
}

const HMAC_SEED: &'static [u8; 12] = b"Bitcoin seed";

#[derive(Zeroize, Debug)]
#[zeroize(drop)]
struct ChainCode([u8; 32]);

pub struct ExtendedSecretKey {
    secret_key: SecretKey,
    chain_code: ChainCode,
}

impl fmt::Display for ExtendedSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SK/CC:  {:?}/{:?}",
            hex::encode(&self.secret_key()),
            hex::encode(&self.chain_code.0)
        )
    }
}

impl TryFrom<Seed> for ExtendedSecretKey {
    type Error = SignerError;

    fn try_from(seed: Seed) -> Result<ExtendedSecretKey, Self::Error> {
        let mut hmac: Hmac<Sha512> = Hmac::new_varkey(HMAC_SEED)?;
        hmac.input(seed.as_bytes());

        let hmac_code = hmac.result().code();
        let (master_private_key, master_chain_code) = hmac_code.split_at(32);

        ExtendedSecretKey::new(
            SecretKey::parse_slice(master_private_key)?,
            &master_chain_code,
        )
    }
}

impl ExtendedSecretKey {
    pub fn new(secret_key: SecretKey, chain_code: &[u8]) -> Result<Self, SignerError> {
        let mut tmp = ChainCode {
            0: Default::default(),
        };
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
    pub fn public_key(&self) -> [u8; COMPRESSED_PUBLIC_KEY_SIZE] {
        let pubkey = PublicKey::from_secret_key(&self.secret_key);
        pubkey.serialize_compressed()
    }

    pub fn derive_child_key(&self, child_index: u32) -> Result<ExtendedSecretKey, SignerError> {
        let mut hmac = Hmac::<Sha512>::new_varkey(&self.chain_code.0)?;

        if child_index & HARDENED_BIT == 0 {
            // Not hardened
            hmac.input(&self.public_key());
            hmac.input(&child_index.to_be_bytes());
        } else {
            // Hardened
            hmac.input(&[0u8]);
            hmac.input(&self.secret_key());
            hmac.input(&child_index.to_be_bytes());
        }

        let hmac_result = hmac.result().code();
        let (secret_key_shift, child_chain_code) = hmac_result.split_at(32);

        let mut child_secret_key = self.secret_key.clone();
        child_secret_key.tweak_add_assign(&SecretKey::parse_slice(secret_key_shift)?);

        ExtendedSecretKey::new(child_secret_key, &child_chain_code)
    }

    pub fn derive_bip44(&self, path: Bip44Path) -> Result<ExtendedSecretKey, SignerError> {
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
    use crate::bip44::{Bip44Path, ExtendedSecretKey};
    use bip39::{Language, Mnemonic, Seed};
    use std::convert::TryFrom;

    const HARDENED_BIT: u32 = 1 << 31;

    #[test]
    fn generate_mnemonic() {
        let phrase = "census rose wild tray fine produce recall hint chalk second try outer antique gain wait topple west indoor pond total dentist change avoid vault";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        let seed = Seed::new(&mnemonic, "");

        let master = ExtendedSecretKey::try_from(seed).unwrap();

        println!("{}", master);
        // FIXME: Add checks & more test cases
        //assert_eq!(master.private_key())
    }

    #[test]
    fn derive_example_path() {
        let phrase = "census rose wild tray fine produce recall hint chalk second try outer antique gain wait topple west indoor pond total dentist change avoid vault";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        let seed = Seed::new(&mnemonic, "");
        let master = ExtendedSecretKey::try_from(seed).unwrap();

        let esk = master.derive_bip44(Bip44Path([0, 0, 0, 0, 0])).unwrap();

        println!("{}", esk);
        // FIXME: Add checks & more test cases
    }

    #[test]
    fn create_derive_path() {
        let path_string = "m/44'/461'/0/0/0";

        let result = Bip44Path::from_string(path_string.to_string()).unwrap();

        // FIX ME: need a way to compare bip44Path
    }
}
