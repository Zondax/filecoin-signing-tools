use secp256k1::util::SIGNATURE_SIZE;
use std::convert::TryFrom;

use crate::error::SignerError;
use crate::utils::from_hex_string;

pub const SIGNATURE_RECOVERY_SIZE: usize = SIGNATURE_SIZE + 1;

pub const BLS_SIGNATURE_SIZE: usize = 96;

pub struct SignatureSECP256K1(pub [u8; SIGNATURE_RECOVERY_SIZE]);

pub struct SignatureBLS(pub [u8; BLS_SIGNATURE_SIZE]);

pub enum Signature {
    SignatureSECP256K1(SignatureSECP256K1),
    SignatureBLS(SignatureBLS),
}

impl Signature {
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            Signature::SignatureSECP256K1(sig_secp256k1) => sig_secp256k1.as_bytes(),
            Signature::SignatureBLS(sig_bls) => sig_bls.as_bytes(),
        }
    }
}

impl SignatureBLS {
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl SignatureSECP256K1 {
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl TryFrom<Vec<u8>> for Signature {
    type Error = SignerError;

    fn try_from(v: Vec<u8>) -> Result<Signature, Self::Error> {
        if v.len() == SIGNATURE_RECOVERY_SIZE {
            let sig_secp256k1 = SignatureSECP256K1::try_from(v)?;

            return Ok(Signature::SignatureSECP256K1(sig_secp256k1));
        }

        if v.len() == BLS_SIGNATURE_SIZE {
            let sig_bls = SignatureBLS::try_from(v)?;

            return Ok(Signature::SignatureBLS(sig_bls));
        }

        Err(SignerError::GenericString(
            "Unknown signature type".to_string(),
        ))
    }
}

impl TryFrom<String> for Signature {
    type Error = SignerError;

    fn try_from(v: String) -> Result<Signature, Self::Error> {
        if v.len() == SIGNATURE_RECOVERY_SIZE * 2 {
            let sig_secp256k1 = SignatureSECP256K1::try_from(v)?;

            return Ok(Signature::SignatureSECP256K1(sig_secp256k1));
        }

        if v.len() == BLS_SIGNATURE_SIZE * 2 {
            let sig_bls = SignatureBLS::try_from(v)?;

            return Ok(Signature::SignatureBLS(sig_bls));
        }

        Err(SignerError::GenericString(
            "Unknown signature type".to_string(),
        ))
    }
}

impl TryFrom<String> for SignatureSECP256K1 {
    type Error = SignerError;

    fn try_from(s: String) -> Result<SignatureSECP256K1, Self::Error> {
        let tmp = from_hex_string(&s)?;
        SignatureSECP256K1::try_from(tmp)
    }
}

impl TryFrom<Vec<u8>> for SignatureSECP256K1 {
    type Error = SignerError;

    fn try_from(v: Vec<u8>) -> Result<SignatureSECP256K1, Self::Error> {
        if v.len() != SIGNATURE_RECOVERY_SIZE {
            return Err(SignerError::GenericString(
                "Invalid Signature Length".to_string(),
            ));
        }

        let mut sig = SignatureSECP256K1 {
            0: [0; SIGNATURE_RECOVERY_SIZE],
        };
        sig.0.copy_from_slice(&v[..SIGNATURE_RECOVERY_SIZE]);
        Ok(sig)
    }
}

impl TryFrom<Vec<u8>> for SignatureBLS {
    type Error = SignerError;

    fn try_from(v: Vec<u8>) -> Result<SignatureBLS, Self::Error> {
        if v.len() != BLS_SIGNATURE_SIZE {
            return Err(SignerError::GenericString(
                "Invalid Signature Length".to_string(),
            ));
        }

        let mut sig = SignatureBLS {
            0: [0; BLS_SIGNATURE_SIZE],
        };
        sig.0.copy_from_slice(&v[..BLS_SIGNATURE_SIZE]);
        Ok(sig)
    }
}

impl TryFrom<String> for SignatureBLS {
    type Error = SignerError;

    fn try_from(s: String) -> Result<SignatureBLS, Self::Error> {
        let tmp = from_hex_string(&s)?;
        SignatureBLS::try_from(tmp)
    }
}

impl AsRef<[u8]> for SignatureBLS {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
