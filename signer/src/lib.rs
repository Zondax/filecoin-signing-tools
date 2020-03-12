use crate::api::{
    MessageTx, MessageTxAPI, MessageTxNetwork, SignatureAPI, SignedMessageAPI, UnsignedMessageAPI,
};
use crate::error::SignerError;
use crate::utils::from_hex_string;
use forest_address::Address;
use forest_encoding::{from_slice, to_vec};
use forest_message;
use std::convert::TryFrom;

use crate::bip44::{Bip44Path, ExtendedSecretKey};
use bip39::{Language, MnemonicType, Seed};
use secp256k1::util::{
    COMPRESSED_PUBLIC_KEY_SIZE, FULL_PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SIGNATURE_SIZE,
};
use secp256k1::{recover, sign, verify, Message, RecoveryId};

pub mod api;
mod bip44;
pub mod error;
pub mod utils;

pub struct Mnemonic(pub String);

pub struct CborBuffer(pub Vec<u8>);

pub const SIGNATURE_RECOVERY_SIZE: usize = SIGNATURE_SIZE + 1;

pub struct Signature(pub [u8; SIGNATURE_RECOVERY_SIZE]);

pub struct PrivateKey(pub [u8; SECRET_KEY_SIZE]);

pub struct PublicKey(pub [u8; FULL_PUBLIC_KEY_SIZE]);

pub struct PublicKeyCompressed(pub [u8; COMPRESSED_PUBLIC_KEY_SIZE]);

pub struct ExtendedKey {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
    pub public_key_compressed: PublicKeyCompressed,
    pub address: String,
}

impl TryFrom<String> for Signature {
    type Error = SignerError;

    fn try_from(s: String) -> Result<Signature, Self::Error> {
        let tmp = from_hex_string(&s)?;
        Signature::try_from(tmp)
    }
}

impl TryFrom<Vec<u8>> for Signature {
    type Error = SignerError;

    fn try_from(v: Vec<u8>) -> Result<Signature, Self::Error> {
        if v.len() != SIGNATURE_RECOVERY_SIZE {
            return Err(SignerError::GenericString(
                "Invalid Signature Length".to_string(),
            ));
        }

        let mut sk = Signature {
            0: [0; SIGNATURE_RECOVERY_SIZE],
        };
        sk.0.copy_from_slice(&v[..SIGNATURE_RECOVERY_SIZE]);
        Ok(sk)
    }
}

impl TryFrom<String> for PrivateKey {
    type Error = SignerError;

    fn try_from(s: String) -> Result<PrivateKey, Self::Error> {
        let v = from_hex_string(&s)?;
        PrivateKey::try_from(v)
    }
}

impl TryFrom<Vec<u8>> for PrivateKey {
    type Error = SignerError;

    fn try_from(v: Vec<u8>) -> Result<PrivateKey, Self::Error> {
        if v.len() != SECRET_KEY_SIZE {
            return Err(SignerError::GenericString("Invalid Key Length".to_string()));
        }
        let mut sk = PrivateKey {
            0: [0; SECRET_KEY_SIZE],
        };
        sk.0.copy_from_slice(&v[..SECRET_KEY_SIZE]);
        Ok(sk)
    }
}

/// Generates a random mnemonic (English - 24 words)
pub fn key_generate_mnemonic() -> Result<Mnemonic, SignerError> {
    let mnemonic = bip39::Mnemonic::new(MnemonicType::Words24, Language::English);
    Ok(Mnemonic(mnemonic.to_string()))
}

/// Returns a public key, private key and address given a mnemonic and derivation path
///
/// # Arguments
///
/// * `mnemonic` - A string containing a 24-words English mnemonic
/// * `path` - A string containing a derivation path
///
pub fn key_derive(mnemonic: Mnemonic, path: String) -> Result<ExtendedKey, SignerError> {
    let mnemonic = bip39::Mnemonic::from_phrase(&mnemonic.0, Language::English)
        .map_err(|err| SignerError::GenericString(err.to_string()))?;

    let seed = Seed::new(&mnemonic, "");

    let master = ExtendedSecretKey::try_from(seed)?;

    let bip44_path = Bip44Path::from_string(path)?;

    let esk = master.derive_bip44(bip44_path)?;

    let address = Address::new_secp256k1(&esk.public_key().to_vec())
        .map_err(|err| SignerError::GenericString(err.to_string()))?;

    Ok(ExtendedKey {
        private_key: PrivateKey(esk.secret_key()),
        public_key: PublicKey(esk.public_key()),
        public_key_compressed: PublicKeyCompressed(esk.public_key_compressed()),
        address: address.to_string(),
    })
}

pub fn key_recover(private_key: &PrivateKey) -> Result<ExtendedKey, SignerError> {
    let secret_key = secp256k1::SecretKey::parse_slice(&private_key.0)?;
    let public_key = secp256k1::PublicKey::from_secret_key(&secret_key);
    let address = Address::new_secp256k1(&public_key.serialize())
        .map_err(|err| SignerError::GenericString(err.to_string()))?;

    Ok(ExtendedKey {
        private_key: PrivateKey(secret_key.serialize()),
        public_key: PublicKey(public_key.serialize()),
        public_key_compressed: PublicKeyCompressed(public_key.serialize_compressed()),
        address: address.to_string(),
    })
}

pub fn transaction_serialize(
    unsigned_message_arg: &UnsignedMessageAPI,
) -> Result<CborBuffer, SignerError> {
    let unsigned_message = forest_message::UnsignedMessage::try_from(unsigned_message_arg)?;
    let message_cbor = CborBuffer(to_vec(&unsigned_message)?);
    Ok(message_cbor)
}

pub fn transaction_parse(
    cbor_buffer: &CborBuffer,
    testnet: bool,
) -> Result<MessageTxAPI, SignerError> {
    let message: MessageTx = from_slice(&cbor_buffer.0)?;

    let message_tx_with_network = MessageTxNetwork {
        message_tx: message,
        testnet,
    };

    let parsed_message = MessageTxAPI::try_from(message_tx_with_network)?;

    Ok(parsed_message)
}

pub fn transaction_sign_raw(
    unsigned_message_api: &UnsignedMessageAPI,
    private_key: &PrivateKey,
) -> Result<Signature, SignerError> {
    let message = forest_message::UnsignedMessage::try_from(unsigned_message_api)?;
    let message_cbor = CborBuffer(to_vec(&message)?);

    let secret_key = secp256k1::SecretKey::parse_slice(&private_key.0)?;

    let cid_hashed = utils::get_digest(&message_cbor.0);

    let message_digest = Message::parse_slice(&cid_hashed)?;

    let (signature_rs, recovery_id) = sign(&message_digest, &secret_key);

    let mut signature = Signature { 0: [0; 65] };
    signature.0[..64].copy_from_slice(&signature_rs.serialize()[..]);
    signature.0[64] = recovery_id.serialize();

    Ok(signature)
}

pub fn transaction_sign(
    unsigned_message: &UnsignedMessageAPI,
    private_key: &PrivateKey,
) -> Result<SignedMessageAPI, SignerError> {
    let message = forest_message::UnsignedMessage::try_from(unsigned_message)?;
    let message_cbor = CborBuffer(to_vec(&message)?);

    let secret_key = secp256k1::SecretKey::parse_slice(&private_key.0)?;

    let cid_hashed = utils::get_digest(&message_cbor.0);

    let message_digest = Message::parse_slice(&cid_hashed)?;

    let (signature_rs, recovery_id) = sign(&message_digest, &secret_key);

    let mut signature = Signature { 0: [0; 65] };
    signature.0[..64].copy_from_slice(&signature_rs.serialize()[..]);
    signature.0[64] = recovery_id.serialize();

    let signed_message = SignedMessageAPI {
        message: unsigned_message.to_owned(),
        signature: SignatureAPI::from(&signature),
    };

    Ok(signed_message)
}

pub fn sign_message() {
    // TODO: message ?
    // TODO: return signature
}

pub fn verify_signature(
    signature: &Signature,
    cbor_buffer: &CborBuffer,
) -> Result<bool, SignerError> {
    let signature_rs = secp256k1::Signature::parse_slice(&signature.0[..64])?;
    let recovery_id = RecoveryId::parse(signature.0[64])?;

    // Should be default network here
    // FIXME: For now only testnet
    let tx = transaction_parse(cbor_buffer, true)?;

    // Decode the CBOR transaction hex string into CBOR transaction buffer
    let message_digest = utils::get_digest(&cbor_buffer.0);
    let message = Message::parse_slice(&message_digest)?;

    let publickey = recover(&message, &signature_rs, &recovery_id)?;

    let from = Address::new_secp256k1(&publickey.serialize_compressed().to_vec())
        .map_err(|err| SignerError::GenericString(err.to_string()))?;

    let tx_from = match tx {
        MessageTxAPI::UnsignedMessageAPI(tx) => tx.from,
        MessageTxAPI::SignedMessageAPI(tx) => tx.message.from,
    };

    // Compare recovered public key with the public key from the transaction
    if tx_from != from.to_string() {
        return Ok(false);
    }

    Ok(verify(&message, &signature_rs, &publickey))
}

#[cfg(test)]
mod tests {
    use crate::api::{MessageTxAPI, UnsignedMessageAPI};
    use crate::utils::{from_hex_string, to_hex_string};
    use crate::{
        key_derive, key_generate_mnemonic, transaction_parse, transaction_sign_raw,
        verify_signature, CborBuffer, Mnemonic, PrivateKey,
    };
    use std::convert::TryFrom;

    // NOTE: not the same transaction used in other tests.
    const EXAMPLE_UNSIGNED_MESSAGE: &str = r#"
        {
            "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
            "from": "t1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka",
            "nonce": 1,
            "value": "100000",
            "gas_price": "2500",
            "gas_limit": "25000",
            "method": 0,
            "params": ""
        }"#;

    const EXAMPLE_CBOR_DATA: &str =
        "885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855010f323f4709e8e4db0c1d4cd374f9f35201d26fb20144000186a0430009c4430061a80040";

    /* signed message :
     [
      // unsigned message
      [h'01FD1D0F4DFCD7E99AFCB99A8326B7DC459D32C628', h'010F323F4709E8E4DB0C1D4CD374F9F35201D26FB2', 1, h'000186A0', h'0009C4', h'0061A8', 0, h''],
      // Signature (sig_type + signatureRS + recoveryID)
      h'01541025CA93D7D15508854520549F6A3C1582FBDE1A511F21B12DCB3E49E8BDFF3EB824CD8236C66B120B45941FD07252908131FFB1DFFA003813B9F2BDD0C2F601'
     ]
    */
    const SIGNED_MESSAGE_CBOR: &str =
        "82885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855010f323f4709e8e4db0c1d4cd374f9f35201d26fb20144000186a0430009c4430061a80040584201541025CA93D7D15508854520549F6A3C1582FBDE1A511F21B12DCB3E49E8BDFF3EB824CD8236C66B120B45941FD07252908131FFB1DFFA003813B9F2BDD0C2F601";

    const EXAMPLE_PRIVATE_KEY: &str =
        "f15716d3b003b304b8055d9cc62e6b9c869d56cc930c3858d4d7c31f5f53f14a";

    #[test]
    fn generate_mnemonic() {
        let mnemonic = key_generate_mnemonic().expect("could not generate mnemonic");
        println!("{}", mnemonic.0);

        let word_count = mnemonic.0.split_ascii_whitespace().count();
        assert_eq!(word_count, 24)
    }

    #[test]
    fn derive_key() {
        let mnemonic = Mnemonic(
            "equip will roof matter pink blind book anxiety banner elbow sun young".to_string(),
        );
        let path = "m/44'/461'/0/0/0".to_string();

        let extended_key = key_derive(mnemonic, path).unwrap();

        assert_eq!(
            to_hex_string(&extended_key.private_key.0),
            EXAMPLE_PRIVATE_KEY
        );
    }

    #[test]
    fn parse_unsigned_transaction() {
        let cbor_data = CborBuffer(from_hex_string(EXAMPLE_CBOR_DATA).unwrap());

        let unsigned_tx = transaction_parse(&cbor_data, true).expect("FIX ME");
        let to = match unsigned_tx {
            MessageTxAPI::UnsignedMessageAPI(tx) => tx.to,
            MessageTxAPI::SignedMessageAPI(_) => panic!("Should be a Unsigned Message!"),
        };

        println!("{}", to.to_string());
        assert_eq!(
            to.to_string(),
            "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy".to_string()
        );
    }

    #[test]
    fn parse_signed_transaction() {
        let cbor_data = CborBuffer(from_hex_string(SIGNED_MESSAGE_CBOR).unwrap());

        let signed_tx = transaction_parse(&cbor_data, true).expect("FIX ME");
        let signature = match signed_tx {
            MessageTxAPI::UnsignedMessageAPI(_) => panic!("Should be a Signed Message!"),
            MessageTxAPI::SignedMessageAPI(tx) => tx.signature,
        };

        assert_eq!(
            to_hex_string(&signature.data),
            "541025ca93d7d15508854520549f6a3c1582fbde1a511f21b12dcb3e49e8bdff3eb824cd8236c66b120b45941fd07252908131ffb1dffa003813b9f2bdd0c2f601".to_string()
        );
    }

    #[test]
    fn parse_transaction_with_network() {
        let cbor_data = CborBuffer(from_hex_string(EXAMPLE_CBOR_DATA).unwrap());

        let unsigned_tx_mainnet = transaction_parse(&cbor_data, false).expect("FIX ME");
        let (to, from) = match unsigned_tx_mainnet {
            MessageTxAPI::UnsignedMessageAPI(tx) => (tx.to, tx.from),
            MessageTxAPI::SignedMessageAPI(_) => panic!("Should be a Unsigned Message!"),
        };

        println!("{}", to.to_string());
        assert_eq!(
            to.to_string(),
            "f17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy".to_string()
        );
        assert_eq!(
            from.to_string(),
            "f1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka".to_string()
        );
    }

    #[test]
    fn parse_transaction_with_network_testnet() {
        let cbor_data = CborBuffer(from_hex_string(EXAMPLE_CBOR_DATA).unwrap());

        let unsigned_tx_testnet = transaction_parse(&cbor_data, true).expect("FIX ME");
        let (to, from) = match unsigned_tx_testnet {
            MessageTxAPI::UnsignedMessageAPI(tx) => (tx.to, tx.from),
            MessageTxAPI::SignedMessageAPI(_) => panic!("Should be a Unsigned Message!"),
        };

        println!("{}", to.to_string());
        assert_eq!(
            to.to_string(),
            "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy".to_string()
        );
        assert_eq!(
            from.to_string(),
            "t1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka".to_string()
        );
    }

    #[test]
    fn parse_transaction_signed_with_network() {
        let cbor_data = CborBuffer(from_hex_string(SIGNED_MESSAGE_CBOR).unwrap());

        let signed_tx_mainnet = transaction_parse(&cbor_data, false).expect("FIX ME");
        let (to, from) = match signed_tx_mainnet {
            MessageTxAPI::UnsignedMessageAPI(_) => panic!("Should be a Signed Message!"),
            MessageTxAPI::SignedMessageAPI(tx) => (tx.message.to, tx.message.from),
        };

        println!("{}", to.to_string());
        assert_eq!(
            to.to_string(),
            "f17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy".to_string()
        );
        assert_eq!(
            from.to_string(),
            "f1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka".to_string()
        );
    }

    #[test]
    fn parse_transaction_signed_with_network_testnet() {
        let cbor_data = CborBuffer(from_hex_string(SIGNED_MESSAGE_CBOR).unwrap());

        let signed_tx_testnet = transaction_parse(&cbor_data, true).expect("FIX ME");
        let (to, from) = match signed_tx_testnet {
            MessageTxAPI::UnsignedMessageAPI(_) => panic!("Should be a Signed Message!"),
            MessageTxAPI::SignedMessageAPI(tx) => (tx.message.to, tx.message.from),
        };

        println!("{}", to.to_string());
        assert_eq!(
            to.to_string(),
            "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy".to_string()
        );
        assert_eq!(
            from.to_string(),
            "t1b4zd6ryj5dsnwda5jtjxj6ptkia5e35s52ox7ka".to_string()
        );
    }

    #[test]
    fn verify_invalid_signature() {
        let cbor_data = CborBuffer(from_hex_string(EXAMPLE_CBOR_DATA).unwrap());

        // Path 44'/461'/0/0/0
        let private_key = PrivateKey::try_from(EXAMPLE_PRIVATE_KEY.to_string()).unwrap();

        let message_user_api: UnsignedMessageAPI =
            serde_json::from_str(EXAMPLE_UNSIGNED_MESSAGE).expect("FIXME");

        let mut signature = transaction_sign_raw(&message_user_api, &private_key).unwrap();

        assert!(verify_signature(&signature, &cbor_data).unwrap());

        // Tampered signature and look if it valid
        signature.0[5] = 0x01;
        signature.0[34] = 0x00;

        assert!(!verify_signature(&signature, &cbor_data).unwrap());
    }
}
