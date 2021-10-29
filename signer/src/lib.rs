#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used,))]

use std::convert::TryFrom;
use std::convert::TryInto;
use std::str::FromStr;

use bip39::{Language, MnemonicType, Seed};
use bls_signatures::Serialize;
use forest_address::{Address, BLSPublicKey, Network, Protocol};
use forest_cid::{multihash::MultihashDigest, Cid, Code::Identity};
use forest_encoding::blake2b_256;
use forest_encoding::{from_slice, to_vec};
use forest_message::{SignedMessage, UnsignedMessage};
use libsecp256k1::util::{
    COMPRESSED_PUBLIC_KEY_SIZE, FULL_PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SIGNATURE_SIZE,
};
use libsecp256k1::{recover, sign, verify, Message, RecoveryId};
use num_bigint_chainsafe::BigInt;
use num_traits::FromPrimitive;
use rayon::prelude::*;
use zx_bip44::BIP44Path;

use extras::{multisig, paych, ExecParams, MethodInit, INIT_ACTOR_ADDR};

use crate::api::{
    MessageParams, MessageTx, MessageTxAPI, MessageTxNetwork, SignatureAPI, SignedMessageAPI,
    UnsignedMessageAPI,
};
use crate::error::SignerError;
use crate::extended_key::ExtendedSecretKey;
use crate::signature::{Signature, SignatureBLS, SignatureSECP256K1};

pub mod api;
pub mod error;
pub mod extended_key;
pub mod signature;
pub mod utils;

/// Mnemonic string
pub struct Mnemonic(pub String);

/// CBOR message in a buffer
pub struct CborBuffer(pub Vec<u8>);

impl AsRef<[u8]> for CborBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub const SIGNATURE_RECOVERY_SIZE: usize = SIGNATURE_SIZE + 1;

pub const BLS_PUB_LEN: usize = 48;

/// Private key buffer
pub struct PrivateKey(pub [u8; SECRET_KEY_SIZE]);

/// Public key secp256k1 buffer
pub struct PublicKeySECP256K1(pub [u8; FULL_PUBLIC_KEY_SIZE]);

pub enum PublicKey {
    PublicKeySECP256K1(PublicKeySECP256K1),
    BLSPublicKey(BLSPublicKey),
}

impl PublicKey {
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            PublicKey::PublicKeySECP256K1(pk) => pk.0.to_vec(),
            PublicKey::BLSPublicKey(pk) => pk.0.to_vec(),
        }
    }
}

/// Compressed public key buffer
pub struct PublicKeyCompressed(pub [u8; COMPRESSED_PUBLIC_KEY_SIZE]);

/// Extended key structure
pub struct ExtendedKey {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
    pub address: String,
}

#[cfg(feature = "with-ffi-support")]
ffi_support::implement_into_ffi_by_pointer!(ExtendedKey);

impl TryFrom<String> for PrivateKey {
    type Error = SignerError;

    fn try_from(s: String) -> Result<PrivateKey, Self::Error> {
        let v = base64::decode(&s)?;

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

fn derive_extended_secret_key(seed: &[u8], path: &str) -> Result<ExtendedSecretKey, SignerError> {
    let master = ExtendedSecretKey::try_from(seed)?;
    let bip44_path = BIP44Path::from_string(path)?;
    let esk = master.derive_bip44(&bip44_path)?;

    Ok(esk)
}

fn derive_extended_secret_key_from_mnemonic(
    mnemonic: &str,
    path: &str,
    password: &str,
    language_code: &str,
) -> Result<ExtendedSecretKey, SignerError> {
    let lang = Language::from_language_code(language_code);

    match lang {
        Some(l) => {
            let mnemonic = bip39::Mnemonic::from_phrase(&mnemonic, l)
                .map_err(|err| SignerError::GenericString(err.to_string()))?;

            let seed = Seed::new(&mnemonic, password);

            derive_extended_secret_key(seed.as_bytes(), path)
        }
        None => Err(SignerError::GenericString(
            "Unknown language code".to_string(),
        )),
    }
}

/// Returns a public key, private key and address given a mnemonic, derivation path and a password
///
/// # Arguments
///
/// * `mnemonic` - A string containing a 24-words English mnemonic
/// * `path` - A string containing a derivation path
/// * `password` - Password to decrypt seed, if none use and empty string (e.g "")
pub fn key_derive(
    mnemonic: &str,
    path: &str,
    password: &str,
    language_code: &str,
) -> Result<ExtendedKey, SignerError> {
    let esk = derive_extended_secret_key_from_mnemonic(mnemonic, path, password, language_code)?;

    let mut address = Address::new_secp256k1(&esk.public_key().to_vec())?;

    let bip44_path = BIP44Path::from_string(path)?;

    address.set_network(Network::Mainnet);
    if bip44_path.is_testnet() {
        address.set_network(Network::Testnet);
    }

    Ok(ExtendedKey {
        private_key: PrivateKey(esk.secret_key()),
        public_key: PublicKey::PublicKeySECP256K1(PublicKeySECP256K1(esk.public_key())),
        address: address.to_string(),
    })
}

/// Returns a public key, private key and address given a seed and derivation path
///
/// # Arguments
///
/// * `seed` - A seed as bytes array
/// * `path` - A string containing a derivation path
///
pub fn key_derive_from_seed(seed: &[u8], path: &str) -> Result<ExtendedKey, SignerError> {
    let esk = derive_extended_secret_key(seed, path)?;

    let mut address = Address::new_secp256k1(&esk.public_key().to_vec())?;

    let bip44_path = BIP44Path::from_string(path)?;

    address.set_network(Network::Mainnet);
    if bip44_path.is_testnet() {
        address.set_network(Network::Testnet);
    }

    Ok(ExtendedKey {
        private_key: PrivateKey(esk.secret_key()),
        public_key: PublicKey::PublicKeySECP256K1(PublicKeySECP256K1(esk.public_key())),
        address: address.to_string(),
    })
}

/// Get extended key from private key
///
/// # Arguments
///
/// * `private_key` - A `PrivateKey`
/// * `testnet` - specify the network, `true` if testnet else `false` for mainnet
///
pub fn key_recover(private_key: &PrivateKey, testnet: bool) -> Result<ExtendedKey, SignerError> {
    let secret_key = libsecp256k1::SecretKey::parse_slice(&private_key.0)?;
    let public_key = libsecp256k1::PublicKey::from_secret_key(&secret_key);
    let mut address = Address::new_secp256k1(&public_key.serialize())?;

    if testnet {
        address.set_network(Network::Testnet);
    } else {
        address.set_network(Network::Mainnet);
    }

    Ok(ExtendedKey {
        private_key: PrivateKey(secret_key.serialize()),
        public_key: PublicKey::PublicKeySECP256K1(PublicKeySECP256K1(public_key.serialize())),
        address: address.to_string(),
    })
}

/// Get extended key from BLS private key
///
/// # Arguments
///
/// * `private_key` - A `bls_signatures::PrivateKey`
/// * `testnet` - specify the network, `true` if testnet else `false` for mainnet
///
pub fn key_recover_bls(
    private_key: &PrivateKey,
    testnet: bool,
) -> Result<ExtendedKey, SignerError> {
    let sk = bls_signatures::PrivateKey::from_bytes(&private_key.0)?;

    let mut address = Address::new_bls(&sk.public_key().as_bytes())?;

    if testnet {
        address.set_network(Network::Testnet);
    } else {
        address.set_network(Network::Mainnet);
    }

    let mut public_key = BLSPublicKey {
        0: [0; forest_address::BLS_PUB_LEN],
    };
    public_key.0.copy_from_slice(&sk.public_key().as_bytes());

    let mut secret_key = PrivateKey {
        0: [0; SECRET_KEY_SIZE],
    };
    secret_key.0.copy_from_slice(&sk.as_bytes());

    Ok(ExtendedKey {
        private_key: secret_key,
        public_key: PublicKey::BLSPublicKey(public_key),
        address: address.to_string(),
    })
}

/// Serialize a transaction and return a CBOR hexstring.
///
/// # Arguments
///
/// * `transaction` - a filecoin transaction
///
pub fn transaction_serialize(
    unsigned_message_arg: &UnsignedMessageAPI,
) -> Result<CborBuffer, SignerError> {
    let unsigned_message = UnsignedMessage::try_from(unsigned_message_arg)?;
    let message_cbor = CborBuffer(to_vec(&unsigned_message)?);
    Ok(message_cbor)
}

/// Parse a CBOR hextring into a filecoin transaction (signed or unsigned).
///
/// # Arguments
///
/// * `hexstring` - the cbor hexstring to parse
/// * `testnet` - boolean value `true` if testnet or `false` for mainnet
///
pub fn transaction_parse(
    cbor_buffer: &CborBuffer,
    testnet: bool,
) -> Result<MessageTxAPI, SignerError> {
    let message: MessageTx = from_slice(cbor_buffer.as_ref())?;

    let message_tx_with_network = MessageTxNetwork {
        message_tx: message,
        testnet,
    };

    let parsed_message = MessageTxAPI::try_from(message_tx_with_network)?;

    Ok(parsed_message)
}

fn transaction_sign_secp56k1_raw(
    unsigned_message_api: &UnsignedMessageAPI,
    private_key: &PrivateKey,
) -> Result<SignatureSECP256K1, SignerError> {
    let message_cbor = transaction_serialize(unsigned_message_api)?;

    let secret_key = libsecp256k1::SecretKey::parse_slice(&private_key.0)?;

    let cid_hashed = utils::get_digest(message_cbor.as_ref())?;

    let message_digest = Message::parse_slice(&cid_hashed)?;

    let (signature_rs, recovery_id) = sign(&message_digest, &secret_key);

    let mut signature = SignatureSECP256K1 { 0: [0; 65] };
    signature.0[..64].copy_from_slice(&signature_rs.serialize()[..]);
    signature.0[64] = recovery_id.serialize();

    Ok(signature)
}

fn transaction_sign_bls_raw(
    unsigned_message_api: &UnsignedMessageAPI,
    private_key: &PrivateKey,
) -> Result<SignatureBLS, SignerError> {
    let sk = bls_signatures::PrivateKey::from_bytes(&private_key.0)?;

    let unsigned_message = UnsignedMessage::try_from(unsigned_message_api)?;

    //sign the message's signing bytes
    let sig = sk.sign(unsigned_message.to_signing_bytes());

    Ok(SignatureBLS::try_from(sig.as_bytes())?)
}

/// Sign a transaction and return a raw signature (RSV format).
///
/// # Arguments
///
/// * `unsigned_message_api` - an unsigned filecoin message
/// * `private_key` - a `PrivateKey`
///
pub fn transaction_sign_raw(
    unsigned_message_api: &UnsignedMessageAPI,
    private_key: &PrivateKey,
) -> Result<Signature, SignerError> {
    // the `from` address protocol let us know which signing scheme to use
    let signature = match unsigned_message_api
        .from
        .as_bytes()
        .get(1)
        .ok_or_else(|| SignerError::GenericString("Empty signing protocol".into()))?
    {
        b'1' => Signature::SignatureSECP256K1(transaction_sign_secp56k1_raw(
            unsigned_message_api,
            private_key,
        )?),
        b'3' => {
            Signature::SignatureBLS(transaction_sign_bls_raw(unsigned_message_api, private_key)?)
        }
        _ => {
            return Err(SignerError::GenericString(
                "Unknown signing protocol".to_string(),
            ));
        }
    };

    Ok(signature)
}

/// Sign a transaction and return a signed message (message + signature).
///
/// # Arguments
///
/// * `unsigned_message_api` - an unsigned filecoin message
/// * `private_key` - a `PrivateKey`
///
pub fn transaction_sign(
    unsigned_message: &UnsignedMessageAPI,
    private_key: &PrivateKey,
) -> Result<SignedMessageAPI, SignerError> {
    let signature = transaction_sign_raw(unsigned_message, private_key)?;

    let signed_message = SignedMessageAPI {
        message: unsigned_message.to_owned(),
        signature: SignatureAPI::from(&signature),
    };

    Ok(signed_message)
}

fn verify_secp256k1_signature(
    signature: &SignatureSECP256K1,
    cbor_buffer: &CborBuffer,
) -> Result<bool, SignerError> {
    let network = Network::Testnet;

    let signature_rs = libsecp256k1::Signature::parse_standard_slice(&signature.0[..64])?;
    let recovery_id = RecoveryId::parse(signature.0[64])?;

    // Should be default network here
    // FIXME: For now only testnet
    let tx = transaction_parse(cbor_buffer, network == Network::Testnet)?;

    // Decode the CBOR transaction hex string into CBOR transaction buffer
    let message_digest = utils::get_digest(cbor_buffer.as_ref())?;

    let blob_to_sign = Message::parse_slice(&message_digest)?;

    let public_key = recover(&blob_to_sign, &signature_rs, &recovery_id)?;
    let mut from = Address::new_secp256k1(&public_key.serialize().to_vec())?;
    from.set_network(network);

    let tx_from = match tx {
        MessageTxAPI::UnsignedMessageAPI(tx) => tx.from,
        MessageTxAPI::SignedMessageAPI(tx) => tx.message.from,
    };
    let expected_from = from.to_string();

    // Compare recovered public key with the public key from the transaction
    if tx_from != expected_from {
        return Ok(false);
    }

    Ok(verify(&blob_to_sign, &signature_rs, &public_key))
}

fn verify_bls_signature(
    signature: &SignatureBLS,
    cbor_buffer: &CborBuffer,
) -> Result<bool, SignerError> {
    // TODO: need a function to extract from public key from cbor buffer directly
    let message = transaction_parse(cbor_buffer, true)?;
    let message = message.get_message();

    let address = Address::from_str(&message.from)?;

    let pk = bls_signatures::PublicKey::from_bytes(&address.payload_bytes())?;

    let sig = bls_signatures::Signature::from_bytes(signature.as_ref())?;

    let message = UnsignedMessage::try_from(&message)?;
    let signing_bytes = message.to_signing_bytes();

    let result = pk.verify(sig, signing_bytes);

    Ok(result)
}

/// Verify a signature. Return a boolean.
///
/// # Arguments
///
/// * `signature` - RSV format signature or BLS signature
/// * `cbor_buffer` - the CBOR transaction to verify the signature against
///
pub fn verify_signature(
    signature: &Signature,
    cbor_buffer: &CborBuffer,
) -> Result<bool, SignerError> {
    let result = match signature {
        Signature::SignatureSECP256K1(sig_secp256k1) => {
            verify_secp256k1_signature(sig_secp256k1, cbor_buffer)?
        }
        Signature::SignatureBLS(sig_bls) => verify_bls_signature(sig_bls, cbor_buffer)?,
    };

    Ok(result)
}

fn extract_from_pub_key_from_message(
    cbor_message: &CborBuffer,
) -> Result<bls_signatures::PublicKey, SignerError> {
    let message = transaction_parse(cbor_message, true)?;

    let unsigned_message_api = message.get_message();
    let from_address = Address::from_str(&unsigned_message_api.from)?;

    let pk = bls_signatures::PublicKey::from_bytes(&from_address.payload_bytes())?;

    Ok(pk)
}

fn extract_bls_signing_bytes_from_message(
    cbor_message: &CborBuffer,
) -> Result<Vec<u8>, SignerError> {
    let message = transaction_parse(cbor_message, true)?;

    let unsigned_message_api = message.get_message();
    let unsigned_message = UnsignedMessage::try_from(&unsigned_message_api)?;

    Ok(unsigned_message.to_signing_bytes())
}

pub fn verify_aggregated_signature(
    signature: &SignatureBLS,
    cbor_messages: &[CborBuffer],
) -> Result<bool, SignerError> {
    let sig = bls_signatures::Signature::from_bytes(signature.as_ref())?;

    // Get public keys from message
    let tmp: Result<Vec<_>, SignerError> = cbor_messages
        .iter()
        .map(|cbor_message| extract_from_pub_key_from_message(cbor_message))
        .collect();

    let pks = match tmp {
        Ok(public_keys) => public_keys,
        Err(_) => {
            return Err(SignerError::GenericString(
                "Invalid public key extracted from message".to_string(),
            ));
        }
    };

    // Hashes
    let tmp: Result<Vec<_>, SignerError> = cbor_messages
        .iter()
        .map(|cbor_message| extract_bls_signing_bytes_from_message(cbor_message))
        .collect();

    let signing_bytes = match tmp {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err(SignerError::GenericString(
                "An invalid message was provided".to_string(),
            ));
        }
    };

    let hashes = signing_bytes
        .par_iter()
        .map(|signing_bytes| bls_signatures::hash(signing_bytes.as_ref()))
        .collect::<Vec<_>>();

    Ok(bls_signatures::verify(&sig, &hashes, pks.as_slice()))
}

/// Utilitary function to create a create multisig message. Return an unsigned message.
///
/// # Arguments
///
/// * `sender_address` - A string address
/// * `addresses` - List of string addresses of the multisig
/// * `value` - Value to send on the multisig
/// * `required` - Number of required signatures required
/// * `nonce` - Nonce of the message
/// * `duration` - Duration of the multisig
///
#[allow(clippy::too_many_arguments)]
pub fn create_multisig(
    sender_address: String,
    addresses: Vec<String>,
    value: String,
    required: i64,
    nonce: u64,
    duration: i64,
    start_epoch: i64,
    gas_limit: i64,
    gas_fee_cap: String,
    gas_premium: String,
) -> Result<UnsignedMessageAPI, SignerError> {
    let signers_tmp: Result<Vec<Address>, _> = addresses
        .into_iter()
        .map(|address_string| Address::from_str(&address_string))
        .collect();

    let signers = match signers_tmp {
        Ok(signers) => signers,
        Err(_) => {
            return Err(SignerError::GenericString(
                "Failed to parse one of the signer addresses".to_string(),
            ));
        }
    };

    if duration < 0 && duration != -1 {
        return Err(SignerError::GenericString(
            "Invalid duration value (duration >= -1)".to_string(),
        ));
    };

    let constructor_params_multisig = multisig::ConstructorParams {
        signers,
        num_approvals_threshold: required,
        unlock_duration: duration,
        start_epoch,
    };

    let serialized_constructor_params = forest_vm::Serialized::serialize::<
        multisig::ConstructorParams,
    >(constructor_params_multisig)
    .map_err(|err| SignerError::GenericString(err.to_string()))?;

    let message_params_multisig = ExecParams {
        code_cid: Cid::new_v1(forest_cid::RAW, Identity.digest(b"fil/6/multisig")),
        constructor_params: serialized_constructor_params,
    };

    let serialized_params = forest_vm::Serialized::serialize::<ExecParams>(message_params_multisig)
        .map_err(|err| SignerError::GenericString(err.to_string()))?;

    let multisig_create_message_api = UnsignedMessageAPI {
        to: INIT_ACTOR_ADDR.to_string(),
        from: sender_address,
        nonce,
        value,
        gas_limit,
        gas_fee_cap,
        gas_premium,
        method: MethodInit::Exec as u64,
        params: base64::encode(serialized_params.bytes()),
    };

    Ok(multisig_create_message_api)
}

/// Utilitary function to create a proposal multisig message. Return an unsigned message.
///
/// # Arguments
///
/// * `multisig_address` - A string address
/// * `to_address` - A string address
/// * `from_address` - A string address
/// * `amount` - Amount of the transaction
/// * `nonce` - Nonce of the message
/// * `gas_limit` - The gas limit
/// * `gas_fee_cap` - The gas fee cap
/// * `gas_premium` - The gas premium
/// * `proposal_method` - The proposal method
/// * `proposal_serialized_params` - The proposal parameters serialized
///
#[allow(clippy::too_many_arguments)]
pub fn proposal_multisig_message(
    multisig_address: String,
    to_address: String,
    from_address: String,
    amount: String,
    nonce: u64,
    gas_limit: i64,
    gas_fee_cap: String,
    gas_premium: String,
    proposal_method: u64,
    proposal_serialized_params: String,
) -> Result<UnsignedMessageAPI, SignerError> {
    let propose_params_multisig = multisig::ProposeParams {
        to: Address::from_str(&to_address)?,
        value: BigInt::from_str(&amount)?,
        method: proposal_method,
        params: forest_vm::Serialized::new(base64::decode(proposal_serialized_params)?),
    };

    let params =
        forest_vm::Serialized::serialize::<multisig::ProposeParams>(propose_params_multisig)
            .map_err(|err| SignerError::GenericString(err.to_string()))?;

    let multisig_propose_message_api = UnsignedMessageAPI {
        to: multisig_address,
        from: from_address,
        nonce,
        value: "0".to_string(),
        gas_limit,
        gas_fee_cap,
        gas_premium,
        method: multisig::MethodMultisig::Propose as u64,
        params: base64::encode(params.bytes()),
    };

    Ok(multisig_propose_message_api)
}

#[allow(clippy::too_many_arguments)]
fn approve_or_cancel_multisig_message(
    method: u64,
    multisig_address: String,
    message_id: i64,
    proposer_address: String,
    to_address: String,
    amount: String,
    from_address: String,
    nonce: u64,
    gas_limit: i64,
    gas_fee_cap: String,
    gas_premium: String,
) -> Result<UnsignedMessageAPI, SignerError> {
    let proposal_parameter = multisig::ProposalHashData {
        requester: Address::from_str(&proposer_address)?,
        to: Address::from_str(&to_address)?,
        value: BigInt::from_str(&amount)?,
        method: 0,
        params: forest_vm::Serialized::new(Vec::new()),
    };

    let serialize_proposal_parameter =
        forest_vm::Serialized::serialize::<multisig::ProposalHashData>(proposal_parameter)
            .map_err(|err| SignerError::GenericString(err.to_string()))?;
    let proposal_hash = blake2b_256(&serialize_proposal_parameter);

    let params_txnid = multisig::TxnIDParams {
        id: multisig::TxnID(message_id),
        proposal_hash: proposal_hash.to_vec(),
    };

    let params = forest_vm::Serialized::serialize::<multisig::TxnIDParams>(params_txnid)
        .map_err(|err| SignerError::GenericString(err.to_string()))?;

    let multisig_unsigned_message_api = UnsignedMessageAPI {
        to: multisig_address,
        from: from_address,
        nonce,
        value: "0".to_string(),
        gas_limit,
        gas_fee_cap,
        gas_premium,
        method,
        params: base64::encode(params.bytes()),
    };

    Ok(multisig_unsigned_message_api)
}

/// Utilitary function to create an approve multisig message. Return an unsigned message.
///
/// # Arguments
///
/// * `multisig_address` - A string address
/// * `message_id` - message id
/// * `proposer_address` - A string address
/// * `to_address` - A string address
/// * `amount` - Amount of the transaction
/// * `from_address` - A string address
/// * `nonce` - Nonce of the message
///
#[allow(clippy::too_many_arguments)]
pub fn approve_multisig_message(
    multisig_address: String,
    message_id: i64,
    proposer_address: String,
    to_address: String,
    amount: String,
    from_address: String,
    nonce: u64,
    gas_limit: i64,
    gas_fee_cap: String,
    gas_premium: String,
) -> Result<UnsignedMessageAPI, SignerError> {
    approve_or_cancel_multisig_message(
        multisig::MethodMultisig::Approve as u64,
        multisig_address,
        message_id,
        proposer_address,
        to_address,
        amount,
        from_address,
        nonce,
        gas_limit,
        gas_fee_cap,
        gas_premium,
    )
}

/// Utilitary function to create a cancel multisig message. Return an unsigned message.
///
/// # Arguments
///
/// * `multisig_address` - A string address
/// * `message_id` - message id
/// * `proposer_address` - A string address
/// * `to_address` - A string address
/// * `amount` - Amount of the transaction
/// * `from_address` - A string address
/// * `nonce` - Nonce of the message
///
#[allow(clippy::too_many_arguments)]
pub fn cancel_multisig_message(
    multisig_address: String,
    message_id: i64,
    proposer_address: String,
    to_address: String,
    amount: String,
    from_address: String,
    nonce: u64,
    gas_limit: i64,
    gas_fee_cap: String,
    gas_premium: String,
) -> Result<UnsignedMessageAPI, SignerError> {
    approve_or_cancel_multisig_message(
        multisig::MethodMultisig::Cancel as u64,
        multisig_address,
        message_id,
        proposer_address,
        to_address,
        amount,
        from_address,
        nonce,
        gas_limit,
        gas_fee_cap,
        gas_premium,
    )
}

/// Utilitary function to serialize parameters of a message. Return a CBOR hexstring.
///
/// # Arguments
///
/// * `params` - Parameters to serialize

pub fn serialize_params(params: MessageParams) -> Result<CborBuffer, SignerError> {
    let serialized_params = params.serialize()?;
    let message_cbor = CborBuffer(serialized_params.bytes().to_vec());
    Ok(message_cbor)
}

/// Utility function to create a payment channel creation message.  Returns unsigned message.
///
/// # Arguments
///
/// * `from_address` - A string address
/// * `to_address` - A string address
/// * `value` - Amount to put in the payment channel initially
/// * `nonce` - Nonce of the message; should be from_address's MpoolGetNonce() value
///
pub fn create_pymtchan(
    from_address: String,
    to_address: String,
    value: String,
    nonce: u64,
    gas_limit: i64,
    gas_fee_cap: String,
    gas_premium: String,
) -> Result<UnsignedMessageAPI, SignerError> {
    let from = Address::from_str(&from_address)?;
    let to = Address::from_str(&to_address)?;

    let create_payment_channel_params = paych::ConstructorParams { from, to };

    let serialized_constructor_params =
        forest_vm::Serialized::serialize::<paych::ConstructorParams>(create_payment_channel_params)
            .map_err(|err| SignerError::GenericString(err.to_string()))?;

    let message_params_create_pymtchan = ExecParams {
        code_cid: Cid::new_v1(forest_cid::RAW, Identity.digest(b"fil/6/paymentchannel")),
        constructor_params: serialized_constructor_params,
    };

    let serialized_params =
        forest_vm::Serialized::serialize::<ExecParams>(message_params_create_pymtchan)
            .map_err(|err| SignerError::GenericString(err.to_string()))?;

    let mut init_actor_address = Address::from_str("f01")?;
    init_actor_address.set_network(from.network());

    let pch_create_message_api = UnsignedMessageAPI {
        to: init_actor_address.to_string(),
        from: from_address,
        nonce,
        value,
        gas_limit,
        gas_fee_cap,
        gas_premium,
        method: MethodInit::Exec as u64,
        params: base64::encode(serialized_params.bytes()),
    };

    Ok(pch_create_message_api)
}

/// Utility function to update the state of a payment channel.  Returns unsigned message.
///
/// # Arguments
///
/// * `pch_address` - A string address
/// * `from_address` - A string address
/// * `signed_voucher` - A SignedVoucher to be associated with the payment channel
/// * `nonce` - Nonce of the message; should be from_address's MpoolGetNonce() value
///
pub fn update_pymtchan(
    pch_address: String,
    from_address: String,
    signed_voucher: String,
    nonce: u64,
    gas_limit: i64,
    gas_fee_cap: String,
    gas_premium: String,
) -> Result<UnsignedMessageAPI, SignerError> {
    let sv_cbor = base64::decode(signed_voucher)?;

    let sv: paych::SignedVoucher = forest_encoding::from_slice(sv_cbor.as_ref())?;

    let update_payment_channel_params = paych::UpdateChannelStateParams { sv, secret: vec![] };

    let serialized_params = forest_vm::Serialized::serialize::<paych::UpdateChannelStateParams>(
        update_payment_channel_params,
    )
    .map_err(|err| SignerError::GenericString(err.to_string()))?;

    // TODO:  don't hardcode gas limit and gas price; use a gas estimator!
    let pch_update_message_api = UnsignedMessageAPI {
        to: pch_address, // INIT_ACTOR_ADDR
        from: from_address,
        nonce,
        value: "0".to_string(),
        gas_limit,
        gas_fee_cap,
        gas_premium,
        method: paych::MethodsPaych::UpdateChannelState as u64,
        params: base64::encode(serialized_params.bytes()),
    };

    Ok(pch_update_message_api)
}

/// Utility function to generate a payment channel settle message.  Returns unsigned message.
///
/// # Arguments
///
/// * `pch_address` - A string address
/// * `from_address` - A string address
/// * `nonce` - Nonce of the message; should be from_address's MpoolGetNonce() value
///
pub fn settle_pymtchan(
    pch_address: String,
    from_address: String,
    nonce: u64,
    gas_limit: i64,
    gas_fee_cap: String,
    gas_premium: String,
) -> Result<UnsignedMessageAPI, SignerError> {
    // TODO:  don't hardcode gas limit and gas price; use a gas estimator!
    let pch_settle_message_api = UnsignedMessageAPI {
        to: pch_address,
        from: from_address,
        nonce,
        value: "0".to_string(),
        gas_limit,
        gas_fee_cap,
        gas_premium,
        method: paych::MethodsPaych::Settle as u64,
        params: base64::encode(Vec::new()),
    };

    Ok(pch_settle_message_api)
}

/// Utility function to generate a payment channel collect message.  Returns unsigned message.
///
/// # Arguments
///
/// * `pch_address` - A string address
/// * `from_address` - A string address
/// * `nonce` - Nonce of the message; should be from_address's MpoolGetNonce() value
///
pub fn collect_pymtchan(
    pch_address: String,
    from_address: String,
    nonce: u64,
    gas_limit: i64,
    gas_fee_cap: String,
    gas_premium: String,
) -> Result<UnsignedMessageAPI, SignerError> {
    // TODO:  don't hardcode gas limit and gas price; use a gas estimator!
    let pch_collect_message_api = UnsignedMessageAPI {
        to: pch_address,
        from: from_address,
        nonce,
        value: "0".to_string(),
        gas_limit,
        gas_fee_cap,
        gas_premium,
        method: paych::MethodsPaych::Collect as u64,
        params: base64::encode(Vec::new()),
    };

    Ok(pch_collect_message_api)
}

/// Sign a voucher for payment channel
///
/// # Arguments
///
/// * `voucher_string` - Voucher as base64 string;
/// * `private_key` - Private key as base64 string;
///
pub fn sign_voucher(
    voucher_string: String,
    private_key: &PrivateKey,
) -> Result<String, SignerError> {
    let decoded_voucher = base64::decode(voucher_string)?;
    let mut voucher: paych::SignedVoucher = from_slice(&decoded_voucher)?;

    let secret_key = libsecp256k1::SecretKey::parse_slice(&private_key.0)?;

    let svb = voucher.signing_bytes()?;
    let digest = utils::get_digest_voucher(&svb)?;

    let blob_to_sign = Message::parse_slice(&digest)?;

    let (signature_rs, recovery_id) = sign(&blob_to_sign, &secret_key);

    let mut signature = SignatureSECP256K1 { 0: [0; 65] };
    signature.0[..64].copy_from_slice(&signature_rs.serialize()[..]);
    signature.0[64] = recovery_id.serialize();

    voucher.signature = Some(forest_crypto::signature::Signature::new_secp256k1(
        signature.0.to_vec(),
    ));

    let binary_voucher = to_vec(&voucher)?;
    let cbor_voucher = base64::encode(binary_voucher);

    Ok(cbor_voucher)
}

/// Create a voucher for payment channel
///
/// # Arguments
///
/// * `payment_channel_address` - The payment channel address;
/// * `time_lock_min` - Time lock min;
/// * `time_lock_maax` - Time lock max;
/// * `amount` - Amount in the voucher;
/// * `lane` - Lane of the voucher;
/// * `nonce` - Next nonce of the voucher;
///
pub fn create_voucher(
    payment_channel_address: String,
    time_lock_min: i64,
    time_lock_max: i64,
    amount: String,
    lane: u64,
    nonce: u64,
    min_settle_height: i64,
) -> Result<String, SignerError> {
    let pch = Address::from_str(&payment_channel_address)?;
    let amount = match BigInt::parse_bytes(amount.as_bytes(), 10) {
        Some(value) => value,
        None => {
            return Err(SignerError::GenericString(
                "`amount` couldn't be parsed.".to_string(),
            ));
        }
    };

    let voucher = paych::SignedVoucher {
        channel_addr: pch,
        time_lock_min,
        time_lock_max,
        secret_pre_image: Vec::new(),
        extra: None,
        lane,
        nonce,
        amount,
        min_settle_height,
        merges: Vec::new(),
        signature: None,
    };

    let cbor_voucher = base64::encode(to_vec(&voucher)?);

    Ok(cbor_voucher)
}

/// Deserialize Params
///
/// # Arguments
///
/// * `params_b64_string` - The base64 params string;
/// * `actor_type` - The string that tell the actor type;
/// * `method` - Method for which we want to deserialize the params;
pub fn deserialize_params(
    params_b64_string: String,
    actor_type: String,
    method: u64,
) -> Result<MessageParams, SignerError> {
    let params_decode = base64::decode(params_b64_string)?;
    let serialized_params = forest_vm::Serialized::new(params_decode);

    match actor_type.as_str() {
        "fil/1/init" | "fil/2/init" | "fil/3/init" | "fil/4/init" | "fil/5/init" | "fil/6/init" => {
            match FromPrimitive::from_u64(method) {
                Some(MethodInit::Exec) => {
                    let params = serialized_params.deserialize::<ExecParams>()?;

                    Ok(MessageParams::MessageParamsMultisig(params.into()))
                }
                _ => Err(SignerError::GenericString(
                    "Unknown method for actor 'fil/2/init', 'fil/3/init', 'fil/4/init', 'fil/5/init' or 'fil/6/init' ."
                        .to_string(),
                )),
            }
        }
        "fil/2/multisig" | "fil/3/multisig" | "fil/4/multisig" | "fil/5/multisig" | "fil/6/multisig" => {
            match FromPrimitive::from_u64(method) {
                Some(multisig::MethodMultisig::Propose) => {
                    let params = serialized_params.deserialize::<multisig::ProposeParams>()?;

                    Ok(MessageParams::ProposeParamsMultisig(params.into()))
                }
                Some(multisig::MethodMultisig::Approve) | Some(multisig::MethodMultisig::Cancel) => {
                    let params = serialized_params.deserialize::<multisig::TxnIDParams>()?;

                    Ok(MessageParams::TxnIDParamsMultisig(params.into()))
                }
                Some(multisig::MethodMultisig::AddSigner) => {
                    let params = serialized_params.deserialize::<multisig::AddSignerParams>()?;

                    Ok(MessageParams::AddSignerMultisigParams(params.into()))
                }
                Some(multisig::MethodMultisig::RemoveSigner) => {
                    let params = serialized_params.deserialize::<multisig::RemoveSignerParams>()?;

                    Ok(MessageParams::RemoveSignerMultisigParams(params.into()))
                }
                Some(multisig::MethodMultisig::SwapSigner) => {
                    let params = serialized_params.deserialize::<multisig::SwapSignerParams>()?;

                    Ok(MessageParams::SwapSignerMultisigParams(params.into()))
                }
                Some(multisig::MethodMultisig::ChangeNumApprovalsThreshold) => {
                    let params = serialized_params
                        .deserialize::<multisig::ChangeNumApprovalsThresholdParams>()?;

                    Ok(MessageParams::ChangeNumApprovalsThresholdMultisigParams(
                        params.into(),
                    ))
                }
                Some(multisig::MethodMultisig::LockBalance) => {
                    let params = serialized_params.deserialize::<multisig::LockBalanceParams>()?;

                    Ok(MessageParams::LockBalanceMultisigParams(params.into()))
                }
                _ => Err(SignerError::GenericString(
                    "Unknown method for actor 'fil/2/multisig', 'fil/3/multisig', 'fil/4/multisig', 'fil/5/multisig' or 'fil/6/multisig'.".to_string(),
                )),
            }
        }
        "fil/2/paymentchannel" | "fil/3/paymentchannel" | "fil/4/paymentchannel" | "fil/5/paymentchannel" | "fil/6/paymentchannel" => {
            match FromPrimitive::from_u64(method) {
                Some(paych::MethodsPaych::UpdateChannelState) => {
                    let params =
                        serialized_params.deserialize::<paych::UpdateChannelStateParams>()?;

                    Ok(MessageParams::PaymentChannelUpdateStateParams(
                        params.try_into()?,
                    ))
                }
                Some(paych::MethodsPaych::Settle) | Some(paych::MethodsPaych::Collect) => {
                    /* Note : those method doesn't have params to decode */
                    Ok(MessageParams::MessageParamsSerialized("".to_string()))
                }
                _ => Err(SignerError::GenericString(
                    "Unknown method fo actor 'fil/2/paymentchannel', 'fil/3/paymentchannel', 'fil/4/paymentchannel', fil/5/paymentchannel or fil/6/paymentchannel'."
                        .to_string(),
                )),
            }
        }
        _ => Err(SignerError::GenericString(
            "Actor type not supported.".to_string(),
        )),
    }
}

/// Deserialize Constructor Params
///
/// # Arguments
///
/// * `params_b64_string` - The base64 params string;
/// * `code_cid` - The string that tell the actor type which is being crated with this parameters;
pub fn deserialize_constructor_params(
    params_b64_string: String,
    code_cid: String,
) -> Result<MessageParams, SignerError> {
    let params_decode = base64::decode(params_b64_string)?;
    let serialized_params = forest_vm::Serialized::new(params_decode);

    match code_cid.as_str() {
        "fil/2/multisig" | "fil/3/multisig" | "fil/4/multisig" | "fil/5/multisig"
        | "fil/6/multisig" => {
            let params = serialized_params.deserialize::<multisig::ConstructorParams>()?;
            Ok(MessageParams::ConstructorParamsMultisig(params.into()))
        }
        "fil/2/paymentchannel"
        | "fil/3/paymentchannel"
        | "fil/4/paymentchannel"
        | "fil/5/paymentchannel"
        | "fil/6/paymentchannel" => {
            let params = serialized_params.deserialize::<paych::ConstructorParams>()?;
            Ok(MessageParams::PaymentChannelCreateParams(params.into()))
        }
        "fil/1/multisig" => {
            let deprecated_multisig_params =
                serialized_params.deserialize::<multisig::ConstructorParamsV1>()?;
            let params = multisig::ConstructorParams {
                signers: deprecated_multisig_params.signers,
                num_approvals_threshold: deprecated_multisig_params.num_approvals_threshold,
                unlock_duration: deprecated_multisig_params.unlock_duration,
                start_epoch: 0,
            };
            Ok(MessageParams::ConstructorParamsMultisig(params.into()))
        }
        _ => Err(SignerError::GenericString(
            "Code CID not supported.".to_string(),
        )),
    }
}

/// Verify Voucher signature
///
/// # Arguments
///
/// * `voucher_base64_string` - The voucher as a base64 string;
/// * `address_signer` - The address matching the private key that signed the voucher;
pub fn verify_voucher_signature(
    voucher_base64_string: String,
    address_signer: String,
) -> Result<bool, SignerError> {
    let decoded_voucher = base64::decode(voucher_base64_string)?;
    let signed_voucher: paych::SignedVoucher = from_slice(&decoded_voucher)?;

    let address = Address::from_str(&address_signer)?;

    let sv_bytes = signed_voucher.signing_bytes()?;
    let digest = utils::get_digest_voucher(&sv_bytes)?;

    match &signed_voucher.signature {
        Some(signature) => match address.protocol() {
            Protocol::Secp256k1 => {
                let sig = libsecp256k1::Signature::parse_standard_slice(&signature.bytes()[..64])?;
                let recovery_id = RecoveryId::parse(signature.bytes()[64])?;
                let message = libsecp256k1::Message::parse(&digest);
                let public_key = recover(&message, &sig, &recovery_id)?;
                let mut signer = Address::new_secp256k1(&public_key.serialize().to_vec())?;
                signer.set_network(address.network());

                if signer.to_string() != address.to_string() {
                    Err(SignerError::GenericString(
                        "Address recovered doesn't match address given".to_string(),
                    ))
                } else {
                    Ok(verify(&message, &sig, &public_key))
                }
            }
            Protocol::BLS => {
                let pk = bls_signatures::PublicKey::from_bytes(&address.payload_bytes())?;
                let sig = bls_signatures::Signature::from_bytes(signature.bytes())?;

                Ok(pk.verify(sig, digest))
            }
            _ => Err(SignerError::GenericString(
                "Address should BLS or Secp256k1.".to_string(),
            )),
        },
        None => Err(SignerError::GenericString(
            "Voucher not signed.".to_string(),
        )),
    }
}

/// Return the CID of a message
///
/// # Arguments
///
/// * `message_api` - The message;
pub fn get_cid(message_api: MessageTxAPI) -> Result<String, SignerError> {
    use forest_encoding::Cbor;

    match message_api {
        MessageTxAPI::UnsignedMessageAPI(unsigned) => {
            let unsigned_message = UnsignedMessage::try_from(&unsigned)?;
            let cid = unsigned_message.cid()?;

            Ok(cid.to_string())
        }
        MessageTxAPI::SignedMessageAPI(signed) => {
            let signed_message = SignedMessage::try_from(&signed)?;
            let cid = signed_message.cid()?;

            Ok(cid.to_string())
        }
    }
}
