#![cfg_attr(
    not(test),
    deny(
        clippy::option_unwrap_used,
        clippy::option_expect_used,
        clippy::result_unwrap_used,
        clippy::result_expect_used,
    )
)]

use crate::api::{
    MessageParams, MessageTx, MessageTxAPI, MessageTxNetwork, SignatureAPI, SignedMessageAPI,
    UnsignedMessageAPI,
};
use crate::error::SignerError;
use extras::{
    ConstructorParams, ExecParams, MethodInit, MethodMultisig, ProposalHashData, ProposeParams,
    TxnID, TxnIDParams, INIT_ACTOR_ADDR,
};
use forest_address::{Address, Network};
use forest_cid::{multihash::Identity, Cid, Codec};
use forest_encoding::blake2b_256;
use forest_encoding::{from_slice, to_vec};
use num_bigint_chainsafe::BigUint;
use std::convert::TryFrom;
use std::str::FromStr;

use crate::extended_key::ExtendedSecretKey;
use bip39::{Language, MnemonicType, Seed};
use bls_signatures::Serialize;
use rayon::prelude::*;
use secp256k1::util::{
    COMPRESSED_PUBLIC_KEY_SIZE, FULL_PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SIGNATURE_SIZE,
};
use secp256k1::{recover, sign, verify, Message, RecoveryId};
use zx_bip44::BIP44Path;

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

/// Private key buffer
pub struct PrivateKey(pub [u8; SECRET_KEY_SIZE]);

/// Public key buffer
pub struct PublicKey(pub [u8; FULL_PUBLIC_KEY_SIZE]);

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

/// Returns a public key, private key and address given a mnemonic, derivation path and a password
///
/// # Arguments
///
/// * `mnemonic` - A string containing a 24-words English mnemonic
/// * `path` - A string containing a derivation path
/// * `password` - Password to decrypt seed, if none use and empty string (e.g "")
pub fn key_derive(mnemonic: &str, path: &str, password: &str) -> Result<ExtendedKey, SignerError> {
    let mnemonic = bip39::Mnemonic::from_phrase(&mnemonic, Language::English)
        .map_err(|err| SignerError::GenericString(err.to_string()))?;

    let seed = Seed::new(&mnemonic, password);

    let master = ExtendedSecretKey::try_from(seed.as_bytes())?;

    let bip44_path = BIP44Path::from_string(path)?;

    let esk = master.derive_bip44(&bip44_path)?;

    let mut address = Address::new_secp256k1(&esk.public_key().to_vec())?;

    address.set_network(Network::Mainnet);
    if bip44_path.is_testnet() {
        address.set_network(Network::Testnet);
    }

    Ok(ExtendedKey {
        private_key: PrivateKey(esk.secret_key()),
        public_key: PublicKey(esk.public_key()),
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
    let master = ExtendedSecretKey::try_from(seed)?;

    let bip44_path = BIP44Path::from_string(path)?;

    let esk = master.derive_bip44(&bip44_path)?;

    let mut address = Address::new_secp256k1(&esk.public_key().to_vec())?;

    address.set_network(Network::Mainnet);
    if bip44_path.is_testnet() {
        address.set_network(Network::Testnet);
    }

    Ok(ExtendedKey {
        private_key: PrivateKey(esk.secret_key()),
        public_key: PublicKey(esk.public_key()),
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
    let secret_key = secp256k1::SecretKey::parse_slice(&private_key.0)?;
    let public_key = secp256k1::PublicKey::from_secret_key(&secret_key);
    let mut address = Address::new_secp256k1(&public_key.serialize())?;

    if testnet {
        address.set_network(Network::Testnet);
    } else {
        address.set_network(Network::Mainnet);
    }

    Ok(ExtendedKey {
        private_key: PrivateKey(secret_key.serialize()),
        public_key: PublicKey(public_key.serialize()),
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
    let unsigned_message = forest_message::UnsignedMessage::try_from(unsigned_message_arg)?;
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

    let secret_key = secp256k1::SecretKey::parse_slice(&private_key.0)?;

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
    let message_cbor = transaction_serialize(unsigned_message_api)?;

    let sk = bls_signatures::PrivateKey::from_bytes(&private_key.0)?;
    let sig = sk.sign(&message_cbor.0);

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
        .ok_or(SignerError::GenericString("Empty signing protocol".into()))?
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

    let signature_rs = secp256k1::Signature::parse_slice(&signature.0[..64])?;
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

    let pk = bls_signatures::PublicKey::from_bytes(message.get_message().from.as_bytes())?;

    let sig = bls_signatures::Signature::from_bytes(signature.as_ref())?;

    let result = pk.verify(sig, cbor_buffer.as_ref());

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
    let hashes: Vec<_> = cbor_messages
        .par_iter()
        .map(|cbor_message| bls_signatures::hash(cbor_message.as_ref()))
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
pub fn create_multisig(
    sender_address: String,
    addresses: Vec<String>,
    value: String,
    required: i64,
    nonce: u64,
    duration: i64,
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

    let constructor_params_multisig = ConstructorParams {
        signers: signers,
        num_approvals_threshold: required,
        unlock_duration: duration,
    };

    let serialized_constructor_params =
        forest_vm::Serialized::serialize::<ConstructorParams>(constructor_params_multisig)
            .map_err(|err| SignerError::GenericString(err.to_string()))?;

    let message_params_multisig = ExecParams {
        code_cid: Cid::new_v1(Codec::Raw, Identity::digest(b"fil/1/multisig")),
        constructor_params: serialized_constructor_params,
    };

    let serialized_params = forest_vm::Serialized::serialize::<ExecParams>(message_params_multisig)
        .map_err(|err| SignerError::GenericString(err.to_string()))?;

    let multisig_create_message_api = UnsignedMessageAPI {
        to: INIT_ACTOR_ADDR.to_string(),
        from: sender_address,
        nonce,
        value,
        // https://github.com/filecoin-project/lotus/blob/596ed330dda83eac0f6e9c010ef7ada9e543369b/node/impl/full/multisig.go#L46
        gas_price: "1".to_string(),
        // used the same value as https://github.com/filecoin-project/lotus/blob/596ed330dda83eac0f6e9c010ef7ada9e543369b/node/impl/full/multisig.go#L78
        gas_limit: 1000000,
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
///
pub fn proposal_multisig_message(
    multisig_address: String,
    to_address: String,
    from_address: String,
    amount: String,
    nonce: u64,
) -> Result<UnsignedMessageAPI, SignerError> {
    let propose_params_multisig = ProposeParams {
        to: Address::from_str(&to_address)?,
        value: BigUint::from_str(&amount)?,
        method: 0,
        params: forest_vm::Serialized::new(Vec::new()),
    };

    let params = forest_vm::Serialized::serialize::<ProposeParams>(propose_params_multisig)
        .map_err(|err| SignerError::GenericString(err.to_string()))?;

    let multisig_propose_message_api = UnsignedMessageAPI {
        to: multisig_address,
        from: from_address,
        nonce,
        value: "0".to_string(),
        // https://github.com/filecoin-project/lotus/blob/596ed330dda83eac0f6e9c010ef7ada9e543369b/node/impl/full/multisig.go#L46
        gas_price: "1".to_string(),
        // used the same value as https://github.com/filecoin-project/lotus/blob/596ed330dda83eac0f6e9c010ef7ada9e543369b/node/impl/full/multisig.go#L78
        gas_limit: 1000000,
        method: MethodMultisig::Propose as u64,
        params: base64::encode(params.bytes()),
    };

    Ok(multisig_propose_message_api)
}

fn approve_or_cancel_multisig_message(
    method: u64,
    multisig_address: String,
    message_id: i64,
    proposer_address: String,
    to_address: String,
    amount: String,
    from_address: String,
    nonce: u64,
) -> Result<UnsignedMessageAPI, SignerError> {
    let proposal_parameter = ProposalHashData {
        requester: Address::from_str(&proposer_address)?,
        to: Address::from_str(&to_address)?,
        value: BigUint::from_str(&amount)?,
        method: 0,
        params: forest_vm::Serialized::new(Vec::new()),
    };

    let serialize_proposal_parameter =
        forest_vm::Serialized::serialize::<ProposalHashData>(proposal_parameter)
            .map_err(|err| SignerError::GenericString(err.to_string()))?;
    let proposal_hash = blake2b_256(&serialize_proposal_parameter);

    let params_txnid = TxnIDParams {
        id: TxnID(message_id),
        proposal_hash,
    };

    let params = forest_vm::Serialized::serialize::<TxnIDParams>(params_txnid)
        .map_err(|err| SignerError::GenericString(err.to_string()))?;

    let multisig_unsigned_message_api = UnsignedMessageAPI {
        to: multisig_address,
        from: from_address,
        nonce,
        value: "0".to_string(),
        gas_price: "1".to_string(),
        gas_limit: 1000000,
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
pub fn approve_multisig_message(
    multisig_address: String,
    message_id: i64,
    proposer_address: String,
    to_address: String,
    amount: String,
    from_address: String,
    nonce: u64,
) -> Result<UnsignedMessageAPI, SignerError> {
    approve_or_cancel_multisig_message(
        MethodMultisig::Approve as u64,
        multisig_address,
        message_id,
        proposer_address,
        to_address,
        amount,
        from_address,
        nonce,
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
pub fn cancel_multisig_message(
    multisig_address: String,
    message_id: i64,
    proposer_address: String,
    to_address: String,
    amount: String,
    from_address: String,
    nonce: u64,
) -> Result<UnsignedMessageAPI, SignerError> {
    approve_or_cancel_multisig_message(
        MethodMultisig::Cancel as u64,
        multisig_address,
        message_id,
        proposer_address,
        to_address,
        amount,
        from_address,
        nonce,
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
    from_address: &str,
    to_address: &str,
    value: String,
    nonce: u64,
) -> Result<UnsignedMessageAPI, SignerError> {
    let create_payment_channel_params = PaymentChannelCreateParams { 
        from: from_address.to_owned(),
        to: to_address.to_owned(),
    };

    let message_params_create_pymtchan = MessageParamsPaymentChannelCreate {
        code_cid: "fil/1/paymentchannel".to_string(),
        pch_constructor_params: create_payment_channel_params,
    };

    // TODO:  don't hardcode gas limit and gas price; use a gas estimator!
    let pch_create_message_api = UnsignedMessageAPI {
        to: "t01".to_owned(),            // INIT_ACTOR_ADDR
        from: from_address.to_owned(),
        nonce,
        value,
        // Next two based on https://github.com/filecoin-project/lotus/blob/fe4efa0e0ee045d38f63f4955d01cbf3e36bc41f/paychmgr/simple.go#L40
        gas_price: "100".to_string(),
        gas_limit: 200000000,
        method: MethodInit::Exec as u64,
        params: MessageParams::MessageParamsPaymentChannelCreate(message_params_create_pymtchan),
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
    pch_address: &str,
    from_address: &str,
    signed_voucher: &SignedVoucher,
    nonce: u64,
) -> Result<UnsignedMessageAPI, SignerError> {
    let update_payment_channel_params = PaymentChannelUpdateStateParams { 
        sv: signed_voucher.into(),
        secret: vec![],
        proof: vec![],
    };

    // TODO:  don't hardcode gas limit and gas price; use a gas estimator!
    let pch_update_message_api = UnsignedMessageAPI {
        to: from_address.to_owned(),            // INIT_ACTOR_ADDR
        from: pch_address.to_owned(),
        nonce,
        value: "0".to_owned(),
        // Next two based on https://github.com/filecoin-project/lotus/blob/fe4efa0e0ee045d38f63f4955d01cbf3e36bc41f/paychmgr/simple.go#L40
        gas_price: "100".to_string(),
        gas_limit: 200000000,
        method: MethodsPaych::UpdateChannelState as u64,
        params: MessageParams::PaymentChannelUpdateStateParams(update_payment_channel_params),
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
    pch_address: &str,
    from_address: &str,
    nonce: u64,
) -> Result<UnsignedMessageAPI, SignerError> {
    // TODO:  don't hardcode gas limit and gas price; use a gas estimator!
    let pch_settle_message_api = UnsignedMessageAPI {
        to: pch_address.to_owned(),
        from: from_address.to_owned(),
        nonce: nonce,
        value: "0".to_string(),
        // Next two based on https://github.com/filecoin-project/lotus/blob/fe4efa0e0ee045d38f63f4955d01cbf3e36bc41f/paychmgr/simple.go#L40
        gas_price: "0".to_string(),
        gas_limit: 20000000,
        method: MethodsPaych::Settle as u64,
        params: MessageParams::MessageParamsSerialized("".to_string()),
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
    pch_address: &str,
    from_address: &str,
    nonce: u64,
) -> Result<UnsignedMessageAPI, SignerError> {
    // TODO:  don't hardcode gas limit and gas price; use a gas estimator!
    let pch_collect_message_api = UnsignedMessageAPI {
        to: pch_address.to_owned(),
        from: from_address.to_owned(),
        nonce: nonce,
        value: "0".to_string(),
        // Next two based on https://github.com/filecoin-project/lotus/blob/fe4efa0e0ee045d38f63f4955d01cbf3e36bc41f/paychmgr/simple.go#L40
        gas_price: "0".to_string(),
        gas_limit: 20000000,
        method: MethodsPaych::Collect as u64,
        params: MessageParams::MessageParamsSerialized("".to_string()),
    };

    Ok(pch_collect_message_api)
}

#[cfg(test)]
mod tests {
    use crate::api::{
        ConstructorParamsMultisig, MessageParams, MessageParamsMultisig, 
        MessageParamsPaymentChannelCreate, MessageTxAPI, UnsignedMessageAPI, 
        PaymentChannelCreateParams, PaymentChannelUpdateStateParams, SignedVoucher,
        SpecsActorsCryptoSignature,
    };
    use crate::signature::{Signature, SignatureBLS};
    use crate::{
        approve_multisig_message, cancel_multisig_message, create_multisig, key_derive,
        key_derive_from_seed, key_generate_mnemonic, key_recover, proposal_multisig_message,
        serialize_params, transaction_parse, transaction_serialize, transaction_sign_bls_raw,
        transaction_sign_raw, verify_aggregated_signature, verify_signature, create_pymtchan, CborBuffer, Mnemonic,
        PrivateKey,
    };
    use bip39::{Language, Seed};
    use forest_encoding::blake2b_256;
    use forest_encoding::to_vec;
    use std::convert::TryFrom;

    use bls_signatures::Serialize;
    use forest_address::Address;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use rayon::prelude::*;
    use regex::Regex;

    const BLS_PUBKEY: &str = "ade28c91045e89a0dcdb49d5ed0d62a4f02d78a96dbd406a4f9d37a1cd2fb5c29058def79b01b4d1556ade74ffc07904";
    const BLS_PRIVATEKEY: &str = "0x7Y0GGX92MeWBF9mcWuR5EYPxe2dy60r8XIQOD31BI=";

    // NOTE: not the same transaction used in other tests.
    const EXAMPLE_UNSIGNED_MESSAGE: &str = r#"
        {
            "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
            "from": "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
            "nonce": 1,
            "value": "100000",
            "gasprice": "2500",
            "gaslimit": 25000,
            "method": 0,
            "params": ""
        }"#;

    const EXAMPLE_CBOR_DATA: &str =
        "89005501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855011eaf1c8a4bbfeeb0870b1745b1f57503470b71160144000186a0430009c41961a80040";

    /* signed message :
    [
        // Unsigned message part
        [0,h'01FD1D0F4DFCD7E99AFCB99A8326B7DC459D32C628', h'010F323F4709E8E4DB0C1D4CD374F9F35201D26FB2', 1, h'000186A0', h'0009C4', 2500, 0, h''],
        // Signed message part (messageType + SignatureRS + recoverID)
        h'01be9aed6bd3b0493ab8559590f61dc124614e3174d369649fe461a218bab4193651f275f0a3e0c3ce67d6ef5780bba10574be5a2dbb4f1490efc71463fd95d33c01']
    */
    const SIGNED_MESSAGE_CBOR: &str =
        "8289005501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c62855011eaf1c8a4bbfeeb0870b1745b1f57503470b71160144000186a0430009c41909c4004058420106398485060ca2a4deb97027f518f45569360c3873a4303926fa6909a7299d4c55883463120836358ff3396882ee0dc2cf15961bd495cdfb3de1ee2e8bd3768e01";

    const EXAMPLE_PRIVATE_KEY: &str = "8VcW07ADswS4BV2cxi5rnIadVsyTDDhY1NfDH19T8Uo=";

    #[test]
    fn decode_key() {
        let pk = PrivateKey::try_from(EXAMPLE_PRIVATE_KEY.to_string()).unwrap();
        assert_eq!(base64::encode(&pk.0), EXAMPLE_PRIVATE_KEY);
    }

    #[test]
    fn generate_mnemonic() {
        let mnemonic = key_generate_mnemonic().expect("could not generate mnemonic");
        println!("{}", mnemonic.0);

        let word_count = mnemonic.0.split_ascii_whitespace().count();
        assert_eq!(word_count, 24)
    }

    #[test]
    fn derive_key() {
        let mnemonic = "equip will roof matter pink blind book anxiety banner elbow sun young";

        let extended_key = key_derive(mnemonic, "m/44'/461'/0/0/0", "").unwrap();

        assert_eq!(
            base64::encode(&extended_key.private_key.0),
            EXAMPLE_PRIVATE_KEY
        );
    }

    #[test]
    fn derive_key_password() {
        let mnemonic = "equip will roof matter pink blind book anxiety banner elbow sun young";

        let m = bip39::Mnemonic::from_phrase(&mnemonic.to_string(), Language::English).unwrap();

        let seed = Seed::new(&m, "password");

        let extended_key_expected =
            key_derive_from_seed(seed.as_bytes(), "m/44'/461'/0/0/0").unwrap();

        let extended_key = key_derive(mnemonic, "m/44'/461'/0/0/0", "password").unwrap();

        assert_eq!(
            base64::encode(&extended_key.private_key.0),
            base64::encode(&extended_key_expected.private_key.0)
        );
    }

    #[test]
    fn derive_key_from_seed() {
        let mnemonic = Mnemonic(
            "equip will roof matter pink blind book anxiety banner elbow sun young".to_string(),
        );

        let mnemonic = bip39::Mnemonic::from_phrase(&mnemonic.0, Language::English).unwrap();

        let seed = Seed::new(&mnemonic, "");

        let extended_key = key_derive_from_seed(seed.as_bytes(), "m/44'/461'/0/0/0").unwrap();

        assert_eq!(
            base64::encode(&extended_key.private_key.0),
            EXAMPLE_PRIVATE_KEY
        );
    }

    #[test]
    fn test_key_recover_testnet() {
        let private_key = PrivateKey::try_from(EXAMPLE_PRIVATE_KEY.to_string()).unwrap();
        let testnet = true;

        let recovered_key = key_recover(&private_key, testnet).unwrap();

        assert_eq!(
            base64::encode(&recovered_key.private_key.0),
            EXAMPLE_PRIVATE_KEY
        );

        assert_eq!(
            &recovered_key.address,
            "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"
        );
    }

    #[test]
    fn test_key_recover_mainnet() {
        let private_key = PrivateKey::try_from(EXAMPLE_PRIVATE_KEY.to_string()).unwrap();
        let testnet = false;

        let recovered_key = key_recover(&private_key, testnet).unwrap();

        assert_eq!(
            base64::encode(&recovered_key.private_key.0),
            EXAMPLE_PRIVATE_KEY
        );

        assert_eq!(
            &recovered_key.address,
            "f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba"
        );
    }

    #[test]
    fn parse_unsigned_transaction() {
        let cbor_data = CborBuffer(hex::decode(EXAMPLE_CBOR_DATA).unwrap());

        let unsigned_tx = transaction_parse(&cbor_data, true).expect("FIX ME");
        let to = match unsigned_tx {
            MessageTxAPI::UnsignedMessageAPI(tx) => tx.to,
            MessageTxAPI::SignedMessageAPI(_) => panic!("Should be a Unsigned Message!"),
        };

        println!("{}", to);
        assert_eq!(to, "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy".to_string());
    }

    #[test]
    fn parse_signed_transaction() {
        let cbor_data = CborBuffer(hex::decode(SIGNED_MESSAGE_CBOR).unwrap());

        let signed_tx = transaction_parse(&cbor_data, true).expect("Could not parse");
        let signature = match signed_tx {
            MessageTxAPI::UnsignedMessageAPI(_) => panic!("Should be a Signed Message!"),
            MessageTxAPI::SignedMessageAPI(tx) => tx.signature,
        };

        assert_eq!(
            hex::encode(&signature.data),
            "06398485060ca2a4deb97027f518f45569360c3873a4303926fa6909a7299d4c55883463120836358ff3396882ee0dc2cf15961bd495cdfb3de1ee2e8bd3768e01".to_string()
        );
    }

    #[test]
    fn parse_transaction_with_network() {
        let cbor_data = CborBuffer(hex::decode(EXAMPLE_CBOR_DATA).unwrap());

        let unsigned_tx_mainnet = transaction_parse(&cbor_data, false).expect("Could not parse");
        let (to, from) = match unsigned_tx_mainnet {
            MessageTxAPI::UnsignedMessageAPI(tx) => (tx.to, tx.from),
            MessageTxAPI::SignedMessageAPI(_) => panic!("Should be a Unsigned Message!"),
        };

        println!("{}", to);
        assert_eq!(to, "f17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy".to_string());
        assert_eq!(
            from,
            "f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba".to_string()
        );
    }

    #[test]
    fn parse_transaction_with_network_testnet() {
        let cbor_data = CborBuffer(hex::decode(EXAMPLE_CBOR_DATA).unwrap());

        let unsigned_tx_testnet = transaction_parse(&cbor_data, true).expect("Could not parse");
        let (to, from) = match unsigned_tx_testnet {
            MessageTxAPI::UnsignedMessageAPI(tx) => (tx.to, tx.from),
            MessageTxAPI::SignedMessageAPI(_) => panic!("Should be a Unsigned Message!"),
        };

        println!("{}", to);
        assert_eq!(to, "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy".to_string());
        assert_eq!(
            from,
            "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba".to_string()
        );
    }

    #[test]
    fn parse_transaction_signed_with_network() {
        let cbor_data = CborBuffer(hex::decode(SIGNED_MESSAGE_CBOR).unwrap());

        let signed_tx_mainnet = transaction_parse(&cbor_data, false).expect("Could not parse");
        let (to, from) = match signed_tx_mainnet {
            MessageTxAPI::UnsignedMessageAPI(_) => panic!("Should be a Signed Message!"),
            MessageTxAPI::SignedMessageAPI(tx) => (tx.message.to, tx.message.from),
        };

        println!("{}", to);
        assert_eq!(to, "f17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy".to_string());
        assert_eq!(
            from,
            "f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba".to_string()
        );
    }

    #[test]
    fn parse_transaction_signed_with_network_testnet() {
        let cbor_data = CborBuffer(hex::decode(SIGNED_MESSAGE_CBOR).unwrap());

        let signed_tx_testnet = transaction_parse(&cbor_data, true).expect("Could not parse");
        let (to, from) = match signed_tx_testnet {
            MessageTxAPI::UnsignedMessageAPI(_) => panic!("Should be a Signed Message!"),
            MessageTxAPI::SignedMessageAPI(tx) => (tx.message.to, tx.message.from),
        };

        assert_eq!(to, "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy".to_string());
        assert_eq!(
            from,
            "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba".to_string()
        );
    }

    #[test]
    fn verify_invalid_signature() {
        // Path 44'/461'/0/0/0
        let private_key = PrivateKey::try_from(EXAMPLE_PRIVATE_KEY.to_string()).unwrap();
        let message_user_api: UnsignedMessageAPI = serde_json::from_str(EXAMPLE_UNSIGNED_MESSAGE)
            .expect("Could not serialize unsigned message");

        // Sign
        let signature = transaction_sign_raw(&message_user_api, &private_key).unwrap();

        // Verify
        let message = forest_message::UnsignedMessage::try_from(&message_user_api)
            .expect("Could not serialize unsigned message");
        let message_cbor = CborBuffer(to_vec(&message).unwrap());

        let valid_signature = verify_signature(&signature, &message_cbor);
        assert!(valid_signature.unwrap());

        // Tampered signature and look if it valid
        let mut sig = signature.as_bytes();
        sig[5] = 0x01;
        sig[34] = 0x00;

        let tampered_signature = Signature::try_from(sig).expect("FIX ME");

        let valid_signature = verify_signature(&tampered_signature, &message_cbor);
        assert!(valid_signature.is_err() || !valid_signature.unwrap());
    }

    #[test]
    fn sign_bls_transaction() {
        // Get address
        let bls_pubkey = hex::decode(BLS_PUBKEY).unwrap();
        let bls_address = Address::new_bls(bls_pubkey.as_slice()).unwrap();

        // Get BLS private key
        let bls_key = PrivateKey::try_from(BLS_PRIVATEKEY.to_string()).unwrap();

        println!("{}", bls_address.to_string());

        // Prepare message with BLS address
        let message = UnsignedMessageAPI {
            to: "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy".to_string(),
            from: bls_address.to_string(),
            nonce: 1,
            value: "100000".to_string(),
            gas_price: "2500".to_string(),
            gas_limit: 25000,
            method: 0,
            params: "".to_string(),
        };

        let raw_sig = transaction_sign_bls_raw(&message, &bls_key).unwrap();
        let sig = bls_signatures::Signature::from_bytes(&raw_sig.0).expect("FIX ME");

        let bls_pk =
            bls_signatures::PublicKey::from_bytes(&hex::decode(BLS_PUBKEY).unwrap()).unwrap();

        let message_cbor = transaction_serialize(&message).expect("FIX ME");

        assert!(bls_pk.verify(sig, &message_cbor));
    }

    #[test]
    fn test_verify_aggregated_signature() {
        // sign 3 messages
        let num_messages = 3;

        let mut rng = ChaCha8Rng::seed_from_u64(12);

        // generate private keys
        let private_keys: Vec<_> = (0..num_messages)
            .map(|_| bls_signatures::PrivateKey::generate(&mut rng))
            .collect();

        // generate messages
        let messages: Vec<UnsignedMessageAPI> = (0..num_messages)
            .map(|i| {
                //Prepare transaction
                let bls_public_key = private_keys[i].public_key();
                let bls_address = Address::new_bls(&bls_public_key.as_bytes()).unwrap();

                UnsignedMessageAPI {
                    to: "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy".to_string(),
                    from: bls_address.to_string(),
                    nonce: 1,
                    value: "100000".to_string(),
                    gas_price: "2500".to_string(),
                    gas_limit: 25000,
                    method: 0,
                    params: "".to_string(),
                }
            })
            .collect();

        // sign messages
        let sigs: Vec<bls_signatures::Signature>;
        sigs = messages
            .par_iter()
            .zip(private_keys.par_iter())
            .map(|(message, pk)| {
                let private_key = PrivateKey::try_from(pk.as_bytes()).expect("FIX ME");
                let raw_sig = transaction_sign_bls_raw(message, &private_key).unwrap();

                bls_signatures::Serialize::from_bytes(&raw_sig.0).expect("FIX ME")
            })
            .collect::<Vec<bls_signatures::Signature>>();

        // serialize messages
        let cbor_messages: Vec<CborBuffer>;
        cbor_messages = messages
            .par_iter()
            .map(|message| transaction_serialize(message).unwrap())
            .collect::<Vec<CborBuffer>>();

        let aggregated_signature = bls_signatures::aggregate(&sigs).expect("FIX ME");

        let sig = SignatureBLS::try_from(aggregated_signature.as_bytes()).expect("FIX ME");

        assert!(verify_aggregated_signature(&sig, &cbor_messages[..]).unwrap());
    }

    // ----------------------------------------
    //    PaychCreate test vector + test
    // ----------------------------------------
    // const PYMT_CHAN_EXAMPLE_UNSIGNED_MESSAGE: &str = r#"
    //     {
    //         "to": builtin.InitActorAddr,
    //         "from": "t3smdzzt2fbrzalmfi5rskc3tc6wpwcj2zbgyu5engqtkkzrxteg2oyqpukqzrhqqfvzqadh7mtqye443liejq",
    //         "nonce": 1,
    //         "value": "1",
    //         "gasprice": "0",
    //         "gaslimit": 1000000,
    //         "method": builtin.MethodsInit.Exec,
    //         "params": "(see below)"
    //     }"#;
	// where the p.ch. payments are going to address 
	//   t1evcupqzya3nuzhuabg4oxwoe2ls7eamcu3uw4cy
    //
    // 
    // How does simple.go:createPaych() create the Params field?
    //
    // 1. First serialize to/from into 'params':
    //
    //  82                         # array(2)
    //    58 31                    # bytes(49) == From address
    //        (03)93079CCF450C7205B0A8EC64A16E62F59F61275909B14E91A684D4ACC6F321B4EC41F4543313C205AE60019FEC9C304E # (t3)smdzzt2fbrzalmfi5rskc3tc6wpwcj2zbgyu5engqtkkzrxteg2oyqpukqzrhqqfvzqadh7mtqye4(43liejq)
    //  55                         # bytes(21) == To address
    //    (01)254547C33806DB4C9E8009B8EBD9C4D2E5F20182 # (t1)evcupqzya3nuzhuabg4oxwoe2ls7eamc(u3uw4cy)
    //
    // 2. Next, the Code CID and the 'params' struct serialized above together
    // into 'enc' which will become Params field in the message::
    //  82                         # array(2)
    //    D8 2A                    # tag(42)
    //      58 19                  # bytes(25) == PaymentChannelActorCodeID
    //        000155001466696C2F312F7061796D656E746368616E6E656C
    //    58 4A                    # bytes(74) == 'params' above
    //        8258310393079CCF450C7205B0A8EC64A16E62F59F61275909B14E91A684D4ACC6F321B4EC41F4543313C205AE60019FEC9C304E5501254547C33806DB4C9E8009B8EBD9C4D2E5F20182
    //
    // 3. Full message as seen by MpoolPush():
    //
    //  82                         # array(2)
    //    89                       # array(9)
    //      00                     # unsigned(0) == Version
    //      42                     # bytes(2)
    //        0001                 # == To: builtin.InitActorAddr (1)
    //      58 31                  # bytes(49) == From: (t3)smdzzt2fbrzalmfi5
    //        0393079CCF450C7205B0 #              rskc3tc6wpwcj2zbgyu5engqtkk
    //        A8EC64A16E62F59F6127 #              zrxteg2oyqpukqzrhqqfvzqadh7m
    //        5909B14E91A684D4ACC6 #              tqye4(43liejq) 
    //        F321B4EC41F4543313C205AE60019FEC9C304E
    //      01                     # unsigned(1) ==> Nonce: 1
    //      42                     # bytes(2)
    //        0001                 # ==> Amt: 1
    //      40                     # bytes(0)
    //                             # ==> Gas price: 0 (==empty buffer)
    //      1A 000F4240            # unsigned(1000000) ==> Gas limit: 1000000
    //      02                     # unsigned(2): ==> Method: builtin.
    //                             #                 MethodsInit.Exec (2)
    //      58 6A                  # bytes(106) ==> Params: 'enc' above
    //        82D82A5819000155001466696C2F312F7061796D656E746368616E6E656C584A8258310393079CCF450C7205B0A8EC64A16E62F59F61275909B14E91A684D4ACC6F321B4EC41F4543313C205AE60019FEC9C304E5501254547C33806DB4C9E8009B8EBD9C4D2E5F20182 
    //      58 61                  # bytes(97) ==> Signature
    //        02836BEF21C8075AD92BE49C2A47C08A2236036B1879301D81B71D285A49E6DE91816FC5C41918F292FD691A5BE23C0E9409C4C62570624356501B785D793950F17BB36E5DA58FE9468E5604D3041B9D13333B8FB1D8A817EFF7FC70A18D676D2C
    #[test]
    fn payment_channel_creation_bls_signing() {
        let from_key = "f27896e1f501a0a368dc630355f5aed286ab8b5d63b38b75429c17541a44a450";
        let _from_address = "t3smdzzt2fbrzalmfi5rskc3tc6wpwcj2zbgyu5engqtkkzrxteg2oyqpukqzrhqqfvzqadh7mtqye443liejq";
        let bls_key = PrivateKey::try_from(from_key.to_string()).unwrap();
        let from_pkey = "93079ccf450c7205b0a8ec64a16e62f59f61275909b14e91a684d4acc6f321b4ec41f4543313c205ae60019fec9c304e";

        //let to_key = "f945c98b4ebade1084c583316556fd27ec0ac855a1857e758e71bb59791e030d";
        //let to_address = "t1evcupqzya3nuzhuabg4oxwoe2ls7eamcu3uw4cy";

        let pch_create = serde_json::json!(
        {
            "to": "t01",           // INIT_ACTOR_ADDR
            "from": "t3smdzzt2fbrzalmfi5rskc3tc6wpwcj2zbgyu5engqtkkzrxteg2oyqpukqzrhqqfvzqadh7mtqye443liejq",
            "nonce": 1,
            "value": "1",
            "gasprice": "0",
            "gaslimit": 1000000,
            "method": 2,           // extras::MethodInit::Exec
            "params": {
                "code_cid": "fil/1/paymentchannel",
                "pch_constructor_params": {
                    "to": "t1evcupqzya3nuzhuabg4oxwoe2ls7eamcu3uw4cy", 
                    "from": "t3smdzzt2fbrzalmfi5rskc3tc6wpwcj2zbgyu5engqtkkzrxteg2oyqpukqzrhqqfvzqadh7mtqye443liejq",
                },
            }
        });

        let pch_create_message_api = create_pymtchan(
            "t3smdzzt2fbrzalmfi5rskc3tc6wpwcj2zbgyu5engqtkkzrxteg2oyqpukqzrhqqfvzqadh7mtqye443liejq",
            "t1evcupqzya3nuzhuabg4oxwoe2ls7eamcu3uw4cy",
            "1".to_string(),
            1,
        )
        .unwrap();

        let pch_create_message_expected: UnsignedMessageAPI =
            serde_json::from_value(pch_create).unwrap();

        assert_eq!(
            serde_json::to_string(&pch_create_message_expected).unwrap(),
            serde_json::to_string(&pch_create_message_api).unwrap()
        );

        // First check transaction_serialize() in creating an unsigned message
        let result = transaction_serialize(&pch_create_message_api).unwrap();

        assert_eq!(
            hex::encode(&result),
            "890042000158310393079ccf450c7205b0a8ec64a16e62f59f61275909b14e91a684d4acc6f321b4ec41f4543313c205ae60019fec9c304e01420001401a000f424002586a82d82a5819000155001466696c2f312f7061796d656e746368616e6e656c584a8258310393079ccf450c7205b0a8ec64a16e62f59f61275909b14e91a684d4acc6f321b4ec41f4543313c205ae60019fec9c304e5501254547c33806db4c9e8009b8ebd9c4d2e5f20182",
            "Correct unsigned message should match"
        );

        // Now check that we can generate a correct signature
        let raw_sig = transaction_sign_bls_raw(&pch_create_message_api, &bls_key).unwrap();
        let sig = bls_signatures::Signature::from_bytes(&raw_sig.0).expect("FIX ME");

        let bls_pkey =
            bls_signatures::PublicKey::from_bytes(&hex::decode(from_pkey).unwrap()).unwrap();

        assert!(bls_pkey.verify(sig, &result));
    }

    // This example reverses the to/from addresses compared with
    // previous test.
    const PYMTCHAN_EXAMPLE_UNSIGNED_MSG: &str = r#"
        {
            "to": "t01",
            "from": "t1evcupqzya3nuzhuabg4oxwoe2ls7eamcu3uw4cy",
            "nonce": 1,
            "value": "1",
            "gasprice": "0",
            "gaslimit": 1000000,
            "method": 2,
            "params": {
                "code_cid": "fil/1/paymentchannel",
                "pch_constructor_params": {
                    "to": "t3smdzzt2fbrzalmfi5rskc3tc6wpwcj2zbgyu5engqtkkzrxteg2oyqpukqzrhqqfvzqadh7mtqye443liejq", 
                    "from": "t1evcupqzya3nuzhuabg4oxwoe2ls7eamcu3uw4cy"
                }
            }
        }"#;
    //
    // Here are the bytes of the final signed message:
    // (see previous example for detailed field labeling)
    //
    // 82                                   # array(2)
    const PYMTCHAN_EXAMPLE_UNSIGNED_MSG_CBOR : &str = r#"
       89                                   # array(9)
          00                                # unsigned(0) 'Version
          42                                # bytes(2)    'To
             0001                           # 
          55                                # bytes(21)   'From
             01254547C33806DB4C9E8009B8EBD9C4D2E5F20182
          01                                # unsigned(1) 'Nonce
          42                                # bytes(2)    'Amount
             0001                           # 
          40                                # bytes(0)    'Gas price
                                            # ""
          1A 000F4240                       # unsigned(1000000) 'Gas limit
          02                                # unsigned(2)       'Method
          58 6A                             # bytes(106)        'Params
             82D82A5819000155001466696C2F312F7061796D656E746368616E6E656C584A825501254547C33806DB4C9E8009B8EBD9C4D2E5F2018258310393079CCF450C7205B0A8EC64A16E62F59F61275909B14E91A684D4ACC6F321B4EC41F4543313C205AE60019FEC9C304E 
    "#;
    //   58 42                                # bytes(66)   'Signature
    //      01D2C3D56B58CAD05781E8107A90DF55B6715DEE12FEEB268CF697FF24BC9ABF5777C7EE2A939F4FD9E8EEB40FB5DE396B73A03DC019699593A87E299E9927F37F01 
    #[test]
    fn payment_channel_creation_secp256k1_signing() {
        let from_key = "f945c98b4ebade1084c583316556fd27ec0ac855a1857e758e71bb59791e030d";
        let _from_pkey = "254547c33806db4c9e8009b8ebd9c4d2e5f20182";
        let privkey = PrivateKey::try_from(from_key.to_string()).unwrap();

        let _pch_create_message_unsigned = serde_json::json!(
            PYMTCHAN_EXAMPLE_UNSIGNED_MSG);
        let pch_create_message_api : UnsignedMessageAPI = 
            serde_json::from_str(PYMTCHAN_EXAMPLE_UNSIGNED_MSG)
            .expect("Could not serialize unsigned message");
        // TODO:  ^^^ this is an error, these lines are duplicated.  First one should have called create_pymtchan()
 
        let signed_message_result = transaction_sign(&pch_create_message_api, &privkey).unwrap();
        // TODO:  how do I check the signature of a transaction_sign() result

        // Check the raw bytes match the test vector cbor
        let cbor_result_unsigned_msg = 
            transaction_serialize(&signed_message_result.message).unwrap();
        let mut expected_unsigned_message_cbor_string : String = 
            PYMTCHAN_EXAMPLE_UNSIGNED_MSG_CBOR.to_string();
        let mut new_expected_unsigned_message_cbor_string = String::from("");
        let re = Regex::new(r"(?P<comment>#.*)").unwrap();
        for l in expected_unsigned_message_cbor_string.lines() {
            let l = re.replace_all(l, "");
            new_expected_unsigned_message_cbor_string.push_str(&l);
        }
        expected_unsigned_message_cbor_string = new_expected_unsigned_message_cbor_string;
        &expected_unsigned_message_cbor_string.retain(|c| !c.is_whitespace());
        
        assert_eq!(
            hex::encode(&cbor_result_unsigned_msg),
            expected_unsigned_message_cbor_string.to_ascii_lowercase(),
            "Correct unsigned message should match"
        );

    }

    const PYMTCHAN_UPDATE_EXAMPLE_UNSIGNED_MSG: &str = r#"
    {
        "to": "t2oajfrgjjllncvbxx4shzbxy3nnegsrnnk3tq2tq",
        "from": "t1gsu6clgzpcrjxclicnsva5bty3r65hnkqpd4jaq",
        "nonce": 1,
        "value": "0",
        "gasprice": "100",
        "gaslimit": 20000000,
        "method": 2,
        "params": "g1hQigAAQPYAAUIAAQCAWEIBfNbDtNF6DAHqTprnuShhmDB+AgesM8ez1/smkrQTWHsvgbvMSEefidI7d0U/82y8AQVFEPe+PLAMg+XOWdT2HQFAQA=="
    }"#;
    // ^^ params == 8358508a000040f6000142000100805842017cd6c3b4d17a0c01ea4e9ae7b9286198307e0207ac33c7b3d7fb2692b413587b2f81bbcc48479f89d23b77453ff36cbc01054510f7be3cb00c83e5ce59d4f61d014040

    #[test]
    fn payment_channel_update() {
        let from_key = "22cf11134e56d5a47a5f293821ba5503bd6c53689b55042095ef34ae3b3c53c1";
        let _from_pkey = "34a9e12cd978a29b89681365507433c6e3ee9daa"; // from base32decode("gsu6clgzpcrjxclicnsva5bty3r65hnk")
        let _pch_addr_hex = "70125899295ada2a86f7e48f90df1b6b486945ad"; // from base32decode("oajfrgjjllncvbxx4shzbxy3nnegsrnn")
        let privkey = PrivateKey::try_from(from_key.to_string()).unwrap();

        let sig = SpecsActorsCryptoSignature{
            typ: 1,
            data: vec![0x7C, 0xD6, 0xC3, 0xB4, 0xD1, 0x7A, 0x0C, 0x01, 0xEA, 0x4E, 0x9A, 0xE7, 0xB9, 0x28, 0x61, 0x98, 0x30, 0x7E, 0x02, 0x07, 0xAC, 0x33, 0xC7, 0xB3, 0xD7, 0xFB, 0x26, 0x92, 0xB4, 0x13, 0x58, 0x7B, 0x2F, 0x81, 0xBB, 0xCC, 0x48, 0x47, 0x9F, 0x89, 0xD2, 0x3B, 0x77, 0x45, 0x3F, 0xF3, 0x6C, 0xBC, 0x01, 0x05, 0x45, 0x10, 0xF7, 0xBE, 0x3C, 0xB0, 0x0C, 0x83, 0xE5, 0xCE, 0x59, 0xD4, 0xF6, 0x1D, 0x01],
        };
        let sv = SignedVoucher::new(0,1,1,&sig);

        let pch_update_message_unsigned_api = update_pymtchan(
            "t2oajfrgjjllncvbxx4shzbxy3nnegsrnnk3tq2tq",
            "t1gsu6clgzpcrjxclicnsva5bty3r65hnkqpd4jaq",
            &sv,
            1,
        )
        .unwrap();

        let pch_update_message_unsigned_expected: UnsignedMessageAPI =
            serde_json::from_str(PYMTCHAN_UPDATE_EXAMPLE_UNSIGNED_MSG)
            .expect("Could not serialize unsigned message");

        assert_eq!(
            serde_json::to_string(&pch_update_message_unsigned_expected).unwrap(),
            serde_json::to_string(&pch_update_message_unsigned_api).unwrap()
        );

        // Sign
        let signature = transaction_sign_raw(&pch_update_message_unsigned_api, &privkey).unwrap();

        // Verify
        let message = forest_message::UnsignedMessage::try_from(&pch_update_message_unsigned_api)
            .expect("Could not serialize unsigned message");
        let message_cbor = CborBuffer(to_vec(&message).unwrap());

        let valid_signature = verify_signature(&signature, &message_cbor);
        assert!(valid_signature.unwrap());
    }

    const PYMTCHAN_SETTLE_EXAMPLE_UNSIGNED_MSG: &str = r#"
    {
        "to": "t2oajfrgjjllncvbxx4shzbxy3nnegsrnnk3tq2tq",
        "from": "t1gsu6clgzpcrjxclicnsva5bty3r65hnkqpd4jaq",
        "nonce": 1,
        "value": "0",
        "gasprice": "0",
        "gaslimit": 20000000,
        "method": 3,
        "params": ""
    }"#;
    
    #[test]
    fn payment_channel_settle() {
        let from_key = "22cf11134e56d5a47a5f293821ba5503bd6c53689b55042095ef34ae3b3c53c1";
        let _from_pkey = "34a9e12cd978a29b89681365507433c6e3ee9daa"; // from base32decode("gsu6clgzpcrjxclicnsva5bty3r65hnk")
        let _pch_addr_hex = "70125899295ada2a86f7e48f90df1b6b486945ad"; // from base32decode("oajfrgjjllncvbxx4shzbxy3nnegsrnn")
        let privkey = PrivateKey::try_from(from_key.to_string()).unwrap();

        let pch_settle_message_unsigned_api = settle_pymtchan(
            "t2oajfrgjjllncvbxx4shzbxy3nnegsrnnk3tq2tq",
            "t1gsu6clgzpcrjxclicnsva5bty3r65hnkqpd4jaq",
            1,
        )
        .unwrap();

        let pch_settle_message_unsigned_expected: UnsignedMessageAPI =
            serde_json::from_str(PYMTCHAN_SETTLE_EXAMPLE_UNSIGNED_MSG)
            .expect("Could not serialize unsigned message");

        assert_eq!(
            serde_json::to_string(&pch_settle_message_unsigned_expected).unwrap(),
            serde_json::to_string(&pch_settle_message_unsigned_api).unwrap()
        );
        
        // Sign
        let signature = transaction_sign_raw(&pch_settle_message_unsigned_api, &privkey).unwrap();

        // Verify
        let message = forest_message::UnsignedMessage::try_from(&pch_settle_message_unsigned_api)
            .expect("Could not serialize unsigned message");
        let message_cbor = CborBuffer(to_vec(&message).unwrap());

        let valid_signature = verify_signature(&signature, &message_cbor);
        assert!(valid_signature.unwrap());
    }

    const PYMTCHAN_COLLECT_EXAMPLE_UNSIGNED_MSG: &str = r#"
    {
        "to": "t2oajfrgjjllncvbxx4shzbxy3nnegsrnnk3tq2tq",
        "from": "t1gsu6clgzpcrjxclicnsva5bty3r65hnkqpd4jaq",
        "nonce": 1,
        "value": "0",
        "gasprice": "0",
        "gaslimit": 20000000,
        "method": 4,
        "params": ""
    }"#;

    #[test]
    fn payment_channel_collect() {
        let from_key = "22cf11134e56d5a47a5f293821ba5503bd6c53689b55042095ef34ae3b3c53c1";
        let _from_pkey = "34a9e12cd978a29b89681365507433c6e3ee9daa"; // from base32decode("gsu6clgzpcrjxclicnsva5bty3r65hnk")
        let _pch_addr_hex = "70125899295ada2a86f7e48f90df1b6b486945ad"; // from base32decode("oajfrgjjllncvbxx4shzbxy3nnegsrnn")
        let privkey = PrivateKey::try_from(from_key.to_string()).unwrap();

        let pch_collect_message_unsigned_api = collect_pymtchan(
            "t2oajfrgjjllncvbxx4shzbxy3nnegsrnnk3tq2tq",
            "t1gsu6clgzpcrjxclicnsva5bty3r65hnkqpd4jaq",
            1,
        )
        .unwrap();

        let pch_collect_message_unsigned_expected: UnsignedMessageAPI =
            serde_json::from_str(PYMTCHAN_COLLECT_EXAMPLE_UNSIGNED_MSG)
            .expect("Could not serialize unsigned message");

        assert_eq!(
            serde_json::to_string(&pch_collect_message_unsigned_expected).unwrap(),
            serde_json::to_string(&pch_collect_message_unsigned_api).unwrap()
        );
    
        // Sign
        let signature = transaction_sign_raw(&pch_collect_message_unsigned_api, &privkey).unwrap();

        // Verify
        let message = forest_message::UnsignedMessage::try_from(&pch_collect_message_unsigned_api)
            .expect("Could not serialize unsigned message");
        let message_cbor = CborBuffer(to_vec(&message).unwrap());

        let valid_signature = verify_signature(&signature, &message_cbor);
        assert!(valid_signature.unwrap());
    }

    #[test]
    fn serialize_signed_payment_voucher() {
        use crate::api::SpecsActorsCryptoSignature;
        use crate::api::SignedVoucher;
        use serde_cbor::ser::to_vec_packed;

        // This is the Lotus voucher
        let _test_vector_cbor_rawbase64 = "igAAQPYAAUIAAQCAWEIBfNbDtNF6DAHqTprnuShhmDB-AgesM8ez1_smkrQTWHsvgbvMSEefidI7d0U_82y8AQVFEPe-PLAMg-XOWdT2HQE";

        // test_vector_cbor broken out by field:
        //
        //  8A                                      # array(10)           // array of 10 items
        //     00                                   # unsigned(0)         // TimeLockMin
        //     00                                   # unsigned(0)         // TimeLockMax
        //     40                                   # bytes(0)            // SecretPreimage
        //                                             # ""
        //     F6                                   # primitive(22)       // Extra
        //     00                                   # unsigned(0)         // Lane
        //     01                                   # unsigned(1)         // Nonce
        //     42                                   # bytes(2)            // Amount
        //         0001                              # "\x00\x01"
        //     00                                   # unsigned(0)         // MinSettleHeight
        //     80                                   # array(0)            // Merges[]
        //     58 42                                # bytes(66)           // Signature
        //  017CD6C3B4D17A0C01EA4E9AE7B9286198307E0207AC33C7B3D7FB2692B413587B2F81BBCC48479F89D23B77453FF36CBC01054510F7BE3CB00C83E5CE59D4F61D01
        let test_vector_cbor_hex_string = "8a000040f6000142000100805842017cd6c3b4d17a0c01ea4e9ae7b9286198307e0207ac33c7b3d7fb2692b413587b2f81bbcc48479f89d23b77453ff36cbc01054510f7be3cb00c83e5ce59d4f61d01";

        let sig = SpecsActorsCryptoSignature{
            typ: 1,
            data: vec![0x7C, 0xD6, 0xC3, 0xB4, 0xD1, 0x7A, 0x0C, 0x01, 0xEA, 0x4E, 0x9A, 0xE7, 0xB9, 0x28, 0x61, 0x98, 0x30, 0x7E, 0x02, 0x07, 0xAC, 0x33, 0xC7, 0xB3, 0xD7, 0xFB, 0x26, 0x92, 0xB4, 0x13, 0x58, 0x7B, 0x2F, 0x81, 0xBB, 0xCC, 0x48, 0x47, 0x9F, 0x89, 0xD2, 0x3B, 0x77, 0x45, 0x3F, 0xF3, 0x6C, 0xBC, 0x01, 0x05, 0x45, 0x10, 0xF7, 0xBE, 0x3C, 0xB0, 0x0C, 0x83, 0xE5, 0xCE, 0x59, 0xD4, 0xF6, 0x1D, 0x01],
        };
        let sv = SignedVoucher::new(0,1,1,&sig);
        let serialized_cbor = to_vec_packed(&sv).unwrap();
        let mut serialized_cbor_hex_string = String::new();
        serialized_cbor.iter().for_each(|x| serialized_cbor_hex_string.push_str( &format!("{:02x}", x) ));
        //println!("serialized cbor = '{}'",serialized_cbor_hex_string);
        assert_eq!(serialized_cbor_hex_string, test_vector_cbor_hex_string);
    }

    #[test]
    fn support_multisig_create() {
        let constructor_params = serde_json::json!({
            "signers": ["t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba", "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy"],
            "num_approvals_threshold": 1,
            "unlock_duration": 0
        });

        let constructor_params_expected: MessageParams =
            serde_json::from_value(constructor_params).unwrap();

        let exec_params = serde_json::json!({
            "code_cid": "fil/1/multisig",
            "constructor_params": base64::encode(serialize_params(constructor_params_expected).unwrap())
        });

        let exec_params_expected: MessageParams = serde_json::from_value(exec_params).unwrap();

        let multisig_create = serde_json::json!(
        {
            "to": "t01",
            "from": "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
            "nonce": 1,
            "value": "1000",
            "gasprice": "1",
            "gaslimit": 1000000,
            "method": 2,
            "params": base64::encode(serialize_params(exec_params_expected).unwrap()),
        });

        let multisig_create_message_api = create_multisig(
            "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba".to_string(),
            vec![
                "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba".to_string(),
                "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy".to_string(),
            ],
            "1000".to_string(),
            1,
            1,
            0,
        )
        .unwrap();

        let multisig_create_message_expected: UnsignedMessageAPI =
            serde_json::from_value(multisig_create).unwrap();

        assert_eq!(
            serde_json::to_string(&multisig_create_message_expected).unwrap(),
            serde_json::to_string(&multisig_create_message_api).unwrap()
        );

        let result = transaction_serialize(&multisig_create_message_api).unwrap();

        println!("{}", hex::encode(&result));

        assert_eq!(
            hex::encode(&result),
            "890042000155011eaf1c8a4bbfeeb0870b1745b1f57503470b711601430003e84200011a000f424002584982d82a53000155000e66696c2f312f6d756c74697369675830838255011eaf1c8a4bbfeeb0870b1745b1f57503470b71165501dfe49184d46adc8f89d44638beb45f78fcad25900100"
        );
    }

    #[test]
    fn support_multisig_propose_message() {
        let proposal_params = serde_json::json!({
            "to": "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy",
            "value": "1000",
            "method": 0,
            "params": "",
        });

        let proposal_params_expected: MessageParams =
            serde_json::from_value(proposal_params).unwrap();

        let multisig_proposal = serde_json::json!(
        {
            "to": "t01",
            "from": "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
            "nonce": 1,
            "value": "0",
            "gasprice": "1",
            "gaslimit": 1000000,
            "method": 2,
            "params": base64::encode(serialize_params(proposal_params_expected).unwrap())
        });

        let multisig_proposal_message_api = proposal_multisig_message(
            "t01".to_string(),
            "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy".to_string(),
            "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba".to_string(),
            "1000".to_string(),
            1,
        )
        .unwrap();

        let multisig_proposal_message_expected: UnsignedMessageAPI =
            serde_json::from_value(multisig_proposal).unwrap();

        assert_eq!(
            serde_json::to_string(&multisig_proposal_message_expected).unwrap(),
            serde_json::to_string(&multisig_proposal_message_api).unwrap()
        );

        let result = transaction_serialize(&multisig_proposal_message_api).unwrap();

        println!("{}", hex::encode(&result));

        assert_eq!(
            hex::encode(&result),
            "890042000155011eaf1c8a4bbfeeb0870b1745b1f57503470b711601404200011a000f424002581d845501dfe49184d46adc8f89d44638beb45f78fcad2590430003e80040"
        );
    }

    #[test]
    fn support_multisig_approve_message() {
        let proposal_params = serde_json::json!({
            "requester": "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
            "to": "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy",
            "value": "1000",
            "method": 0,
            "params": "",
        });

        let proposal_params_expected: MessageParams =
            serde_json::from_value(proposal_params).unwrap();

        let proposal_hash =
            blake2b_256(serialize_params(proposal_params_expected).unwrap().as_ref());

        let approval_params = serde_json::json!({
            "txn_id": 1234,
            "proposal_hash_data": base64::encode(proposal_hash),
        });

        let approval_params_expected: MessageParams =
            serde_json::from_value(approval_params).unwrap();

        let multisig_approval = serde_json::json!(
        {
            "to": "t01",
            "from": "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
            "nonce": 1,
            "value": "0",
            "gasprice": "1",
            "gaslimit": 1000000,
            "method": 3,
            "params": base64::encode(serialize_params(approval_params_expected).unwrap()),
        });

        let multisig_approval_message_api = approve_multisig_message(
            "t01".to_string(),
            1234,
            "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba".to_string(),
            "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy".to_string(),
            "1000".to_string(),
            "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba".to_string(),
            1,
        )
        .unwrap();

        let multisig_approval_message_expected: UnsignedMessageAPI =
            serde_json::from_value(multisig_approval).unwrap();

        assert_eq!(
            serde_json::to_string(&multisig_approval_message_expected).unwrap(),
            serde_json::to_string(&multisig_approval_message_api).unwrap()
        );

        let result = transaction_serialize(&multisig_approval_message_api).unwrap();

        println!("{}", hex::encode(&result));

        assert_eq!(
            hex::encode(&result),
            "890042000155011eaf1c8a4bbfeeb0870b1745b1f57503470b711601404200011a000f4240035845821904d2982018f818ac18f218651829187218f00918ae18aa181d189b186118cf18cd18861870182b1830189318c1189c183018491860184f181918db188c18b3187818f3"
        );
    }

    #[test]
    fn support_multisig_cancel_message() {
        let proposal_params = serde_json::json!({
            "requester": "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
            "to": "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy",
            "value": "1000",
            "method": 0,
            "params": "",
        });

        let proposal_params_expected: MessageParams =
            serde_json::from_value(proposal_params).unwrap();

        let proposal_hash =
            blake2b_256(serialize_params(proposal_params_expected).unwrap().as_ref());

        let cancel_params = serde_json::json!({
            "txn_id": 1234,
            "proposal_hash_data": base64::encode(proposal_hash),
        });

        let cancel_params_expected: MessageParams = serde_json::from_value(cancel_params).unwrap();

        let multisig_cancel = serde_json::json!(
        {
            "to": "t01",
            "from": "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba",
            "nonce": 1,
            "value": "0",
            "gasprice": "1",
            "gaslimit": 1000000,
            "method": 4,
            "params": base64::encode(serialize_params(cancel_params_expected).unwrap()),
        });

        let multisig_cancel_message_api = cancel_multisig_message(
            "t01".to_string(),
            1234,
            "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba".to_string(),
            "t137sjdbgunloi7couiy4l5nc7pd6k2jmq32vizpy".to_string(),
            "1000".to_string(),
            "t1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba".to_string(),
            1,
        )
        .unwrap();

        let multisig_cancel_message_expected: UnsignedMessageAPI =
            serde_json::from_value(multisig_cancel).unwrap();

        assert_eq!(
            serde_json::to_string(&multisig_cancel_message_expected).unwrap(),
            serde_json::to_string(&multisig_cancel_message_api).unwrap()
        );

        let result = transaction_serialize(&multisig_cancel_message_api).unwrap();

        println!("{}", hex::encode(&result));

        assert_eq!(
            hex::encode(&result),
            "890042000155011eaf1c8a4bbfeeb0870b1745b1f57503470b711601404200011a000f4240045845821904d2982018f818ac18f218651829187218f00918ae18aa181d189b186118cf18cd18861870182b1830189318c1189c183018491860184f181918db188c18b3187818f3"
        );
    }
}
