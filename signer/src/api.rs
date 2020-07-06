use crate::error::SignerError;
use crate::signature::Signature;
use extras::{ConstructorParams, ExecParams, ProposalHashData, ProposeParams, TxnID, TxnIDParams};
use forest_address::{Address, Network};
use forest_cid::{multihash::Identity, Cid, Codec};
use forest_encoding::blake2b_256;
use forest_message::{Message, SignedMessage, UnsignedMessage};
use forest_vm::Serialized;
use num_bigint_chainsafe::BigUint;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::str::FromStr;

pub enum SigTypes {
    SigTypeSecp256k1 = 0x01,
    SigTypeBLS = 0x02,
}

#[cfg_attr(feature = "with-arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructorParamsMultisig {
    pub signers: Vec<String>,
    pub num_approvals_threshold: i64,
    #[serde(skip)]
    // FIXME: only skip if -1
    pub unlock_duration: i64,
}

impl TryFrom<ConstructorParamsMultisig> for ConstructorParams {
    type Error = SignerError;

    fn try_from(
        constructor_params: ConstructorParamsMultisig,
    ) -> Result<ConstructorParams, Self::Error> {
        let signers_tmp: Result<Vec<Address>, _> = constructor_params
            .signers
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

        Ok(ConstructorParams {
            signers,
            num_approvals_threshold: constructor_params.num_approvals_threshold,
            // FIXME: What is default ? Optional ?
            unlock_duration: 0,
        })
    }
}

#[cfg_attr(feature = "with-arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MessageParamsMultisig {
    pub code_cid: String,
    pub constructor_params: ConstructorParamsMultisig,
}

impl TryFrom<MessageParamsMultisig> for ExecParams {
    type Error = SignerError;

    fn try_from(exec_constructor: MessageParamsMultisig) -> Result<ExecParams, Self::Error> {
        let constructor_multisig_params =
            ConstructorParams::try_from(exec_constructor.constructor_params)?;

        let serialized_constructor_multisig_params =
            forest_vm::Serialized::serialize::<ConstructorParams>(constructor_multisig_params)
                .map_err(|err| SignerError::GenericString(err.to_string()))?;

        Ok(ExecParams {
            code_cid: Cid::new_v1(Codec::Raw, Identity::digest(b"fil/1/multisig")),
            constructor_params: serialized_constructor_multisig_params,
        })
    }
}

#[cfg_attr(feature = "with-arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProposeParamsMultisig {
    pub to: String,
    pub value: String,
    // FIXME: only support method 0
    pub method: u64,
    // FIXME: extend to other more complex transaction
    pub params: String,
}

impl TryFrom<ProposeParamsMultisig> for ProposeParams {
    type Error = SignerError;

    fn try_from(propose_params: ProposeParamsMultisig) -> Result<ProposeParams, Self::Error> {
        Ok(ProposeParams {
            to: Address::from_str(&propose_params.to)?,
            value: BigUint::from_str(&propose_params.value)?,
            method: propose_params.method,
            params: forest_vm::Serialized::new(Vec::new()),
        })
    }
}

/// Proposal data
#[cfg_attr(feature = "with-arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PropoposalHashDataParamsMultisig {
    pub requester: String,
    pub to: String,
    pub value: String,
    pub method: u64,
    // Only suport method 0 and params ""
    pub params: String,
}

impl TryFrom<PropoposalHashDataParamsMultisig> for ProposalHashData {
    type Error = SignerError;

    fn try_from(params: PropoposalHashDataParamsMultisig) -> Result<ProposalHashData, Self::Error> {
        Ok(ProposalHashData {
            requester: Address::from_str(&params.requester)?,
            to: Address::from_str(&params.to)?,
            value: BigUint::from_str(&params.value)?,
            method: params.method,
            params: forest_vm::Serialized::new(Vec::new()),
        })
    }
}

/// Data to approve
#[cfg_attr(feature = "with-arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TxnIDParamsMultisig {
    pub txn_id: i64,
    pub proposal_hash_data: PropoposalHashDataParamsMultisig,
}

impl TryFrom<TxnIDParamsMultisig> for TxnIDParams {
    type Error = SignerError;

    fn try_from(params: TxnIDParamsMultisig) -> Result<TxnIDParams, Self::Error> {
        let proposal_data = ProposalHashData::try_from(params.proposal_hash_data)?;
        let serialized_porposal_data =
            forest_vm::Serialized::serialize::<ProposalHashData>(proposal_data)
                .map_err(|err| SignerError::GenericString(err.to_string()))?;
        let proposal_hash = blake2b_256(&serialized_porposal_data);

        Ok(TxnIDParams {
            id: TxnID(params.txn_id),
            proposal_hash,
        })
    }
}

#[cfg_attr(feature = "with-arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum MessageParams {
    MessageParamsMultisig(MessageParamsMultisig),
    MessageParamsEmpty(String),
    ProposeParamsMultisig(ProposeParamsMultisig),
    TxnIDParamsMultisig(TxnIDParamsMultisig),
}

impl MessageParams {
    pub fn serialize(self) -> Result<Serialized, SignerError> {
        let params_serialized = match self {
            MessageParams::MessageParamsEmpty(_) => forest_vm::Serialized::new(Vec::new()),
            MessageParams::MessageParamsMultisig(multisig_params) => {
                let params = ExecParams::try_from(multisig_params)?;

                forest_vm::Serialized::serialize::<ExecParams>(params)
                    .map_err(|err| SignerError::GenericString(err.to_string()))?
            }
            MessageParams::ProposeParamsMultisig(multisig_proposal_params) => {
                let params = ProposeParams::try_from(multisig_proposal_params)?;

                forest_vm::Serialized::serialize::<ProposeParams>(params)
                    .map_err(|err| SignerError::GenericString(err.to_string()))?
            }
            MessageParams::TxnIDParamsMultisig(multisig_txn_id_params) => {
                let params = TxnIDParams::try_from(multisig_txn_id_params)?;

                forest_vm::Serialized::serialize::<TxnIDParams>(params)
                    .map_err(|err| SignerError::GenericString(err.to_string()))?
            }
        };

        Ok(params_serialized)
    }
}

/// Unsigned message api structure
#[cfg_attr(feature = "with-arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedMessageAPI {
    pub to: String,
    pub from: String,
    pub nonce: u64,
    pub value: String,
    #[serde(rename = "gasprice")]
    #[serde(alias = "gasPrice")]
    #[serde(alias = "gas_price")]
    pub gas_price: String,
    #[serde(rename = "gaslimit")]
    #[serde(alias = "gasLimit")]
    #[serde(alias = "gas_limit")]
    pub gas_limit: u64,
    pub method: u64,
    pub params: MessageParams,
}

/// Signature api structure
#[cfg_attr(feature = "with-arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct SignatureAPI {
    #[serde(rename = "type")]
    pub sig_type: u8,
    #[serde(with = "serde_base64_vector")]
    pub data: Vec<u8>,
}

/// Signed message api structure
#[cfg_attr(feature = "with-arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct SignedMessageAPI {
    pub message: UnsignedMessageAPI,
    pub signature: SignatureAPI,
}

/// Structure containing an `UnsignedMessageAPI` or a `SignedMessageAPI`
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum MessageTxAPI {
    UnsignedMessageAPI(UnsignedMessageAPI),
    SignedMessageAPI(SignedMessageAPI),
}

impl MessageTxAPI {
    pub fn get_message(&self) -> UnsignedMessageAPI {
        match self {
            MessageTxAPI::UnsignedMessageAPI(unsigned_message_api) => {
                unsigned_message_api.to_owned()
            }
            MessageTxAPI::SignedMessageAPI(signed_message_api) => {
                signed_message_api.message.to_owned()
            }
        }
    }
}

/// Structure containing an `UnsignedMessage` or a `SignedMessage` from forest_address
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum MessageTx {
    UnsignedMessage(UnsignedMessage),
    SignedMessage(SignedMessage),
}

/// Message structure with network parameter
pub struct MessageTxNetwork {
    pub message_tx: MessageTx,
    pub testnet: bool,
}

impl From<&Signature> for SignatureAPI {
    fn from(sig: &Signature) -> SignatureAPI {
        match sig {
            Signature::SignatureSECP256K1(sig_secp256k1) => SignatureAPI {
                sig_type: SigTypes::SigTypeSecp256k1 as u8,
                data: sig_secp256k1.0.to_vec(),
            },
            Signature::SignatureBLS(sig_bls) => SignatureAPI {
                sig_type: SigTypes::SigTypeBLS as u8,
                data: sig_bls.0.to_vec(),
            },
        }
    }
}

mod serde_base64_vector {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(v: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64::encode(v))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        base64::decode(s).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<MessageTxNetwork> for MessageTxAPI {
    type Error = SignerError;

    fn try_from(message_tx_network: MessageTxNetwork) -> Result<MessageTxAPI, Self::Error> {
        let network = if message_tx_network.testnet {
            Network::Testnet
        } else {
            Network::Mainnet
        };

        match message_tx_network.message_tx {
            MessageTx::UnsignedMessage(message_tx) => {
                let mut to_address: forest_address::Address = message_tx.to().to_owned();
                to_address.set_network(network);

                let mut from_address: forest_address::Address = message_tx.from().to_owned();
                from_address.set_network(network);

                let tmp = UnsignedMessageAPI::from(message_tx);

                let unsigned_message_user_api = UnsignedMessageAPI {
                    to: to_address.to_string(),
                    from: from_address.to_string(),
                    ..tmp
                };

                Ok(MessageTxAPI::UnsignedMessageAPI(unsigned_message_user_api))
            }
            MessageTx::SignedMessage(message_tx) => {
                let mut to_address: forest_address::Address = message_tx.to().to_owned();
                to_address.set_network(network);

                let mut from_address: forest_address::Address = message_tx.from().to_owned();
                from_address.set_network(network);

                let tmp = UnsignedMessageAPI::from(message_tx.message().clone());

                let unsigned_message_user_api = UnsignedMessageAPI {
                    to: to_address.to_string(),
                    from: from_address.to_string(),
                    ..tmp
                };

                let y = Signature::try_from(message_tx.signature().bytes().to_vec())?;

                let signed_message_api = SignedMessageAPI {
                    message: unsigned_message_user_api,
                    signature: SignatureAPI::from(&y),
                };

                Ok(MessageTxAPI::SignedMessageAPI(signed_message_api))
            }
        }
    }
}

impl From<MessageTx> for MessageTxAPI {
    fn from(message_tx: MessageTx) -> MessageTxAPI {
        match message_tx {
            MessageTx::UnsignedMessage(message_tx) => {
                MessageTxAPI::UnsignedMessageAPI(UnsignedMessageAPI::from(message_tx))
            }
            MessageTx::SignedMessage(message_tx) => {
                MessageTxAPI::SignedMessageAPI(SignedMessageAPI::from(message_tx))
            }
        }
    }
}

impl TryFrom<&UnsignedMessageAPI> for UnsignedMessage {
    type Error = SignerError;

    fn try_from(message_api: &UnsignedMessageAPI) -> Result<UnsignedMessage, Self::Error> {
        let to = Address::from_str(&message_api.to)
            .map_err(|err| SignerError::GenericString(err.to_string()))?;
        let from = Address::from_str(&message_api.from)
            .map_err(|err| SignerError::GenericString(err.to_string()))?;
        let value = BigUint::from_str(&message_api.value)?;
        let gas_limit = message_api.gas_limit;
        let gas_price = BigUint::from_str(&message_api.gas_price)?;

        // FIXME: use trait instead of a match ?
        let params = match message_api.params.clone() {
            MessageParams::MessageParamsEmpty(_) => forest_vm::Serialized::new(Vec::new()),
            MessageParams::MessageParamsMultisig(multisig_params) => {
                let params = ExecParams::try_from(multisig_params)?;

                forest_vm::Serialized::serialize::<ExecParams>(params)
                    .map_err(|err| SignerError::GenericString(err.to_string()))?
            }
            MessageParams::ProposeParamsMultisig(multisig_proposal_params) => {
                let params = ProposeParams::try_from(multisig_proposal_params)?;

                forest_vm::Serialized::serialize::<ProposeParams>(params)
                    .map_err(|err| SignerError::GenericString(err.to_string()))?
            }
            MessageParams::TxnIDParamsMultisig(multisig_txn_id_params) => {
                let params = TxnIDParams::try_from(multisig_txn_id_params)?;

                forest_vm::Serialized::serialize::<TxnIDParams>(params)
                    .map_err(|err| SignerError::GenericString(err.to_string()))?
            }
        };

        let tmp = UnsignedMessage::builder()
            .to(to)
            .from(from)
            .sequence(message_api.nonce)
            .value(value)
            .method_num(message_api.method)
            .params(params)
            .gas_limit(gas_limit)
            .gas_price(gas_price)
            .build()
            .map_err(SignerError::GenericString)?;

        Ok(tmp)
    }
}

impl From<UnsignedMessage> for UnsignedMessageAPI {
    fn from(unsigned_message: UnsignedMessage) -> UnsignedMessageAPI {
        UnsignedMessageAPI {
            to: unsigned_message.to().to_string(),
            from: unsigned_message.from().to_string(),
            nonce: unsigned_message.sequence(),
            value: unsigned_message.value().to_string(),
            gas_price: unsigned_message.gas_price().to_string(),
            gas_limit: unsigned_message.gas_limit(),
            // FIXME: cannot extract method byte. Set always as 0
            method: 0,
            // FIXME: need a proper way to serialize parameters, for now
            // only method=0 is supported for keep empty
            params: MessageParams::MessageParamsEmpty("".to_string()),
        }
    }
}

impl From<SignedMessage> for SignedMessageAPI {
    fn from(signed_message: SignedMessage) -> SignedMessageAPI {
        SignedMessageAPI {
            message: UnsignedMessageAPI::from(signed_message.message().clone()),
            signature: SignatureAPI {
                sig_type: SigTypes::SigTypeSecp256k1 as u8,
                data: signed_message.signature().bytes().to_vec(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::api::UnsignedMessageAPI;
    use forest_encoding::{from_slice, to_vec};
    use forest_message::UnsignedMessage;
    use hex::{decode, encode};
    use std::convert::TryFrom;

    const EXAMPLE_UNSIGNED_MESSAGE: &str = r#"
        {
            "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
            "from": "t1xcbgdhkgkwht3hrrnui3jdopeejsoas2rujnkdi",
            "nonce": 1,
            "value": "100000",
            "gasprice": "2500",
            "gaslimit": 25000,
            "method": 0,
            "params": ""
        }"#;

    const EXAMPLE_CBOR_DATA: &str =
        "89005501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c6285501b882619d46558f3d9e316d11b48dcf211327025a0144000186a0430009c41961a80040";

    #[test]
    fn json_to_cbor() {
        let message_api: UnsignedMessageAPI =
            serde_json::from_str(EXAMPLE_UNSIGNED_MESSAGE).expect("FIXME");
        println!("{:?}", message_api);

        let message = UnsignedMessage::try_from(&message_api).expect("FIXME");

        let message_cbor: Vec<u8> = to_vec(&message).expect("Cbor serialization failed");
        let message_cbor_hex = encode(message_cbor);

        println!("{:?}", message_cbor_hex);
        assert_eq!(EXAMPLE_CBOR_DATA, message_cbor_hex)
    }

    #[test]
    fn cbor_to_json() {
        let cbor_buffer = decode(EXAMPLE_CBOR_DATA).expect("FIXME");

        let message: UnsignedMessage = from_slice(&cbor_buffer).expect("could not decode cbor");
        println!("{:?}", message);

        let message_user_api =
            UnsignedMessageAPI::try_from(message).expect("could not convert message");

        let message_user_api_json =
            serde_json::to_string_pretty(&message_user_api).expect("could not serialize as JSON");

        println!("{}", message_user_api_json);

        // FIXME: Add checks
    }
}
