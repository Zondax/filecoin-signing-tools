use std::convert::{TryFrom, TryInto};
use std::str::FromStr;

use forest_address::{Network};
use fvm_shared::address::{Address};
//use forest_cid::{multihash::MultihashDigest, Cid, Code::Identity};
use forest_crypto::signature;
use forest_message::{Message, SignedMessage, UnsignedMessage};
use forest_vm::Serialized;
use num_bigint_chainsafe::BigInt;
use serde::{Deserialize, Serialize, Serializer};

//use extras::{multisig, paych, ExecParams};
use fil_actor_multisig as multisig;
use fil_actor_paych as paych;
use fil_actor_init::ExecParams;
use fvm_shared::encoding::RawBytes;

use crate::error::SignerError;
use crate::signature::Signature;

pub enum SigTypes {
    SigTypeSecp256k1 = 0x01,
    SigTypeBLS = 0x02,
}

/// *crypto.Signature Go type:  specs-actors/actors/crytpo:Signature
#[cfg_attr(feature = "with-arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SpecsActorsCryptoSignature {
    pub typ: u8,
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

impl From<&SpecsActorsCryptoSignature> for SpecsActorsCryptoSignature {
    fn from(sig: &SpecsActorsCryptoSignature) -> Self {
        let d = sig.data.iter().copied().collect();
        SpecsActorsCryptoSignature {
            typ: sig.typ,
            data: d,
        }
    }
}

impl Serialize for SpecsActorsCryptoSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut v = Vec::<u8>::new();
        v.push(self.typ);
        v.extend(self.data.iter().copied());
        serde_bytes::Serialize::serialize(&v, serializer)
    }
}

#[cfg_attr(feature = "with-arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub enum MessageParams {
    MessageParamsSerialized(String),
    ExecParams(ExecParams),
    MultisigConstructorParams(multisig::ConstructorParams),
    ProposeParams(multisig::ProposeParams),
    TxnIDParams(multisig::TxnIDParams),
    AddSignerParams(multisig::AddSignerParams),
    RemoveSignerParams(multisig::RemoveSignerParams),
    SwapSignerParams(multisig::SwapSignerParams),
    ChangeNumApprovalsThresholdParams(multisig::ChangeNumApprovalsThresholdParams),
    LockBalanceParams(multisig::LockBalanceParams),
    PaychConstructorParams(paych::ConstructorParams),
    UpdateChannelStateParams(paych::UpdateChannelStateParams),
}

impl MessageParams {
    pub fn serialize(self) -> Result<RawBytes, SignerError> {
        let params_serialized = match self {
            MessageParams::MessageParamsSerialized(params_string) => {
                let params_bytes = base64::decode(&params_string)
                    .map_err(|err| SignerError::GenericString(err.to_string()))?;
                RawBytes::from(params_bytes)
            },
            params => {
                RawBytes::serialize(&params)
                    .map_err(|err| SignerError::GenericString(err.to_string()))?
            }
        };

        Ok(params_serialized)
    }
}

/// Unsigned message api structure
#[cfg_attr(feature = "with-arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct UnsignedMessageAPI {
    #[serde(alias = "To")]
    pub to: String,
    #[serde(alias = "From")]
    pub from: String,
    #[serde(alias = "Nonce")]
    pub nonce: u64,
    #[serde(alias = "Value")]
    pub value: String,

    #[serde(rename = "gaslimit")]
    #[serde(alias = "gasLimit")]
    #[serde(alias = "gas_limit")]
    #[serde(alias = "GasLimit")]
    pub gas_limit: i64,

    #[serde(rename = "gasfeecap")]
    #[serde(alias = "gasFeeCap")]
    #[serde(alias = "gas_fee_cap")]
    #[serde(alias = "GasFeeCap")]
    pub gas_fee_cap: String,

    #[serde(rename = "gaspremium")]
    #[serde(alias = "gasPremium")]
    #[serde(alias = "gas_premium")]
    #[serde(alias = "GasPremium")]
    pub gas_premium: String,

    #[serde(alias = "Method")]
    pub method: u64,
    #[serde(alias = "Params")]
    pub params: String,
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

/// Create multisig message api structure
#[cfg_attr(feature = "with-arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct CreateMultisigMessageAPI {
    #[serde(alias = "From")]
    pub from: String,
    #[serde(alias = "Nonce")]
    pub nonce: u64,
    #[serde(alias = "Value")]
    pub value: String,

    #[serde(rename = "gaslimit")]
    #[serde(alias = "gasLimit")]
    #[serde(alias = "gas_limit")]
    #[serde(alias = "GasLimit")]
    pub gas_limit: i64,

    #[serde(rename = "gasfeecap")]
    #[serde(alias = "gasFeeCap")]
    #[serde(alias = "gas_fee_cap")]
    #[serde(alias = "GasFeeCap")]
    pub gas_fee_cap: String,

    #[serde(rename = "gaspremium")]
    #[serde(alias = "gasPremium")]
    #[serde(alias = "gas_premium")]
    #[serde(alias = "GasPremium")]
    pub gas_premium: String,

    #[serde(alias = "Signers")]
    #[serde(alias = "signers")]
    pub signers: Vec<String>,

    #[serde(alias = "Threshold")]
    #[serde(alias = "threshold")]
    pub threshold: i64,

    #[serde(alias = "UnlockDuration")]
    #[serde(alias = "unlock_duration")]
    pub unlock_duration: i64,

    #[serde(alias = "StartEpoch")]
    #[serde(alias = "start_epoch")]
    pub start_epoch: i64,
}

/// Proposal message api structure
#[cfg_attr(feature = "with-arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct ProposalMessageParamsAPI {
    #[serde(alias = "Requester")]
    pub requester: String,

    #[serde(alias = "To")]
    pub to: String,

    #[serde(alias = "Value")]
    pub value: String,

    #[serde(alias = "Method")]
    pub method: u64,

    #[serde(alias = "Params")]
    pub params: String,
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

impl TryFrom<&SignatureAPI> for signature::Signature {
    type Error = SignerError;

    fn try_from(sig: &SignatureAPI) -> Result<signature::Signature, Self::Error> {
        match sig.sig_type {
            2 => (Ok(signature::Signature::new_bls(sig.data.to_vec()))),
            1 => (Ok(signature::Signature::new_secp256k1(sig.data.to_vec()))),
            _ => Err(SignerError::GenericString(
                "Unknown signature type.".to_string(),
            )),
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
            forest_address::Network::Testnet
        } else {
            forest_address::Network::Mainnet
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
        let to = forest_address::Address::from_str(&message_api.to)
            .map_err(|err| SignerError::GenericString(err.to_string()))?;
        let from = forest_address::Address::from_str(&message_api.from)
            .map_err(|err| SignerError::GenericString(err.to_string()))?;
        let value = BigInt::from_str(&message_api.value)?;
        let gas_limit = message_api.gas_limit;
        let gas_fee_cap = BigInt::from_str(&message_api.gas_fee_cap)?;
        let gas_premium = BigInt::from_str(&message_api.gas_premium)?;

        let message_params_bytes = base64::decode(&message_api.params)
            .map_err(|err| SignerError::GenericString(err.to_string()))?;
        let params = Serialized::new(message_params_bytes);

        let tmp = UnsignedMessage::builder()
            .to(to)
            .from(from)
            .sequence(message_api.nonce)
            .value(value)
            .method_num(message_api.method)
            .params(params)
            .gas_limit(gas_limit)
            .gas_premium(gas_premium)
            .gas_fee_cap(gas_fee_cap)
            .build()
            .map_err(SignerError::GenericString)?;

        Ok(tmp)
    }
}

impl From<UnsignedMessage> for UnsignedMessageAPI {
    fn from(unsigned_message: UnsignedMessage) -> UnsignedMessageAPI {
        let params_b64_string = base64::encode(unsigned_message.params().bytes());

        UnsignedMessageAPI {
            to: unsigned_message.to().to_string(),
            from: unsigned_message.from().to_string(),
            nonce: unsigned_message.sequence(),
            value: unsigned_message.value().to_string(),
            gas_limit: unsigned_message.gas_limit(),
            gas_fee_cap: unsigned_message.gas_fee_cap().to_string(),
            gas_premium: unsigned_message.gas_premium().to_string(),
            method: unsigned_message.method_num(),
            params: params_b64_string,
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

impl TryFrom<&SignedMessageAPI> for SignedMessage {
    type Error = SignerError;

    fn try_from(signed_message_api: &SignedMessageAPI) -> Result<SignedMessage, Self::Error> {
        let message = UnsignedMessage::try_from(&signed_message_api.message)?;
        let signature = signature::Signature::try_from(&signed_message_api.signature)?;

        Ok(SignedMessage { message, signature })
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use forest_encoding::{from_slice, to_vec};
    use forest_message::{SignedMessage, UnsignedMessage};
    use hex::{decode, encode};

    use crate::api::{SignedMessageAPI, UnsignedMessageAPI};

    const EXAMPLE_UNSIGNED_MESSAGE: &str = r#"
        {
            "to": "t17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
            "from": "t1xcbgdhkgkwht3hrrnui3jdopeejsoas2rujnkdi",
            "nonce": 1,
            "value": "100000",
            "gasfeecap": "1",
            "gaspremium": "1",
            "gaslimit": 25000,
            "method": 0,
            "params": ""
        }"#;

    const EXAMPLE_CBOR_DATA: &str =
        "8a005501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c6285501b882619d46558f3d9e316d11b48dcf211327025a0144000186a01961a84200014200010040";

    const EXAMPLE_CBOR_DATA_CONV: &str = "8a004300ec075501dfe49184d46adc8f89d44638beb45f78fcad259001401a000f4240430009c4430009c402581d845501dfe49184d46adc8f89d44638beb45f78fcad2590430003e80040";

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

        let message_user_api =
            UnsignedMessageAPI::try_from(message).expect("could not convert message");

        let message_user_api_json =
            serde_json::to_string_pretty(&message_user_api).expect("could not serialize as JSON");

        println!("{:?}", message_user_api_json);

        let message_api: UnsignedMessageAPI =
            serde_json::from_str(EXAMPLE_UNSIGNED_MESSAGE).expect("FIXME");

        assert_eq!(message_api, message_user_api)
    }

    #[test]
    fn conversion_unsigned_messages() {
        let cbor_bytes = decode(EXAMPLE_CBOR_DATA_CONV).unwrap();

        let message: UnsignedMessage = from_slice(&cbor_bytes).expect("could not decode cbor");

        let message_api: UnsignedMessageAPI =
            UnsignedMessageAPI::try_from(message.clone()).unwrap();

        let message_back = UnsignedMessage::try_from(&message_api).unwrap();

        assert_eq!(message, message_back);
    }

    #[test]
    fn conversion_signed_messages() {
        const EXAMPLE_SIGNED_MESSAGE: &str = r#"
        {
            "message": {
                "to": "f14ole2akjiw5qizembmw6r2e6yvj5ygmxgczervy",
                "from": "f1iuj7atowet37tsmeehwxfvyjv2pqhsnyvb6niay",
                "nonce": 37,
                "value": "1000000000000000",
                "gasfeecap": "1890700000",
                "gaspremium": "150000",
                "gaslimit": 2101318,
                "method": 0,
                "params": ""
            },
            "signature": {
                "type": 1,
                "data": "f3w5IcXFvWpWEAFp9LOAzixIsPjkgVaFx5XwynXx2sgZJ57yLIHLJi8CepHwoYeaWfZTRRUucHPARhi6iE2qqgA="
            }
        }"#;

        let signed_message: SignedMessageAPI =
            serde_json::from_str(EXAMPLE_SIGNED_MESSAGE).expect("FIXME");
        println!("{:?}", signed_message);

        let _signed_message = SignedMessage::try_from(&signed_message).expect("FIXME");

        assert!(true);
    }
}
