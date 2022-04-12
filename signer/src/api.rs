use std::convert::TryFrom;
use std::str::FromStr;

use serde::{Deserialize, Serialize, Serializer};

use fvm_ipld_encoding::RawBytes;
use fvm_shared::message::Message;
use fvm_shared::crypto::signature::Signature;

use extras::init::ExecParamsAPI;
use extras::{multisig, paych, message::MessageAPI};

use crate::error::SignerError;

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum MessageParams {
    MessageParamsSerialized(String),
    #[serde(with = "ExecParamsAPI")]
    ExecParams(fil_actor_init::ExecParams),
    #[serde(with = "multisig::ConstructorParamsAPI")]
    MultisigConstructorParams(fil_actor_multisig::ConstructorParams),
    #[serde(with = "multisig::ProposeParamsAPI")]
    ProposeParams(fil_actor_multisig::ProposeParams),
    #[serde(with = "multisig::TxnIDParamsAPI")]
    TxnIDParams(fil_actor_multisig::TxnIDParams),
    #[serde(with = "multisig::AddSignerParamsAPI")]
    AddSignerParams(fil_actor_multisig::AddSignerParams),
    #[serde(with = "multisig::RemoveSignerParamsAPI")]
    RemoveSignerParams(fil_actor_multisig::RemoveSignerParams),
    #[serde(with = "multisig::SwapSignerParamsAPI")]
    SwapSignerParams(fil_actor_multisig::SwapSignerParams),
    #[serde(with = "multisig::ChangeNumApprovalsThresholdParamsAPI")]
    ChangeNumApprovalsThresholdParams(fil_actor_multisig::ChangeNumApprovalsThresholdParams),
    #[serde(with = "multisig::LockBalanceParamsAPI")]
    LockBalanceParams(fil_actor_multisig::LockBalanceParams),
    #[serde(with = "paych::ConstructorParamsAPI")]
    PaychConstructorParams(fil_actor_paych::ConstructorParams),
    #[serde(with = "paych::UpdateChannelStateParamsAPI")]
    UpdateChannelStateParams(fil_actor_paych::UpdateChannelStateParams),
}

impl MessageParams {
    pub fn serialize(self) -> Result<RawBytes, SignerError> {
        let params_serialized = match self {
            MessageParams::MessageParamsSerialized(params_string) => {
                let params_bytes = base64::decode(&params_string)
                    .map_err(|err| SignerError::GenericString(err.to_string()))?;
                RawBytes::from(params_bytes)
            }
            MessageParams::ExecParams(params) => RawBytes::serialize(&params)
                .map_err(|err| SignerError::GenericString(err.to_string()))?,
            MessageParams::MultisigConstructorParams(params) => RawBytes::serialize(&params)
                .map_err(|err| SignerError::GenericString(err.to_string()))?,
            MessageParams::ProposeParams(params) => RawBytes::serialize(&params)
                .map_err(|err| SignerError::GenericString(err.to_string()))?,
            MessageParams::TxnIDParams(params) => RawBytes::serialize(&params)
                .map_err(|err| SignerError::GenericString(err.to_string()))?,
            MessageParams::AddSignerParams(params) => RawBytes::serialize(&params)
                .map_err(|err| SignerError::GenericString(err.to_string()))?,
            MessageParams::RemoveSignerParams(params) => RawBytes::serialize(&params)
                .map_err(|err| SignerError::GenericString(err.to_string()))?,
            MessageParams::SwapSignerParams(params) => RawBytes::serialize(&params)
                .map_err(|err| SignerError::GenericString(err.to_string()))?,
            MessageParams::ChangeNumApprovalsThresholdParams(params) => {
                RawBytes::serialize(&params)
                    .map_err(|err| SignerError::GenericString(err.to_string()))?
            }
            MessageParams::LockBalanceParams(params) => RawBytes::serialize(&params)
                .map_err(|err| SignerError::GenericString(err.to_string()))?,
            MessageParams::PaychConstructorParams(params) => RawBytes::serialize(&params)
                .map_err(|err| SignerError::GenericString(err.to_string()))?,
            MessageParams::UpdateChannelStateParams(params) => RawBytes::serialize(&params)
                .map_err(|err| SignerError::GenericString(err.to_string()))?,
        };

        Ok(params_serialized)
    }
}

/// Signed message api structure
#[cfg_attr(feature = "with-arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct SignedMessageAPI {
    #[serde(with = "MessageAPI")]
    pub message: Message,
    #[serde(with = "json_signature")]
    pub signature: Signature,
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


#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use forest_encoding::{from_slice, to_vec};
    use forest_message::{SignedMessage, UnsignedMessage};
    use hex::{decode, encode};

    use crate::api::{SignedMessageAPI, UnsignedMessageAPI};

    const EXAMPLE_UNSIGNED_MESSAGE: &str = r#"
        {
            "to": "f17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
            "from": "f1xcbgdhkgkwht3hrrnui3jdopeejsoas2rujnkdi",
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
