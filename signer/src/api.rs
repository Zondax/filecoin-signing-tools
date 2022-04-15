use std::convert::TryFrom;

use serde::{Deserialize, Serialize};

use fvm_ipld_encoding::RawBytes;
use fvm_shared::message::Message;
use fvm_shared::crypto::signature::Signature;

use extras::init::ExecParamsAPI;
use extras::{multisig, paych, message::MessageAPI, signature::SignatureAPI};

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
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SignedMessageAPI {
    #[serde(with = "MessageAPI")]
    pub message: Message,
    #[serde(with = "SignatureAPI")]
    pub signature: Signature,
}

/// Structure containing an `UnsignedMessageAPI` or a `SignedMessageAPI`
#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub enum MessageTxAPI {
    #[serde(with = "MessageAPI")]
    Message(Message),
    SignedMessage(SignedMessageAPI),
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
    pub fn get_message(&self) -> Message {
        match self {
            MessageTxAPI::Message(message) => {
                message.to_owned()
            }
            MessageTxAPI::SignedMessage(signed_message) => {
                signed_message.message.to_owned()
            }
        }
    }
}

/// Message structure with network parameter
pub struct MessageTxNetwork {
    pub message_tx: MessageTxAPI,
    pub testnet: bool,
}

impl TryFrom<MessageTxNetwork> for MessageTxAPI {
    type Error = SignerError;

    fn try_from(message_tx_network: MessageTxNetwork) -> Result<MessageTxAPI, Self::Error> {
        let network = if message_tx_network.testnet {
            fvm_shared::address::Network::Testnet
        } else {
            fvm_shared::address::Network::Mainnet
        };

        match message_tx_network.message_tx {
            MessageTxAPI::Message(message_tx) => {
                let mut to_address: fvm_shared::address::Address = message_tx.to.to_owned();
                to_address.set_network(network);

                let mut from_address: fvm_shared::address::Address = message_tx.from.to_owned();
                from_address.set_network(network);

                let message_with_network = Message {
                    to: to_address,
                    from: from_address,
                    ..message_tx
                };

                Ok(MessageTxAPI::Message(message_with_network))
            }
            MessageTxAPI::SignedMessage(message_tx) => {
                let mut to_address: fvm_shared::address::Address = message_tx.message.to.to_owned();
                to_address.set_network(network);

                let mut from_address: fvm_shared::address::Address = message_tx.message.from.to_owned();
                from_address.set_network(network);

                let tmp = message_tx.message.clone();

                let message_with_network = Message {
                    to: to_address,
                    from: from_address,
                    ..tmp
                };

                let signed_message_api = SignedMessageAPI {
                    message: message_with_network,
                    signature: message_tx.signature,
                };

                Ok(MessageTxAPI::SignedMessage(signed_message_api))
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use fvm_ipld_encoding::{from_slice, to_vec};
    use hex::{decode, encode};

    use crate::api::{SignedMessageAPI, MessageTxAPI};

    const EXAMPLE_UNSIGNED_MESSAGE: &str = r#"
        {
            "To": "f17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
            "From": "f1xcbgdhkgkwht3hrrnui3jdopeejsoas2rujnkdi",
            "Nonce": 1,
            "Value": "100000",
            "GasFeeCap": "1",
            "GasPremium": "1",
            "GasLimit": 25000,
            "Method": 0,
            "Params": ""
        }"#;

    const EXAMPLE_CBOR_DATA: &str =
        "8a005501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c6285501b882619d46558f3d9e316d11b48dcf211327025a0144000186a01961a84200014200010040";

    //const EXAMPLE_CBOR_DATA_CONV: &str = "8a004300ec075501dfe49184d46adc8f89d44638beb45f78fcad259001401a000f4240430009c4430009c402581d845501dfe49184d46adc8f89d44638beb45f78fcad2590430003e80040";

    #[test]
    fn json_to_cbor() {
        let message_api : MessageTxAPI =
            serde_json::from_str(EXAMPLE_UNSIGNED_MESSAGE).expect("FIXME");

        let message = match message_api {
            MessageTxAPI::Message(msg) => msg,
            _ => panic!("Shouldn't be SignedMessage"),
        };

        let message_cbor: Vec<u8> = to_vec(&message).expect("Cbor serialization failed");
        let message_cbor_hex = encode(message_cbor);

        assert_eq!(EXAMPLE_CBOR_DATA, message_cbor_hex)
    }

    #[test]
    fn cbor_to_json() {
        let cbor_buffer = decode(EXAMPLE_CBOR_DATA).expect("FIXME");

        let message = MessageTxAPI::Message(from_slice(&cbor_buffer).expect("could not decode cbor"));

        let message_json =
            serde_json::to_string_pretty(&message).expect("could not serialize as JSON");

        const EXPECTED_MESSAGE_JSON: &str = r#"{
  "From": "f1xcbgdhkgkwht3hrrnui3jdopeejsoas2rujnkdi",
  "To": "f17uoq6tp427uzv7fztkbsnn64iwotfrristwpryy",
  "Sequence": 1,
  "Value": "100000",
  "MethodNum": 0,
  "Params": "",
  "GasLimit": 25000,
  "GasFeeCap": "1",
  "GasPremium": "1"
}"#;

        assert_eq!(EXPECTED_MESSAGE_JSON, message_json)
    }

    #[test]
    fn conversion_signed_messages() {
        const EXAMPLE_SIGNED_MESSAGE: &str = r#"{
  "Message": {
    "From": "f1iuj7atowet37tsmeehwxfvyjv2pqhsnyvb6niay",
    "To": "f14ole2akjiw5qizembmw6r2e6yvj5ygmxgczervy",
    "Sequence": 37,
    "Value": "1000000000000000",
    "MethodNum": 0,
    "Params": "",
    "GasLimit": 2101318,
    "GasFeeCap": "1890700000",
    "GasPremium": "150000"
  },
  "Signature": {
    "Type": 1,
    "Data": "f3w5IcXFvWpWEAFp9LOAzixIsPjkgVaFx5XwynXx2sgZJ57yLIHLJi8CepHwoYeaWfZTRRUucHPARhi6iE2qqgA="
  }
}"#;

        let message_api: MessageTxAPI =
            serde_json::from_str(EXAMPLE_SIGNED_MESSAGE).expect("FIXME");

        let signed_message = match message_api {
            MessageTxAPI::SignedMessage(smsg) => smsg,
            _ => panic!("Shouldn't be Message"),
        };

        let signed_message_json =
        serde_json::to_string_pretty(&signed_message).expect("could not serialize as JSON");

        assert_eq!(EXAMPLE_SIGNED_MESSAGE, signed_message_json);
    }
}
