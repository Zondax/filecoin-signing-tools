use crate::error::SignerError;
use forest_address::Address;
use forest_message::{Message, SignedMessage, UnsignedMessage};
use hex::{decode, encode};
use num_bigint_chainsafe::BigUint;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::str::FromStr;
use vm::{MethodNum, Serialized, TokenAmount};

#[derive(Debug, Deserialize, Serialize)]
pub struct UnsignedMessageUserAPI {
    pub to: String,
    pub from: String,
    pub nonce: u64,
    pub value: String,
    pub gas_price: String,
    pub gas_limit: String,
    pub method: u64,
    pub params: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SignedMessageUserAPI {
    pub message: UnsignedMessageUserAPI,
    pub signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum MessageTxUserAPI {
    UnsignedMessageUserAPI(UnsignedMessageUserAPI),
    SignedMessageUserAPI(SignedMessageUserAPI),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum MessageTx {
    UnsignedMessage(UnsignedMessage),
    SignedMessage(SignedMessage),
}

impl From<MessageTx> for MessageTxUserAPI {
    fn from(message_tx: MessageTx) -> MessageTxUserAPI {
        match message_tx {
            MessageTx::UnsignedMessage(message_tx) => {
                MessageTxUserAPI::UnsignedMessageUserAPI(UnsignedMessageUserAPI::from(message_tx))
            }
            MessageTx::SignedMessage(message_tx) => {
                MessageTxUserAPI::SignedMessageUserAPI(SignedMessageUserAPI::from(message_tx))
            }
        }
    }
}

impl TryFrom<UnsignedMessageUserAPI> for UnsignedMessage {
    type Error = SignerError;

    fn try_from(message_api: UnsignedMessageUserAPI) -> Result<UnsignedMessage, Self::Error> {
        let to = Address::from_str(&message_api.to)
            .map_err(|err| SignerError::GenericString(err.to_string()))?;
        let from = Address::from_str(&message_api.from)
            .map_err(|err| SignerError::GenericString(err.to_string()))?;
        let value = BigUint::from_str(&message_api.value)?;
        let gas_limit = BigUint::from_str(&message_api.gas_limit)?;
        let gas_price = BigUint::from_str(&message_api.gas_price)?;
        let params = Serialized::new(decode(message_api.params)?);

        let tmp = UnsignedMessage::builder()
            .to(to)
            .from(from)
            .sequence(message_api.nonce)
            .value(TokenAmount(value))
            .method_num(MethodNum::new(message_api.method))
            .params(params)
            .gas_limit(gas_limit)
            .gas_price(gas_price)
            .build()
            .map_err(|err| SignerError::GenericString(err))?;

        Ok(tmp)
    }
}

impl From<UnsignedMessage> for UnsignedMessageUserAPI {
    fn from(unsigned_message: UnsignedMessage) -> UnsignedMessageUserAPI {
        UnsignedMessageUserAPI {
            to: unsigned_message.to().to_string(),
            from: unsigned_message.from().to_string(),
            nonce: unsigned_message.sequence(),
            value: unsigned_message.value().0.to_string(),
            gas_price: unsigned_message.gas_price().to_string(),
            gas_limit: unsigned_message.gas_limit().to_string(),
            // FIXME: cannot extract method byte. Set always as 0
            method: 0,
            // FIXME: need a proper way to serialize parameters, for now
            // only method=0 is supported for keep empty
            params: "".to_owned(),
        }
    }
}

impl From<SignedMessage> for SignedMessageUserAPI {
    fn from(signed_message: SignedMessage) -> SignedMessageUserAPI {
        SignedMessageUserAPI {
            message: UnsignedMessageUserAPI::from(signed_message.message().clone()),
            signature: encode(signed_message.signature().bytes()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::api::UnsignedMessageUserAPI;
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
            "gas_price": "2500",
            "gas_limit": "25000",
            "method": 0,
            "params": ""
        }"#;

    const EXAMPLE_CBOR_DATA: &str =
        "885501fd1d0f4dfcd7e99afcb99a8326b7dc459d32c6285501b882619d46558f3d9e316d11b48dcf211327025a0144000186a0430009c4430061a80040";

    #[test]
    fn json_to_cbor() {
        let message_api: UnsignedMessageUserAPI =
            serde_json::from_str(EXAMPLE_UNSIGNED_MESSAGE).expect("FIXME");
        println!("{:?}", message_api);

        let message = UnsignedMessage::try_from(message_api).expect("FIXME");

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
            UnsignedMessageUserAPI::try_from(message).expect("could not convert message");

        let message_user_api_json =
            serde_json::to_string_pretty(&message_user_api).expect("could not serialize as JSON");

        println!("{}", message_user_api_json);

        // FIXME: Add checks
    }
}
