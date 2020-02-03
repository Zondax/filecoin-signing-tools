use forest_address::Address;
use forest_message::{Message, UnsignedMessage};
use hex::decode;
use num_bigint_chainsafe::BigUint;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use vm::{MethodNum, Serialized, TokenAmount};

#[derive(Debug, Deserialize, Serialize)]
pub struct UnsignedMessageUserAPI {
    to: String,
    from: String,
    nonce: u64,
    value: String,
    // bigint
    gas_price: String,
    gas_limit: String,
    method: u64,
    params: String,
}

impl From<UnsignedMessageUserAPI> for UnsignedMessage {
    fn from(message_api: UnsignedMessageUserAPI) -> UnsignedMessage {
        let to = Address::from_str(&message_api.to).unwrap();
        let value = BigUint::from_str(&message_api.value).expect("could not read value");
        let gas_limit =
            BigUint::from_str(&message_api.gas_limit).expect("could not read gas_limit");
        let gas_price =
            BigUint::from_str(&message_api.gas_price).expect("could not read gas_price");

        UnsignedMessage::builder()
            .to(to)
            .from(Address::from_str(&message_api.from).unwrap())
            .sequence(message_api.nonce)
            .value(TokenAmount(value))
            // FIXME:
            .method_num(MethodNum::new(message_api.method))
            // FIXME:
            .params(Serialized::new(decode(message_api.params).unwrap()))
            .gas_limit(gas_limit)
            .gas_price(gas_price)
            .build()
            .unwrap()
    }
}

impl From<UnsignedMessage> for UnsignedMessageUserAPI {
    fn from(unsigned_message: UnsignedMessage) -> UnsignedMessageUserAPI {
        let value = unsigned_message.value().0.to_string();
        let gas_price = unsigned_message.gas_price().to_string();
        let gas_limit = unsigned_message.gas_limit().to_string();

        UnsignedMessageUserAPI {
            to: unsigned_message.to().to_string(),
            from: unsigned_message.from().to_string(),
            nonce: unsigned_message.sequence(),
            value: value,
            gas_price: gas_price,
            gas_limit: gas_limit,
            // FIXME: cannot extract method byte. Set always as 0
            method: 0,
            // FIXME: need a proper way to serialize parameters, for now
            // only method=0 is supported for keep empty
            params: "".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::api::UnsignedMessageUserAPI;
    use forest_encoding::{from_slice, to_vec};
    use forest_message::UnsignedMessage;
    use hex::{decode, encode};

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
            serde_json::from_str(EXAMPLE_UNSIGNED_MESSAGE).unwrap();
        println!("{:?}", message_api);

        let message = UnsignedMessage::from(message_api);

        let message_cbor: Vec<u8> = to_vec(&message).expect("Cbor serialization failed");
        let message_cbor_hex = encode(message_cbor);

        println!("{:?}", message_cbor_hex);
        assert_eq!(EXAMPLE_CBOR_DATA, message_cbor_hex)

        // FIXME: Add checks
    }

    #[test]
    fn cbor_to_json() {
        let cbor_buffer = decode(EXAMPLE_CBOR_DATA).unwrap();

        let message: UnsignedMessage = from_slice(&cbor_buffer).expect("could not decode cbor");
        println!("{:?}", message);

        let message_user_api = UnsignedMessageUserAPI::from(message);

        let message_user_api_json =
            serde_json::to_string_pretty(&message_user_api).expect("could not serialize as JSON");

        println!("{}", message_user_api_json);

        // FIXME: Add checks
    }
}
