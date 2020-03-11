//////! Fcservice RPC Client

use crate::service::error::ServiceError;
use filecoin_signer::api::UnsignedMessageAPI;
use filecoin_signer::utils::{from_hex_string, to_hex_string};
use filecoin_signer::{CborBuffer, Mnemonic, SecretKey, Signature};
use jsonrpc_core::{Id, MethodCall, Success, Version};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::convert::TryFrom;

pub async fn key_generate_mnemonic(_c: MethodCall) -> Result<Success, ServiceError> {
    let mnemonic = filecoin_signer::key_generate_mnemonic()?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: Value::from(mnemonic.0),
        id: Id::Num(1),
    };

    Ok(so)
}

#[derive(Debug, Deserialize, Serialize)]
pub struct KeyDeriveParamsAPI {
    pub mnemonic: String,
    pub path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct KeyDeriveResultApi {
    pub public_hexstring: String,
    pub private_hexstring: String,
    pub address: String,
}

pub async fn key_derive(c: MethodCall) -> Result<Success, ServiceError> {
    let params = c.params.parse::<KeyDeriveParamsAPI>()?;

    let (private, public, address) =
        filecoin_signer::key_derive(Mnemonic(params.mnemonic), params.path)?;

    let result = KeyDeriveResultApi {
        public_hexstring: to_hex_string(&public.0[..]),
        private_hexstring: to_hex_string(&private.0[..]),
        address,
    };

    let result_json = serde_json::to_value(&result)?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: result_json,
        id: Id::Num(1),
    };

    Ok(so)
}

pub async fn transaction_create(c: MethodCall) -> Result<Success, ServiceError> {
    let y = c.params.parse::<UnsignedMessageAPI>()?;
    let cbor_hexstring = filecoin_signer::transaction_serialize(y)?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: Value::from(cbor_hexstring.0),
        id: Id::Num(1),
    };

    Ok(so)
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TransctionParseParamsAPI {
    pub cbor_hex: String,
    pub testnet: bool,
}

pub async fn transaction_parse(c: MethodCall) -> Result<Success, ServiceError> {
    let params = c.params.parse::<TransctionParseParamsAPI>()?;

    let cbor_data = CborBuffer(from_hex_string(params.cbor_hex.as_ref()).unwrap());

    let message_parsed = filecoin_signer::transaction_parse(&cbor_data, params.testnet)?;

    let tx = serde_json::to_string(&message_parsed)?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: Value::from(tx),
        id: Id::Num(1),
    };

    Ok(so)
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SignTransactionParamsAPI {
    pub transaction: UnsignedMessageAPI,
    pub prvkey_hex: String,
}

pub async fn sign_transaction(c: MethodCall) -> Result<Success, ServiceError> {
    let params = c.params.parse::<SignTransactionParamsAPI>()?;

    let private_key = SecretKey::try_from(params.prvkey_hex)?;

    let signature = filecoin_signer::sign_transaction(params.transaction, &private_key)?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: Value::from(to_hex_string(&signature.0)),
        id: Id::Num(1),
    };

    Ok(so)
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VerifySignatureParamsAPI {
    pub signature_hex: String,
    pub message_hex: String,
}

pub async fn verify_signature(c: MethodCall) -> Result<Success, ServiceError> {
    let params = c.params.parse::<VerifySignatureParamsAPI>()?;

    let signature = Signature::try_from(params.signature_hex)?;
    let message = CborBuffer(from_hex_string(params.message_hex.as_ref()).unwrap());

    let result = filecoin_signer::verify_signature(&signature, &message)?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: Value::from(result),
        id: Id::Num(1),
    };

    Ok(so)
}

#[cfg(test)]
mod tests {
    use crate::service::client::get_nonce;
    use futures_await_test::async_test;

    #[ignore]
    #[async_test]
    async fn example_something_else_and_retrieve_nonce() {
        // FIXME: use configuration parameters instead
        let url = "https://lotus-dev.temporal.cloud/rpc/v0";
        let jwt = "some_token";
        let addr = "t1jdlfl73voaiblrvn2yfivvn5ifucwwv5f26nfza";

        let nonce = get_nonce(&url, &jwt, &addr).await;
        assert!(nonce.is_ok());
    }
}
