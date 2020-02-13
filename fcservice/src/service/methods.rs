//////! Fcservice RPC Client

use crate::service::client::get_nonce;
use crate::service::error::ServiceError;
use crate::service::utils::{from_hex_string, to_hex_string};
use fcsigner::api::UnsignedMessageUserAPI;
use jsonrpc_core::{Id, MethodCall, Success, Version};
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub async fn key_generate(_c: MethodCall) -> Result<Success, ServiceError> {
    Err(ServiceError::NotImplemented)
}

pub async fn key_derive(_c: MethodCall) -> Result<Success, ServiceError> {
    Err(ServiceError::NotImplemented)
}

pub async fn transaction_create(c: MethodCall) -> Result<Success, ServiceError> {
    let y = c.params.parse::<UnsignedMessageUserAPI>()?;
    let cbor_hexstring = fcsigner::transaction_create(y)?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: Value::from(cbor_hexstring),
        id: Id::Num(1),
    };

    Ok(so)
}

pub async fn transaction_parse(_c: MethodCall) -> Result<Success, ServiceError> {
    Err(ServiceError::NotImplemented)
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SignTransactionParamsAPI {
    pub transaction: UnsignedMessageUserAPI,
    pub prvkey_hex: String,
}

pub async fn sign_transaction(c: MethodCall) -> Result<Success, ServiceError> {
    let params = c.params.parse::<SignTransactionParamsAPI>()?;

    let prvkey_bytes = from_hex_string(&params.prvkey_hex)?;
    let secret_key = SecretKey::parse_slice(&prvkey_bytes)?;

    let signature = fcsigner::sign_transaction(params.transaction, secret_key)?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: Value::from(to_hex_string(&signature.serialize())),
        id: Id::Num(1),
    };

    Ok(so)
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VerifySignatureParamsAPI {
    pub signature_hex: String,
    pub message_hex: String,
    pub pubkey_hex: String,
}

pub async fn verify_signature(c: MethodCall) -> Result<Success, ServiceError> {
    let params = c.params.parse::<VerifySignatureParamsAPI>()?;

    let signature = from_hex_string(&params.signature_hex)?;
    let message = from_hex_string(&params.message_hex)?;
    let pubkey = from_hex_string(&params.pubkey_hex)?;

    let result = fcsigner::verify_signature(&signature, &message, &pubkey)?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: Value::from(result),
        id: Id::Num(1),
    };

    Ok(so)
}

pub async fn example_something_else_and_retrieve_nonce(
    _c: MethodCall,
) -> Result<Success, ServiceError> {
    // FIXME: add lru cache

    let addr = String::from("some_address");
    let nonce = get_nonce(&addr).await?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: Value::from(nonce),
        id: Id::Num(1),
    };

    Ok(so)
}
