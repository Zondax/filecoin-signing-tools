//////! Fcservice RPC Client

use crate::service::client::get_nonce;
use crate::service::error::ServiceError;
use fcsigner::api::UnsignedMessageUserAPI;
use jsonrpc_core::{Id, MethodCall, Success, Value, Version};

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
