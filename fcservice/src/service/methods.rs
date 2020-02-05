//////! Fcservice RPC Client

use crate::service::client::get_nonce;
use fcsigner::api::UnsignedMessageUserAPI;
use jsonrpc_core::{Id, MethodCall, Output, Success, Value, Version};

// FIXME: improve error types, move to thiserror?
pub async fn key_generate(_c: MethodCall) -> anyhow::Result<Output> {
    Err(anyhow::anyhow!("not implemented"))
}

pub async fn key_derive(_c: MethodCall) -> anyhow::Result<Output> {
    Err(anyhow::anyhow!("not implemented"))
}

pub async fn transaction_create(c: MethodCall) -> anyhow::Result<Output> {
    let y = c.params.parse::<UnsignedMessageUserAPI>()?;
    let cbor_hexstring = fcsigner::transaction_create(y)?;

    let so = Output::Success(Success {
        jsonrpc: Some(Version::V2),
        result: Value::from(cbor_hexstring),
        id: Id::Num(1),
    });

    Ok(so)
}

pub async fn transaction_parse(_c: MethodCall) -> anyhow::Result<Output> {
    Err(anyhow::anyhow!("not implemented"))
}

// FIXME: improve error types, move to thiserror?
pub async fn example_something_else_and_retrieve_nonce(_c: MethodCall) -> anyhow::Result<Output> {
    // FIXME: add lru cache

    let nonce = get_nonce().await?;

    let so = Output::Success(Success {
        jsonrpc: Some(Version::V2),
        result: Value::from(nonce),
        id: Id::Num(1),
    });

    Ok(so)
}
