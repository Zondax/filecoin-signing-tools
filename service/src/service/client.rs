////! Fcservice RPC Client

use crate::service::cache::{cache_get_nonce, cache_put_nonce};
use crate::service::error::RemoteNode::{EmptyNonce, InvalidNonce};
use crate::service::error::ServiceError;
use jsonrpc_core::response::Output::Success;
use jsonrpc_core::{Id, MethodCall, Params, Response, Version};
use serde_json::value::Value;
use std::sync::atomic::{AtomicU64, Ordering};

static CALL_ID: AtomicU64 = AtomicU64::new(1);

pub async fn get_nonce(url: &str, jwt: &str, addr: &str) -> Result<u64, ServiceError> {
    if let Some(nonce) = cache_get_nonce(addr) {
        return Ok(nonce);
    }

    let call_id = CALL_ID.fetch_add(1, Ordering::SeqCst);

    // Prepare request
    let m = MethodCall {
        jsonrpc: Some(Version::V2),
        method: "Filecoin.MpoolGetNonce".to_owned(),
        params: Params::Array(vec![Value::from(addr)]),
        id: Id::Num(call_id),
    };

    // Build request
    let client = reqwest::Client::new();
    let builder = client.post(url).bearer_auth(jwt).json(&m);

    // Send and wait for response
    let resp = builder.send().await?.json::<Response>().await?;

    // Handle response
    let nonce = match resp {
        Response::Single(Success(s)) => s.result.as_u64().ok_or(EmptyNonce)?,
        _ => return Err(ServiceError::RemoteNode(InvalidNonce)),
    };

    cache_put_nonce(addr, nonce);
    Ok(nonce)
}

pub async fn is_mainnet(_url: &str, _jwt: &str) -> Result<bool, ServiceError> {
    // FIXME: Check if the node behind the url is running mainnet or not
    // FIXME: https://github.com/Zondax/filecoin-rs/issues/32
    Err(ServiceError::NotImplemented)
}

pub async fn send_signed_tx(_url: &str, _jwt: &str) -> Result<bool, ServiceError> {
    // FIXME: Check if the node (url) is running mainnet or not
    // FIXME: https://github.com/Zondax/filecoin-rs/issues/33
    Err(ServiceError::NotImplemented)
}

pub async fn get_status(_url: &str, _jwt: &str) -> Result<bool, ServiceError> {
    // FIXME: Get tx status
    // FIXME: https://github.com/Zondax/filecoin-rs/issues/34
    Err(ServiceError::NotImplemented)
}
