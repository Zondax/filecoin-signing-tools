////! Fcservice RPC Client

use crate::service::cache::{cache_get_nonce, cache_put_nonce};
use crate::service::error::RemoteNode::{EmptyNonce, InvalidNonce, InvalidStatusRequest, JSONRPC};
use crate::service::error::ServiceError;
use jsonrpc_core::response::Output::{Success, Failure};
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
    let request = client.post(url).bearer_auth(jwt).json(&m).build()?;

    // Send and wait for response
    let kek = client.execute(request).await?;

    let resp = kek.json::<Response>().await?;

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

pub async fn get_status(url: &str, jwt: &str, cid_message: Value) -> Result<Value, ServiceError> {
    let call_id = CALL_ID.fetch_add(1, Ordering::SeqCst);

    // Prepare request
    let m = MethodCall {
        jsonrpc: Some(Version::V2),
        method: "Filecoin.ChainGetMessage".to_owned(),
        params: Params::Array(vec![Value::from(cid_message)]),
        id: Id::Num(call_id),
    };

    // Build request
    let client = reqwest::Client::new();
    let request = client.post(url).bearer_auth(jwt).json(&m).build()?;

    // Send and wait for response
    let resp = client.execute(request).await?;

    let ok = resp.json::<Response>().await?;

    // Handle response
    let transaction_status = match ok {
        Response::Single(Success(s)) => s.result,
        // REVIEW: if not mined yet return
        // "error":{"code":1,"message":"blockstore: block not found"}
        Response::Single(Failure(f)) => return Err(ServiceError::RemoteNode(JSONRPC(f.error))),
        _ => return Err(ServiceError::RemoteNode(InvalidStatusRequest)),
    };

    Ok(transaction_status)
}
