//////! Fcservice RPC Client

use crate::service::client::get_nonce;
use jsonrpc_core::{Id, MethodCall, Output, Success, Value, Version};

// FIXME: improve error types, move to thiserror?
pub async fn method_key_generate(_c: MethodCall) -> Output {
    // FIXME: add lru cache

    // FIXME: remove unwrap
    let nonce = get_nonce().await.unwrap();

    let so = Output::Success(Success {
        jsonrpc: Some(Version::V2),
        result: Value::from(nonce),
        id: Id::Num(1),
    });

    so
}
