//////! Fcservice RPC Client

use jsonrpc_core::{MethodCall, Value, Version, Output, Success, Id};
use crate::service::client::get_nonce;

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
