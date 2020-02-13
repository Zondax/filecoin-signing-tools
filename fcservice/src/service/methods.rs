//////! Fcservice RPC Client

use crate::service::client::get_nonce;
use crate::service::utils::{from_hex_string, to_hex_string};
use fcsigner::api::UnsignedMessageUserAPI;
use jsonrpc_core::types::params::Params;
use jsonrpc_core::{Id, MethodCall, Output, Success, Value, Version};
use secp256k1::SecretKey;

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

pub async fn sign_transaction(c: MethodCall) -> anyhow::Result<Output> {
    let y = c.params.parse::<Vec<Value>>()?;

    // Review : Doesn't seem right... but working.
    let t: UnsignedMessageUserAPI = serde_json::from_str(&y[0].to_string())?;
    let prvkey_hex: String = serde_json::from_value(y[1].clone())?;
    let prvkey_bytes = from_hex_string(&prvkey_hex)?;
    let secret_key = SecretKey::parse_slice(&prvkey_bytes)?;

    let signature = fcsigner::sign_transaction(t, secret_key)?;

    let so = Output::Success(Success {
        jsonrpc: Some(Version::V2),
        result: Value::from(to_hex_string(&signature.serialize())),
        id: Id::Num(1),
    });

    Ok(so)
}

pub async fn verify_signature(c: MethodCall) -> anyhow::Result<Output> {
    let y = c.params.parse::<Vec<Value>>()?;

    let signature_hex: String = serde_json::from_value(y[0].clone())?;
    let signature = from_hex_string(&signature_hex)?;

    let message_hex: String = serde_json::from_value(y[1].clone())?;
    let message = from_hex_string(&message_hex)?;

    let pubkey_hex: String = serde_json::from_value(y[2].clone())?;
    let pubkey = from_hex_string(&pubkey_hex)?;

    let result = fcsigner::verify_signature(&signature, &message, &pubkey)?;

    let so = Output::Success(Success {
        jsonrpc: Some(Version::V2),
        result: Value::from(result),
        id: Id::Num(1),
    });

    Ok(so)
}

// FIXME: improve error types, move to thiserror?
pub async fn example_something_else_and_retrieve_nonce(_c: MethodCall) -> anyhow::Result<Output> {
    // FIXME: add lru cache

    let addr = String::from("some_address");
    let nonce = get_nonce(&addr).await?;

    let so = Output::Success(Success {
        jsonrpc: Some(Version::V2),
        result: Value::from(nonce),
        id: Id::Num(1),
    });

    Ok(so)
}
