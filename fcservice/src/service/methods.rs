//////! Fcservice RPC Client

use crate::service::client;
use crate::service::error::ServiceError;
use fcsigner::api::UnsignedMessageUserAPI;
use fcsigner::utils::{from_hex_string, to_hex_string};
use jsonrpc_core::{Id, MethodCall, Success, Version};
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;

pub async fn key_generate_mnemonic(_c: MethodCall) -> Result<Success, ServiceError> {
    let mnemonic = fcsigner::key_generate_mnemonic()?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: Value::from(mnemonic),
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
    pub prvkey: String,
    pub pubkey: String,
    pub address: String,
}

pub async fn key_derive(c: MethodCall) -> Result<Success, ServiceError> {
    let y = c.params.parse::<KeyDeriveParamsAPI>()?;

    let (prvkey, pubkey, address) = fcsigner::key_derive(y.mnemonic, y.path)?;

    let result = KeyDeriveResultApi {
        prvkey,
        pubkey,
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
    let y = c.params.parse::<UnsignedMessageUserAPI>()?;
    let cbor_hexstring = fcsigner::transaction_create(y)?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: Value::from(cbor_hexstring),
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
    let message_parsed = fcsigner::transaction_parse(params.cbor_hex.as_bytes(), params.testnet)?;
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
    pub transaction: UnsignedMessageUserAPI,
    pub prvkey_hex: String,
}

pub async fn sign_transaction(c: MethodCall) -> Result<Success, ServiceError> {
    let params = c.params.parse::<SignTransactionParamsAPI>()?;

    let prvkey_bytes = from_hex_string(&params.prvkey_hex)?;

    let (signed_message, v) = fcsigner::sign_transaction(params.transaction, &prvkey_bytes)?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: Value::from([to_hex_string(&signed_message), format!("{:02x}", &v)].concat()),
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

    let signature = from_hex_string(&params.signature_hex)?;

    let result = fcsigner::verify_signature(&signature, &params.message_hex.as_bytes())?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: Value::from(result),
        id: Id::Num(1),
    };

    Ok(so)
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetStatusParamsAPI {
    pub cid_message: String,
}

pub async fn get_status(c: MethodCall) -> Result<Success, ServiceError> {
    // FIXME: get from file configuration
    let url = "http://86.192.13.13:1234/rpc/v0";
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBbGxvdyI6WyJyZWFkIiwid3JpdGUiLCJzaWduIiwiYWRtaW4iXX0.xK1G26jlYnAEnGLJzN1RLywghc4p4cHI6ax_6YOv0aI";

    let call_params = c.params.parse::<GetStatusParamsAPI>()?;
    let params = json!({"/": call_params.cid_message.to_string()});

    let status = client::get_status(&url, &jwt, params).await?;

    let so = Success {
        jsonrpc: Some(Version::V2),
        result: Value::from(status),
        id: Id::Num(1),
    };

    Ok(so)
}

#[cfg(test)]
mod tests {
    use crate::service::methods::get_status;
    use jsonrpc_core::{Id, MethodCall, Params, Version};
    use serde_json::json;

    #[tokio::test]
    async fn example_get_status_transaction() {
        let params_str = json!({ "cid_message": "bafy2bzaceaxm23epjsmh75yvzcecsrbavlmkcxnva66bkdebdcnyw3bjrc74u" });
        let params: Params =
            serde_json::from_str(&params_str.to_string()).expect("could not deserialize");

        let mc = MethodCall {
            jsonrpc: Some(Version::V2),
            method: "get_status".to_string(),
            params,
            id: Id::Num(0),
        };

        let status = get_status(mc).await;

        println!("{:?}", status);
    }
}
