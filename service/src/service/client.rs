////! Filecoin service RPC Client

use crate::service::cache::{cache_get_nonce, cache_put_nonce};
use crate::service::error::RemoteNode::{EmptyNonce, InvalidNonce, InvalidStatusRequest, JSONRPC};
use crate::service::error::ServiceError;
use abscissa_core::tracing::info;
use jsonrpc_core::response::Output::{Failure, Success};
use jsonrpc_core::{Id, MethodCall, Params, Response, Version};
use serde_json::value::Value;
use std::sync::atomic::{AtomicU64, Ordering};

static CALL_ID: AtomicU64 = AtomicU64::new(1);

pub async fn make_rpc_call(url: &str, jwt: &str, m: &MethodCall) -> Result<Response, ServiceError> {
    let client = reqwest::Client::new();
    let request = client.post(url).bearer_auth(jwt).json(&m).build()?;
    let node_answer = client.execute(request).await?;

    ///// FIXME: This block is a workaround for a non-standard Lotus answer
    let mut workaround = node_answer.json::<Value>().await?;
    let obj = workaround.as_object_mut().unwrap();

    if obj.contains_key("error") {
        obj.remove("result");
    }

    let fixed_value = serde_json::Value::Object(obj.clone());
    let resp: Response = serde_json::from_value(fixed_value)?;
    //////////////////

    Ok(resp)
}

pub async fn get_nonce(url: &str, jwt: &str, addr: &str) -> Result<u64, ServiceError> {
    // FIXME: reactivate cache and make it configurable
    // if let Some(nonce) = cache_get_nonce(addr) {
    //     return Ok(nonce);
    // }

    let call_id = CALL_ID.fetch_add(1, Ordering::SeqCst);

    // Prepare request
    let m = MethodCall {
        jsonrpc: Some(Version::V2),
        method: "Filecoin.MpoolGetNonce".to_owned(),
        params: Params::Array(vec![Value::from(addr)]),
        id: Id::Num(call_id),
    };

    let resp = make_rpc_call(url, jwt, &m).await?;

    // Handle response
    let nonce = match resp {
        Response::Single(Success(s)) => s.result.as_u64().ok_or(EmptyNonce)?,
        _ => return Err(ServiceError::RemoteNode(InvalidNonce)),
    };

    // cache_put_nonce(addr, nonce);
    Ok(nonce)
}

pub async fn is_mainnet(_url: &str, _jwt: &str) -> Result<bool, ServiceError> {
    // FIXME: Check if the node behind the url is running mainnet or not
    // FIXME: https://github.com/Zondax/filecoin-rs/issues/32
    Err(ServiceError::NotImplemented)
}

pub async fn send_signed_tx(url: &str, jwt: &str, signed_tx: Value) -> Result<Value, ServiceError> {
    let call_id = CALL_ID.fetch_add(1, Ordering::SeqCst);

    let params = Params::Array(vec![signed_tx]);

    info!("[send_signed_tx] params: {:?}", params);

    // Prepare request
    let m = MethodCall {
        jsonrpc: Some(Version::V2),
        method: "Filecoin.MpoolPush".to_owned(),
        params,
        id: Id::Num(call_id),
    };

    let resp = make_rpc_call(url, jwt, &m).await?;

    // Handle response
    let result = match resp {
        Response::Single(Success(s)) => s.result,
        Response::Single(Failure(f)) => return Err(ServiceError::RemoteNode(JSONRPC(f.error))),
        _ => return Err(ServiceError::RemoteNode(InvalidStatusRequest)),
    };

    Ok(result)
}

pub async fn get_status(url: &str, jwt: &str, cid_message: Value) -> Result<Value, ServiceError> {
    let call_id = CALL_ID.fetch_add(1, Ordering::SeqCst);

    let params = Params::Array(vec![cid_message]);

    // Prepare request
    let m = MethodCall {
        jsonrpc: Some(Version::V2),
        method: "Filecoin.ChainGetMessage".to_owned(),
        params,
        id: Id::Num(call_id),
    };

    let resp = make_rpc_call(url, jwt, &m).await?;

    // Handle response
    let result = match resp {
        Response::Single(Success(s)) => s.result,
        // REVIEW: if not mined yet return
        // "error":{"code":1,"message":"blockstore: block not found"}
        Response::Single(Failure(f)) => return Err(ServiceError::RemoteNode(JSONRPC(f.error))),
        _ => return Err(ServiceError::RemoteNode(InvalidStatusRequest)),
    };

    Ok(result)
}

#[cfg(test)]
mod tests {
    use crate::service::client::{get_nonce, get_status};
    use crate::service::test_helper::tests;

    use jsonrpc_core::types::error::{Error, ErrorCode};
    use jsonrpc_core::Response;
    use serde_json::json;

    #[tokio::test]
    async fn decode_error() {
        let data = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":1,\"message\":\"cbor input had wrong number of fields\"}}\n";

        let _err: Response = serde_json::from_slice(data).unwrap();
    }

    #[tokio::test]
    async fn example_something_else_and_retrieve_nonce() {
        let addr = "t02";

        let credentials = tests::get_remote_credentials();
        let nonce = get_nonce(&credentials.url, &credentials.jwt, &addr).await;

        println!("{:?}", nonce);

        assert!(nonce.is_ok());
    }

    #[tokio::test]
    async fn example_get_status_transaction() {
        let params =
            json!({ "/": "bafy2bzacea2ob4bctlucgp2okbczqvk5ctx4jqjapslz57mbcmnnzyftgeqgu" });

        let expected_response = json!({
            "To":"t1lv32q33y64xs64pnyn6om7ftirax5ikspkumwsa",
            "From":"t3wjxuftije2evjmzo2yoy5ghfe2o42mavrpmwuzooghzcxdhqjdu7kn6dvkzf4ko37w7sfnnzdzstcjmeooea",
            "Nonce":66867,
            "Value":"5000000000000000",
            "GasPrice":"0",
            "GasLimit":"1000",
            "Method":0,
            "Params":""
        });

        let credentials = tests::get_remote_credentials();
        let status = get_status(&credentials.url, &credentials.jwt, params)
            .await
            .unwrap();

        println!("{:?}", status);

        assert_eq!(status, expected_response);
    }

    #[tokio::test]
    async fn example_get_status_transaction_fail() {
        let params =
            json!({ "/": "bafy2bzaceaxm23epjsmh75yvzcecsrbavlmkcxnva66bkdebdcnyw3bjrc74u" });

        let credentials = tests::get_remote_credentials();
        let status = get_status(&credentials.url, &credentials.jwt, params).await;

        println!("{:?}", status);
        let _err_jsonrpc = Error {
            code: ErrorCode::ServerError(1),
            message: "cbor input had wrong number of fields".to_string(),
            data: None,
        };

        assert!(status.is_err());
        //assert!(status.contains_err(&error::ServiceError::JSONRPC(err_jsonrpc)));
    }

    #[tokio::test]
    async fn example_get_status_transaction_fail_2() {
        let params =
            json!({ "/": "bafy2bzacedbo3svni7n2jb57exuqh4v5zvjjethf3p74zgv7yfdtczce2yu4u" });

        let credentials = tests::get_remote_credentials();
        let status = get_status(&credentials.url, &credentials.jwt, params).await;

        println!("{:?}", status);
        assert!(status.is_err());
    }
}
