////! Fcservice RPC Client

use jsonrpc_core::{Call, MethodCall, Version};

use crate::config::RemoteNodeSection;
use crate::service::error::ServiceError;
use crate::service::error::ServiceError::JSONRPC;
use crate::service::methods;
use jsonrpc_core::error::ErrorCode::ServerError;
use warp::{Rejection, Reply};

pub async fn v0_get_status(config: RemoteNodeSection) -> Result<impl Reply, Rejection> {
    let message = "Filecoin Signing Service".to_string();
    Ok(warp::reply::html(message))
    // TODO: return some information about the service status
}

pub async fn v0_get(config: RemoteNodeSection) -> Result<impl Reply, Rejection> {
    println!("Received JSONRPC GET. ");
    // TODO: return some information about the service API?
    Ok(warp::reply::html("Document API here?".to_string()))
}

pub async fn v0_post(request: Call, config: RemoteNodeSection) -> Result<impl Reply, Rejection> {
    return match request {
        Call::MethodCall(c) => v0_post_methods(c, config).await,
        _ => {
            return Err(warp::reject::not_found());
        }
    };
}

async fn v0_post_methods(
    method_call: MethodCall,
    config: RemoteNodeSection,
) -> Result<impl Reply, Rejection> {
    let method_id = method_call.id.clone();

    let reply = match &method_call.method[..] {
        "key_generate_mnemonic" => methods::key_generate_mnemonic(method_call, config).await,
        "key_derive" => methods::key_derive(method_call, config).await,
        "transaction_create" => methods::transaction_create(method_call, config).await,
        "transaction_parse" => methods::transaction_parse(method_call, config).await,
        "sign_transaction" => methods::sign_transaction(method_call, config).await,
        "verify_signature" => methods::verify_signature(method_call, config).await,
        "get_status" => methods::get_status(method_call, config).await,
        "get_nonce" => methods::get_nonce(method_call).await,
        _ => return Err(warp::reject::not_found()),
    };

    match reply {
        Ok(ok_reply) => Ok(warp::reply::json(&ok_reply)),
        Err(JSONRPC(err)) => {
            let json_err = jsonrpc_core::Failure {
                jsonrpc: Some(Version::V2),
                error: err,
                id: method_id,
            };
            Ok(warp::reply::json(&json_err))
        }
        Err(err) => {
            let json_err = jsonrpc_core::Failure {
                jsonrpc: Some(Version::V2),
                error: jsonrpc_core::Error {
                    code: ServerError(0),
                    message: err.to_string(),
                    data: None,
                },
                id: method_id,
            };
            Ok(warp::reply::json(&json_err))
        }
    }
}

impl warp::reject::Reject for ServiceError {}

#[cfg(test)]
mod tests {
    use crate::config::RemoteNodeSection;
    use crate::service::handlers::v0_post;
    use futures_await_test::async_test;
    use jsonrpc_core::{Call, Id, MethodCall, Params, Version};
    use warp::Reply;

    const TEST_URL: &str = "http://86.192.13.13:1234/rpc/v0";
    const JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBbGxvdyI6WyJyZWFkIiwid3JpdGUiLCJzaWduIiwiYWRtaW4iXX0.xK1G26jlYnAEnGLJzN1RLywghc4p4cHI6ax_6YOv0aI";

    #[async_test]
    async fn returns_jsonrpc_error_not_found() {
        let bad_call = Call::from(MethodCall {
            jsonrpc: Some(Version::V2),
            method: "invalid method".to_owned(),
            params: Params::None,
            id: Id::Num(1),
        });

        let config = RemoteNodeSection {
            url: TEST_URL.to_string(),
            jwt: JWT.to_string(),
        };

        let response = v0_post(bad_call, config).await;

        assert!(response.is_err());
        let err = response.err().unwrap();
        assert!(err.is_not_found());
    }

    #[async_test]
    async fn returns_jsonrpc_error_bad_params() {
        let bad_call = Call::from(MethodCall {
            jsonrpc: Some(Version::V2),
            method: "transaction_create".to_owned(),
            params: Params::None,
            id: Id::Num(1),
        });

        let config = RemoteNodeSection {
            url: TEST_URL.to_string(),
            jwt: JWT.to_string(),
        };

        let reply = v0_post(bad_call, config).await.unwrap();

        let response = reply.into_response();

        assert_eq!(response.status(), 200);

        let (_parts, body) = response.into_parts();
        let s = format!("{:?}", body);
        println!("{}", s);
    }
}
