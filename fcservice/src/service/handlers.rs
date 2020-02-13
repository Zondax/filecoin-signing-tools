////! Fcservice RPC Client

use jsonrpc_core::{Call, Id, MethodCall, Version};

use crate::service::error::ServiceError;
use crate::service::error::ServiceError::{Signer, JSONRPC};
use crate::service::methods;
use warp::{Future, Rejection, Reply};

pub async fn get_status() -> Result<impl Reply, Rejection> {
    let message = "Filecoin Signing Service".to_string();
    Ok(warp::reply::html(message))
    // TODO: return some information about the service status
}

pub async fn get_api_v0() -> Result<impl Reply, Rejection> {
    println!("Received JSONRPC GET. ");
    // TODO: return some information about the service API?
    Ok(warp::reply::html("Document API here?".to_string()))
}

impl warp::reject::Reject for ServiceError {}

pub async fn post_api_v0_methods(method_call: MethodCall) -> Result<impl Reply, Rejection> {
    let method_id = method_call.id.clone();

    let reply = match &method_call.method[..] {
        "key_generate" => methods::key_generate(method_call).await,
        "key_derive" => methods::key_derive(method_call).await,
        "transaction_create" => methods::transaction_create(method_call).await,
        "transaction_parse" => methods::transaction_parse(method_call).await,
        _ => return Err(warp::reject::not_found()),
    };

    match reply {
        Ok(ok_reply) => Ok(warp::reply::json(&ok_reply)),
        Err(JSONRPC(err)) => Ok(warp::reply::json(&err)),
        Err(Signer(err)) => {
            let json_err = jsonrpc_core::Failure {
                jsonrpc: Some(Version::V2),
                error: jsonrpc_core::Error::invalid_params(format!("{}", err)),
                id: method_id,
            };
            Ok(warp::reply::json(&json_err))
        }
        Err(err) => Err(warp::reject::custom(err)),
    }
}

pub async fn post_api_v0(request: Call) -> Result<impl Reply, Rejection> {
    return match request {
        Call::MethodCall(c) => post_api_v0_methods(c).await,
        _ => {
            return Err(warp::reject::not_found());
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::service::handlers::post_api_v0;
    use futures_await_test::async_test;
    use jsonrpc_core::{Call, Id, MethodCall, Params, Version};

    #[test]
    fn do_nothing() {}

    #[async_test]
    async fn returns_jsonrpc_error_not_found() {
        let bad_call = Call::from(MethodCall {
            jsonrpc: Some(Version::V2),
            method: "invalid method".to_owned(),
            params: Params::None,
            id: Id::Num(1),
        });

        let response = post_api_v0(bad_call).await;

        match response {
            Ok(_) => assert!(false),
            Err(e) => {
                assert!(e.is_not_found());
            }
        }
    }

    #[async_test]
    async fn returns_jsonrpc_error_bad_params() {
        let bad_call = Call::from(MethodCall {
            jsonrpc: Some(Version::V2),
            method: "transaction_create".to_owned(),
            params: Params::None,
            id: Id::Num(1),
        });

        let response = post_api_v0(bad_call).await;
        match response {
            Ok(_) => assert!(false),
            Err(e) => {
                println!("{:?}", e);
            }
        }
    }
}
