////! Fcservice RPC Client

use jsonrpc_core::Call;

use crate::service::error::ServiceError;
use crate::service::methods;
use warp::Rejection;

pub async fn get_status() -> Result<impl warp::Reply, warp::Rejection> {
    let message = "Filecoin Signing Service".to_string();
    Ok(warp::reply::html(message))
    // TODO: return some information about the service status
}

pub async fn get_api_v0() -> Result<impl warp::Reply, warp::Rejection> {
    println!("Received JSONRPC GET. ");
    // TODO: return some information about the service API?
    Ok(warp::reply::html("Document API here?".to_string()))
}

impl warp::reject::Reject for ServiceError {}

pub async fn post_api_v0(request: Call) -> Result<impl warp::Reply, warp::Rejection> {
    let reply = match request {
        Call::MethodCall(c) if c.method == "key_generate" => methods::key_generate(c).await,
        Call::MethodCall(c) if c.method == "key_derive" => methods::key_derive(c).await,
        Call::MethodCall(c) if c.method == "transaction_create" => {
            methods::transaction_create(c).await
        }
        Call::MethodCall(c) if c.method == "transaction_parse" => {
            methods::transaction_parse(c).await
        }
        //        Call::MethodCall(c) if c.method == "sign_transaction" => {
        //            Ok(c.method.to_string())
        //        }
        //        Call::MethodCall(c) if c.method == "sign_message" => {
        //            Ok(c.method.to_string())
        //        }
        //        Call::MethodCall(c) if c.method == "verify_signature" => {
        //            Ok(c.method.to_string())
        //        }
        Call::MethodCall(_) => {
            return Err(warp::reject::not_found());
        }
        Call::Notification(_n) => {
            return Err(warp::reject::not_found());
        }
        Call::Invalid { .. } => {
            return Err(warp::reject::not_found());
        }
    };

    match reply {
        Ok(ok_reply) => Ok(warp::reply::json(&ok_reply)),
        Err(err) => {
            return Err(warp::reject::custom(err));
        }
    }
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
