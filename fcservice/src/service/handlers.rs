////! Fcservice RPC Client

use jsonrpc_core::Call;

use crate::service::methods;

pub async fn get_status() -> Result<impl warp::Reply, warp::Rejection> {
    let message = format!("Filecoin Signing Service");
    Ok(warp::reply::html(message))
    // TODO: return some information about the service status
}

pub async fn get_api_v0() -> Result<impl warp::Reply, warp::Rejection> {
    println!("Received JSONRPC GET. ");
    // TODO: return some information about the service API?
    Ok(warp::reply::html(format!("Document API here?")))
}

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
        Call::Invalid { id: _ } => {
            return Err(warp::reject::not_found());
        }
    };

    match reply {
        Ok(ok_reply) => Ok(warp::reply::json(&ok_reply)),
        Err(err) => {
            println!("{:?}", err);
            return Err(warp::reject::not_found());
        }
    }
}
