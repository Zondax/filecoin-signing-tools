use crate::prelude::*;
use std::net::SocketAddr;
use warp::Filter;
use crate::service::handlers::{get_api_v0, get_status, post_api_v0};
use jsonrpc_core::Call;

mod handlers;
mod client;
mod methods;

fn jsonrpc_body() -> impl Filter<Extract=(Call, ), Error=warp::Rejection> + Clone {
    // When accepting a body, we want a JSON body and to reject huge payloads)...
    const MAX_SIZE: u64 = 1024 * 16;
    warp::body::content_length_limit(MAX_SIZE).and(warp::body::json())
}

#[tokio::main]
pub async fn service_main() {
    let config = app_config();
    println!("Remote URL    : {}", &config.remote_node.url);
    println!("Local address : {}", &config.service.address);

    let addr: SocketAddr = config.service.address.parse().expect("Invalid address");

    // Define path handlers
    let path_v0_get = warp::path!("v0")
        .and(warp::get())
        .and_then(get_api_v0);

    let path_v0_post = warp::path!("v0")
        .and(warp::post())
        .and(jsonrpc_body())
        .and_then(post_api_v0)
        .with(warp::log("POST"));

    let path_status_get = warp::path!("status")
        .and(warp::get())
        .and_then(get_status);

    // Define route
    let routes = path_status_get
        .or(path_v0_get)
        .or(path_v0_post)
        .with(warp::log("MAIN"));

    warp::serve(routes).run(addr).await;
}
