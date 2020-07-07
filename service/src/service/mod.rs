use crate::config::RemoteNodeSection;
use crate::prelude::*;
use crate::service::handlers::{v0_get, v0_get_status, v0_post};
use jsonrpc_core::Call;
use std::net::SocketAddr;
use std::process;

use warp::Filter;

#[cfg(feature = "cache-nonce")]
mod cache;
mod client;
mod error;
mod handlers;
mod methods;

#[cfg(test)]
mod test_helper;

fn jsonrpc_body() -> impl Filter<Extract = (Call,), Error = warp::Rejection> + Clone {
    // When accepting a body, we want a JSON body and to reject huge payloads)...
    const MAX_SIZE: u64 = 1024 * 16;
    warp::body::content_length_limit(MAX_SIZE).and(warp::body::json())
}

fn with_config(
    config: RemoteNodeSection,
) -> impl Filter<Extract = (RemoteNodeSection,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || config.clone())
}

#[tokio::main]
pub async fn service_main() {
    let config = app_config();
    println!("Remote URL    : {}", &config.remote_node.url);
    println!("Local address : {}", &config.service.address);

    let addr: SocketAddr = config.service.address.parse().unwrap_or_else(|e| {
        println!("Address {} is invalid: {}", &config.service.address, e);
        process::exit(1);
    });

    let path_v0 = warp::path!("v0");

    let path_v0_get = path_v0
        .and(warp::get())
        .and(with_config(config.remote_node.clone()))
        .and_then(v0_get);

    let path_v0_post = path_v0
        .and(warp::post())
        .and(jsonrpc_body())
        .and(with_config(config.remote_node.clone()))
        .and_then(v0_post)
        .with(warp::log("POST"));

    let path_status_get = warp::path!("status")
        .and(warp::get())
        .and(with_config(config.remote_node.clone()))
        .and_then(v0_get_status);

    // Define route
    let routes = path_status_get
        .or(path_v0_get)
        .or(path_v0_post)
        .with(warp::log("MAIN"));

    let server = warp::serve(routes);

    let (addr, fut) = server.try_bind_ephemeral(addr).unwrap_or_else(|e| {
        println!("Error connecting: {}", e);
        process::exit(1);
    });

    println!("listening on http://{}", addr);

    fut.await;
}
