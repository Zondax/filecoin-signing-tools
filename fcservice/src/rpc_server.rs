//! Fcservice RPC

use jsonrpc_http_server::ServerBuilder;
use std::net::SocketAddr;
use crate::rpc_api::FilecoinSignerRpc;
use crate::rpc_api::FilecoinSignerRpcImpl;

pub fn start(addr: &SocketAddr) {
    let mut io = jsonrpc_core::IoHandler::new();
    io.extend_with(FilecoinSignerRpcImpl.to_delegate());

    let server = ServerBuilder::new(io)
        .threads(3)
        .start_http(&addr)
        .unwrap();

    server.wait();
}
