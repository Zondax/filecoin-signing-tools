//! Fcservice RPC API

use jsonrpc_core::Result;
use jsonrpc_derive::rpc;

#[rpc(server)]
pub trait FilecoinSignerRpc {
    /// Adds two numbers and returns a result
    #[rpc(name = "add")]
    fn add(&self, a: u64, b: u64) -> Result<u64>;
}

pub struct FilecoinSignerRpcImpl;

impl FilecoinSignerRpc for FilecoinSignerRpcImpl {
    fn add(&self, a: u64, b: u64) -> Result<u64> {
        Ok(a + b)
    }
}
