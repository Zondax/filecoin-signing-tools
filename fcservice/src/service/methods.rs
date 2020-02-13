//////! Fcservice RPC Client

use crate::service::client::get_nonce;
use crate::service::error::ServiceError;
use fcsigner::api::UnsignedMessageUserAPI;
use jsonrpc_core::{Id, MethodCall, Success, Value, Version};

pub async fn key_generate(_c: MethodCall) -> Result<Success, ServiceError> {
    Err(ServiceError::NotImplemented)
}

pub async fn key_derive(_c: MethodCall) -> Result<Success, ServiceError> {
    Err(ServiceError::NotImplemented)
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

pub async fn transaction_parse(_c: MethodCall) -> Result<Success, ServiceError> {
    Err(ServiceError::NotImplemented)
}

#[cfg(test)]
mod tests {
    use crate::service::client::get_nonce;
    use futures_await_test::async_test;

    #[async_test]
    async fn example_something_else_and_retrieve_nonce() {
        // FIXME: use configuration parameters instead
        let url = "https://lotus-dev.temporal.cloud/rpc/v0";
        let jwt = "some_token";
        let addr = "t1jdlfl73voaiblrvn2yfivvn5ifucwwv5f26nfza";

        let nonce = get_nonce(&url, &jwt, &addr).await;
        assert!(nonce.is_ok());
    }
}
