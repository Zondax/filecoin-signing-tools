////! Fcservice RPC Client

use jsonrpc_core::Result as CoreResult;
use jsonrpc_core::{Id, MethodCall, Params, Response, Version};
use serde_json::value::Value;

pub async fn get_nonce() -> Result<u64, anyhow::Error> {
    // FIXME: use configuration parameters instead
    let url = "https://lotus-dev.temporal.cloud/rpc/v0";
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBbGxvdyI6WyJyZWFkIiwid3JpdGUiLCJzaWduIiwiYWRtaW4iXX0.3kxS0ClOY8Knng4YEAKOkHPcVGvrh4ApKq8ChfYuPkE";

    // Prepare request
    let m = MethodCall {
        jsonrpc: Some(Version::V2),
        method: "Filecoin.MpoolGetNonce".to_owned(),
        params: Params::Array(vec![Value::from(
            "t1jdlfl73voaiblrvn2yfivvn5ifucwwv5f26nfza",
        )]),
        id: Id::Num(1),
    };

    // Build request
    let client = reqwest::Client::new();
    let builder = client.post(url).bearer_auth(jwt).json(&m);

    // Send and wait for response
    let resp = builder.send().await?.json::<Response>().await?;

    // Handle response
    let nonce = match resp {
        Response::Single(o) => {
            // TODO: too many abstractiosn to get the result?
            let result = CoreResult::<Value>::from(o)?;

            // FIXME: remove this unwrap
            result.as_u64().unwrap()
        }
        _ => {
            // FIXME: return a proper error here
            0
        }
    };

    Ok(nonce)
}
