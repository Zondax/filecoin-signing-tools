////! Fcservice RPC Client

use crate::service::error::ServiceError;
use jsonrpc_core::Result as CoreResult;
use jsonrpc_core::{Id, MethodCall, Params, Response, Version};
use lazy_static::lazy_static;
use lru::LruCache;
use serde_json::value::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

static CALL_ID: AtomicU64 = AtomicU64::new(1);

lazy_static! {
    static ref NONCE_CACHE: Mutex<LruCache::<String, u64>> = Mutex::new(LruCache::new(100));
}

fn cache_get_nonce(addr: &str) -> Option<u64> {
    // Retrieve from cache
    let mut cache = NONCE_CACHE.lock().expect("mutex lock failed");
    let nonce = cache.get(&addr.to_owned());
    nonce.and_then(|v| Some(*v)).or_else(|| None)
}

fn cache_put_nonce(addr: &str, nonce: u64) {
    let mut cache = NONCE_CACHE.lock().expect("mutex lock failed");
    cache.put(addr.to_owned(), nonce);
}

fn cache_len() -> usize {
    let mut cache = NONCE_CACHE.lock().expect("mutex lock failed");
    cache.len()
}

pub async fn get_nonce(addr: &str) -> Result<u64, ServiceError> {
    if let Some(nonce) = cache_get_nonce(addr) {
        return Ok(nonce);
    }

    // FIXME: use configuration parameters instead
    let url = "https://lotus-dev.temporal.cloud/rpc/v0";
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJBbGxvdyI6WyJyZWFkIiwid3JpdGUiLCJzaWduIiwiYWRtaW4iXX0.3kxS0ClOY8Knng4YEAKOkHPcVGvrh4ApKq8ChfYuPkE";

    let call_id = CALL_ID.fetch_add(1, Ordering::SeqCst);

    // Prepare request
    let m = MethodCall {
        jsonrpc: Some(Version::V2),
        method: "Filecoin.MpoolGetNonce".to_owned(),
        params: Params::Array(vec![Value::from(
            "t1jdlfl73voaiblrvn2yfivvn5ifucwwv5f26nfza",
        )]),
        id: Id::Num(call_id),
    };

    // Build request
    let client = reqwest::Client::new();
    let builder = client.post(url).bearer_auth(jwt).json(&m);

    // Send and wait for response
    let resp = builder.send().await?.json::<Response>().await?;

    // Handle response
    let nonce = match resp {
        Response::Single(o) => {
            // TODO: too many abstractions to get the result?
            let result = CoreResult::<Value>::from(o)?;

            result.as_u64().expect("FIXME")
        }
        _ => {
            // FIXME: return a proper error here
            0
        }
    };

    cache_put_nonce(addr, nonce);
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use crate::service::client::{cache_get_nonce, cache_len, cache_put_nonce};

    #[test]
    fn cache_put_get() {
        let not_found = cache_get_nonce("unknown");
        assert!(not_found.is_none());
        assert_eq!(cache_len(), 0);

        cache_put_nonce("address1", 123);
        cache_put_nonce("address2", 456);
        assert_eq!(cache_len(), 2);

        let found1 = cache_get_nonce("address1");
        assert!(found1.is_some());
        assert_eq!(found1.unwrap(), 123);

        let found2 = cache_get_nonce("address2");
        assert!(found2.is_some());
        assert_eq!(found2.unwrap(), 456);
    }
}
