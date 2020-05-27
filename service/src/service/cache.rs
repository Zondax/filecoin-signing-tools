use crate::service::error::ServiceError;
use lazy_static::lazy_static;
use lru::LruCache;
use std::sync::Mutex;

lazy_static! {
    static ref NONCE_CACHE: Mutex<LruCache::<String, u64>> = Mutex::new(LruCache::new(100));
}

pub fn cache_get_nonce(addr: &str) -> Result<u64, ServiceError> {
    // Retrieve from cache
    let mut cache = NONCE_CACHE
        .lock()
        .map_err(|e| ServiceError::ErrorStr(e.to_string()))?;
    let nonce = cache.get(&addr.to_owned());
    nonce
        .copied()
        .ok_or_else(|| ServiceError::ErrorStr("Couldn't get cached value".to_string()))
}

pub fn cache_put_nonce(addr: &str, nonce: u64) -> Result<(), ServiceError> {
    let mut cache = NONCE_CACHE
        .lock()
        .map_err(|e| ServiceError::ErrorStr(e.to_string()))?;
    cache.put(addr.to_owned(), nonce);
    Ok(())
}

pub fn cache_len() -> Result<usize, ServiceError> {
    let cache = NONCE_CACHE
        .lock()
        .map_err(|e| ServiceError::ErrorStr(e.to_string()))?;
    Ok(cache.len())
}

#[cfg(test)]
mod tests {
    use crate::service::cache::{cache_get_nonce, cache_len, cache_put_nonce};

    #[test]
    fn cache_put_get() {
        let not_found = cache_get_nonce("unknown");
        assert!(not_found.is_err());
        assert_eq!(cache_len().unwrap(), 0);

        cache_put_nonce("address1", 123).unwrap();
        cache_put_nonce("address2", 456).unwrap();
        assert_eq!(cache_len().unwrap(), 2);

        let found1 = cache_get_nonce("address1");
        assert!(found1.is_ok());
        assert_eq!(found1.unwrap(), 123);

        let found2 = cache_get_nonce("address2");
        assert!(found2.is_ok());
        assert_eq!(found2.unwrap(), 456);
    }
}
