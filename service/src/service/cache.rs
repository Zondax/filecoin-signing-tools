use lazy_static::lazy_static;
use lru::LruCache;
use std::sync::Mutex;

lazy_static! {
    static ref NONCE_CACHE: Mutex<LruCache::<String, u64>> = Mutex::new(LruCache::new(100));
}

pub fn cache_get_nonce(addr: &str) -> Option<u64> {
    // Retrieve from cache
    let mut cache = NONCE_CACHE.lock().expect("mutex lock failed");
    let nonce = cache.get(&addr.to_owned());
    nonce.copied().or_else(|| None)
}

pub fn cache_put_nonce(addr: &str, nonce: u64) {
    let mut cache = NONCE_CACHE.lock().expect("mutex lock failed");
    cache.put(addr.to_owned(), nonce);
}

pub fn cache_len() -> usize {
    let cache = NONCE_CACHE.lock().expect("mutex lock failed");
    cache.len()
}

#[cfg(test)]
mod tests {
    use crate::service::cache::{cache_get_nonce, cache_len, cache_put_nonce};

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
