//! Idempotency-Key cache for POST /v1/upload (spec §4: "Idempotency-Key
//! (recommended) retry must not create a duplicate file").
//!
//! Keyed by (app_id, key): a retried upload inside the configured window gets
//! back the ORIGINAL file metadata (no second blob written, no quota double
//! charge). After the window expires the key is forgotten and behaves as a
//! brand-new upload — cross-window behavior is documented as such.
//!
//! In-memory only (like the embed-token idempotency pattern, this is a
//! best-effort retry guard, not a durable queue); the map has a hard capacity
//! and expires entries so it cannot grow without bound.

use rusqlite::types::Value;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::sync::Mutex;

struct Entry {
    response: JsonValue,
    created_at: i64,
}

pub struct IdemStore {
    map: Mutex<HashMap<(i64, String), Entry>>,
    window_secs: i64,
    max_entries: usize,
}

impl IdemStore {
    pub fn new(window_secs: i64, max_entries: usize) -> Self {
        IdemStore {
            map: Mutex::new(HashMap::new()),
            window_secs,
            max_entries,
        }
    }

    /// Look up a cached, in-window result for (app_id, key).
    pub fn get(&self, app_id: i64, key: &str) -> Option<JsonValue> {
        let now = crate::config::Config::now();
        let mut map = self.map.lock().unwrap();
        // opportunistic sweep on every read (cheap; map is small)
        map.retain(|_, e| now - e.created_at < self.window_secs);
        map.get(&(app_id, key.to_string()))
            .filter(|e| now - e.created_at < self.window_secs)
            .map(|e| e.response.clone())
    }

    /// Cache a successful upload result.
    pub fn put(&self, app_id: i64, key: &str, response: JsonValue) {
        let now = crate::config::Config::now();
        let mut map = self.map.lock().unwrap();
        map.retain(|_, e| now - e.created_at < self.window_secs);
        if map.len() >= self.max_entries {
            // evict the oldest entry (LRU by creation time)
            if let Some(old) = map
                .iter()
                .min_by_key(|(_, e)| e.created_at)
                .map(|(k, _)| k.clone())
            {
                map.remove(&old);
            }
        }
        map.insert(
            (app_id, key.to_string()),
            Entry {
                response,
                created_at: now,
            },
        );
    }

    #[cfg(test)]
    pub fn tracked(&self) -> usize {
        self.map.lock().unwrap().len()
    }
}

#[allow(dead_code)]
fn _assert_value_shape(_v: &Value) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_key_returns_cached_result() {
        let store = IdemStore::new(3600, 100);
        let resp = serde_json::json!({"file_id": 42, "size": 11});
        assert!(store.get(1, "k1").is_none());
        store.put(1, "k1", resp.clone());
        assert_eq!(store.get(1, "k1"), Some(resp));
        // different app / key -> miss
        assert!(store.get(2, "k1").is_none());
        assert!(store.get(1, "k2").is_none());
    }

    #[test]
    fn expired_entries_are_swept() {
        let store = IdemStore::new(60, 100);
        store.put(1, "old", serde_json::json!({"a": 1}));
        // force the entry to be older than the window
        {
            let mut map = store.map.lock().unwrap();
            if let Some(e) = map.get_mut(&(1, "k1".to_string())) {
                e.created_at -= 1000;
            }
            if let Some(e) = map.get_mut(&(1, "old".to_string())) {
                e.created_at -= 1000;
            }
        }
        assert!(store.get(1, "old").is_none());
        assert_eq!(store.tracked(), 0);
    }

    #[test]
    fn capacity_evicts_oldest() {
        let store = IdemStore::new(3600, 2);
        store.put(1, "a", serde_json::json!({"a": 1}));
        store.put(1, "b", serde_json::json!({"b": 1}));
        // created_at has second granularity; age them explicitly.
        {
            let mut map = store.map.lock().unwrap();
            map.get_mut(&(1, "a".to_string())).unwrap().created_at -= 100;
            map.get_mut(&(1, "b".to_string())).unwrap().created_at -= 50;
        }
        store.put(1, "c", serde_json::json!({"c": 1}));
        assert!(store.get(1, "a").is_none(), "oldest evicted");
        assert!(store.get(1, "b").is_some());
        assert!(store.get(1, "c").is_some());
    }
}
