//! Per-app fixed-window rate limiting (spec §11): generate / upload / export
//! and the chunked-upload calls share one bucket keyed by app_id.
//!
//! Design:
//! - One shared 60s window per app (not per-endpoint): a noisy tenant cannot
//!   walk around the limit by spreading calls across endpoints.
//! - The map has a hard capacity; expired windows are swept before it can
//!   grow unbounded (anti memory-bomb).
//! - On exceed: the caller builds a 429 with `Retry-After` (seconds until the
//!   current window ends).

use axum::http::HeaderMap;
use axum::response::IntoResponse;
use std::collections::HashMap;
use std::sync::Mutex;

pub const WINDOW_SECS: u64 = 60;

struct Window {
    start: i64,
    count: u32,
}

#[derive(Default)]
pub struct RateLimiter {
    map: Mutex<HashMap<i64, Window>>,
    /// Allowed requests per window (0 = limiting disabled).
    limit: u32,
    /// Hard capacity of the map before expired entries are swept.
    max_entries: usize,
}

impl RateLimiter {
    pub fn new(limit_per_min: u32, max_entries: usize) -> Self {
        RateLimiter {
            map: Mutex::new(HashMap::new()),
            limit: limit_per_min,
            max_entries,
        }
    }

    /// Returns Ok(()) when the call may proceed; Err(retry_after_secs) when the
    /// app's window is exhausted.
    pub fn check(&self, app_id: i64) -> Result<(), u64> {
        if self.limit == 0 {
            return Ok(());
        }
        let now = crate::config::Config::now();
        let mut map = self.map.lock().unwrap();
        // Sweep before inserting so the map cannot grow without bound.
        if map.len() >= self.max_entries {
            map.retain(|_, w| now - w.start < WINDOW_SECS as i64);
        }
        let entry = map.entry(app_id).or_insert(Window { start: now, count: 0 });
        if now - entry.start >= WINDOW_SECS as i64 {
            entry.start = now;
            entry.count = 0;
        }
        if entry.count >= self.limit {
            let elapsed = (now - entry.start).max(0) as u64;
            let retry = WINDOW_SECS.saturating_sub(elapsed).max(1);
            return Err(retry);
        }
        entry.count += 1;
        Ok(())
    }

    /// Test helper: number of tracked apps.
    #[cfg(test)]
    pub fn tracked(&self) -> usize {
        self.map.lock().unwrap().len()
    }
}

/// Apply the per-app limit gate; on exceed, return the standard 429 response
/// with `Retry-After` (seconds) and the unified error model body.
pub fn gate(
    st: &crate::state::AppState,
    app_id: i64,
) -> Result<(), Box<axum::response::Response>> {
    match st.ratelimit.check(app_id) {
        Ok(()) => Ok(()),
        Err(retry_after) => Err(Box::new(rate_limited_response(retry_after))),
    }
}

fn rate_limited_response(retry_after: u64) -> axum::response::Response {
    let rid: String = crate::crypto::random_token().chars().take(12).collect();
    let body = serde_json::json!({
        "error": {
            "code": "rate_limited",
            "message": "Rate limit exceeded.",
            "request_id": rid
        }
    });
    (
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        [(axum::http::header::RETRY_AFTER, retry_after.to_string())],
        axum::Json(body),
    )
        .into_response()
}

/// HeaderMap helper kept for callers that want a plain string lookup.
#[allow(dead_code)]
pub fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_until_limit_then_rejects_with_retry_after() {
        let rl = RateLimiter::new(3, 100);
        for _ in 0..3 {
            assert!(rl.check(1).is_ok());
        }
        let err = rl.check(1).unwrap_err();
        assert!((1..=WINDOW_SECS).contains(&err), "retry_after={err}");
        // A different app is unaffected (per-app buckets)
        assert!(rl.check(2).is_ok());
    }

    #[test]
    fn zero_limit_disables() {
        let rl = RateLimiter::new(0, 10);
        for _ in 0..100 {
            assert!(rl.check(1).is_ok());
        }
    }

    #[test]
    fn map_sweeps_expired_windows() {
        let rl = RateLimiter::new(5, 3);
        let now = crate::config::Config::now();
        {
            let mut map = rl.map.lock().unwrap();
            // three stale apps
            map.insert(10, Window { start: now - 1000, count: 9 });
            map.insert(11, Window { start: now - 1000, count: 9 });
            map.insert(12, Window { start: now - 1000, count: 9 });
        }
        assert_eq!(rl.tracked(), 3);
        // a 4th app pushes over capacity: the sweep reclaims stale windows
        // before the insert, so only the fresh one survives.
        rl.check(13).unwrap();
        assert_eq!(rl.tracked(), 1);
    }
}
