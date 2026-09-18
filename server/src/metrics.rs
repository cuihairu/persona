//! 进程内计数器：HTTP 请求（方法 + 路由模板 + 状态码）与事件接入。
//!
//! 有意不引 metrics 框架：计数维度有界（路由来自路由表 + "unmatched"），
//! `render()` 手写 Prometheus 文本格式（渲染见后续 /metrics 端点）。

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct HttpKey {
    method: String,
    route: String,
    status: u16,
}

/// `snapshot()` 的返回形状（测试专用，别名避免 clippy::type_complexity）。
#[cfg(test)]
type HttpSnapshot = (Vec<(String, String, u16, u64)>, u64, u64, u64);

#[derive(Default)]
struct Counters {
    http: HashMap<HttpKey, u64>,
    events_ingested: u64,
    events_duplicates: u64,
    events_rejected: u64,
}

pub struct Metrics {
    counters: Mutex<Counters>,
    start_time_unix: i64,
    started_at: Instant,
}

impl Metrics {
    pub fn new(start_time_unix: i64) -> Self {
        Self {
            counters: Mutex::new(Counters::default()),
            start_time_unix,
            started_at: Instant::now(),
        }
    }

    pub fn record_http(&self, method: &str, route: &str, status: u16) {
        self.lock()
            .http
            .entry(HttpKey {
                method: method.to_owned(),
                route: route.to_owned(),
                status,
            })
            .and_modify(|n| *n += 1)
            .or_insert(1);
    }

    pub fn add_events_ingested(&self, n: u64) {
        self.lock().events_ingested += n;
    }

    pub fn add_events_duplicates(&self, n: u64) {
        self.lock().events_duplicates += n;
    }

    pub fn add_events_rejected(&self, n: u64) {
        self.lock().events_rejected += n;
    }

    pub fn uptime_seconds(&self) -> f64 {
        self.started_at.elapsed().as_secs_f64()
    }

    pub fn start_time_unix(&self) -> i64 {
        self.start_time_unix
    }

    /// 锁中毒只可能发生在持锁线程 panic 时；计数器丢一次渲染可接受，
    /// 直接取回内部值继续用。
    fn lock(&self) -> MutexGuard<'_, Counters> {
        self.counters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> HttpSnapshot {
        let counters = self.lock();
        let mut http: Vec<_> = counters
            .http
            .iter()
            .map(|(k, v)| (k.method.clone(), k.route.clone(), k.status, *v))
            .collect();
        http.sort_unstable();
        (
            http,
            counters.events_ingested,
            counters.events_duplicates,
            counters.events_rejected,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Metrics;

    #[test]
    fn http_counters_accumulate_per_key() {
        let metrics = Metrics::new(0);
        metrics.record_http("GET", "/health", 200);
        metrics.record_http("GET", "/health", 200);
        metrics.record_http("POST", "/api/v1/events", 202);

        let (http, _, _, _) = metrics.snapshot();
        assert_eq!(http.len(), 2);
        assert!(http.contains(&("GET".into(), "/health".into(), 200, 2)));
        assert!(http.contains(&("POST".into(), "/api/v1/events".into(), 202, 1)));
    }

    #[test]
    fn event_counters_accumulate() {
        let metrics = Metrics::new(0);
        metrics.add_events_ingested(3);
        metrics.add_events_duplicates(1);
        metrics.add_events_rejected(2);

        let (_, ingested, duplicates, rejected) = metrics.snapshot();
        assert_eq!((ingested, duplicates, rejected), (3, 1, 2));
    }

    #[test]
    fn uptime_and_start_time_are_reported() {
        let metrics = Metrics::new(1_758_182_400);
        assert_eq!(metrics.start_time_unix(), 1_758_182_400);
        assert!(metrics.uptime_seconds() >= 0.0);
    }
}
