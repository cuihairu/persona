//! 进程内计数器：HTTP 请求（方法 + 路由模板 + 状态码）与事件接入。
//!
//! 有意不引 metrics 框架：计数维度有界（路由来自路由表 + "unmatched"），
//! `render()` 手写 Prometheus 文本格式，由 `/metrics` 端点（lib.rs）暴露。

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

/// Prometheus label 值转义：`\`、`"`、换行（先转反斜杠，避免二次转义）。
fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

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

    /// Prometheus 文本格式（`text/plain; version=0.0.4`）。
    ///
    /// 锁内拼串：计数维度有界（路由表 + "unmatched"），渲染开销可忽略；
    /// HTTP 行按键排序保证输出确定性（便于测试断言与 diff）。
    pub fn render(&self) -> String {
        let counters = self.lock();
        let mut http: Vec<_> = counters.http.iter().collect();
        http.sort_unstable();

        let mut out = String::with_capacity(1400 + http.len() * 96);
        out.push_str(
            "# HELP http_requests_total Total HTTP requests by method, route template and status code.\n",
        );
        out.push_str("# TYPE http_requests_total counter\n");
        for (key, count) in http {
            out.push_str(&format!(
                "http_requests_total{{method=\"{}\",route=\"{}\",status=\"{}\"}} {count}\n",
                escape_label_value(&key.method),
                escape_label_value(&key.route),
                key.status,
            ));
        }
        for (name, value, help) in [
            (
                "persona_events_ingested_total",
                counters.events_ingested,
                "Total audit events accepted into storage.",
            ),
            (
                "persona_events_duplicates_total",
                counters.events_duplicates,
                "Total audit events deduplicated by client_event_id.",
            ),
            (
                "persona_events_rejected_total",
                counters.events_rejected,
                "Total audit events rejected by validation.",
            ),
        ] {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"
            ));
        }
        out.push_str("# HELP process_start_time_seconds Process start time in Unix seconds.\n");
        out.push_str("# TYPE process_start_time_seconds gauge\n");
        out.push_str(&format!(
            "process_start_time_seconds {}\n",
            self.start_time_unix
        ));
        out.push_str("# HELP process_uptime_seconds Process uptime in seconds.\n");
        out.push_str("# TYPE process_uptime_seconds gauge\n");
        out.push_str(&format!(
            "process_uptime_seconds {:.3}\n",
            self.started_at.elapsed().as_secs_f64()
        ));
        out
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
    use super::{escape_label_value, Metrics};

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

    #[test]
    fn label_values_are_escaped() {
        assert_eq!(escape_label_value("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }

    #[test]
    fn render_is_deterministic_and_complete() {
        let metrics = Metrics::new(1_758_182_400);
        metrics.record_http("POST", "/api/v1/events", 202);
        metrics.record_http("GET", "/health", 200);
        metrics.record_http("GET", "/health", 200);
        metrics.add_events_ingested(2);
        metrics.add_events_rejected(1);

        assert_eq!(metrics.render(), metrics.render());

        let text = metrics.render();
        assert!(
            text.contains("http_requests_total{method=\"GET\",route=\"/health\",status=\"200\"} 2")
        );
        assert!(text.contains(
            "http_requests_total{method=\"POST\",route=\"/api/v1/events\",status=\"202\"} 1"
        ));
        assert!(text.contains("persona_events_ingested_total 2"));
        assert!(text.contains("persona_events_duplicates_total 0"));
        assert!(text.contains("persona_events_rejected_total 1"));
        assert!(text.contains("process_start_time_seconds 1758182400"));
        assert!(text.contains("process_uptime_seconds"));
        assert_eq!(text.matches("# TYPE ").count(), 6);
    }
}
