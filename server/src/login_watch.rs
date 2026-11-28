//! Login awareness (PERSONA-DEVALERT-001, P0): every SRP login attempt is
//! ledgered in memory and classified into INFO / NOTICE / ALERT tiers;
//! NOTICE and ALERT fan out to an optional Herald notification gateway.
//!
//! Model (mirrors the Apple "new device sign-in" / Steam Guard e-mail shape):
//! - New device: the very first sighting of a device name in this process's
//!   registry. The registry is intentionally in-memory (no new persistence
//!   surface) — a server restart re-arms first-sighting detection, which is
//!   the conservative direction for a security signal.
//! - Unusual location: the device logs in from a location label it has never
//!   used before. P0 resolves locations with a network-prefix proxy (no
//!   external GeoIP dependency, nothing leaves the box); the resolver is a
//!   trait so an ASN/GeoIP source can slot in later (P2) without touching
//!   the classification logic.
//! - Risk signal: a burst of failed proofs for one device inside a short
//!   window.
//!
//! Tiering (the classification is decided BEFORE the record is updated, so
//! the tiers below are defined against the pre-login state):
//! - INFO  — known device, known location, no failure burst. Silent: ledger
//!   only, never notified.
//! - NOTICE — a new device from a location the registry has already seen, or
//!   an established device from a location it has never used. Herald level
//!   `warning`.
//! - ALERT — a brand-new device from a location the whole registry has never
//!   seen, or a login-failure burst. Herald level `critical`.
//! - Bootstrap: the registry's very first sighting overall is INFO — with
//!   zero history there is no "usual" to deviate from, and the owner's own
//!   first login must not page them. Every subsequent first-sighting is
//!   NOTICE/ALERT per the rules above.
//!
//! Safety posture: notifications carry device name / IP / location label /
//! time / outcome only — never any vault content; delivery is fire-and-forget
//! (a dead or misconfigured gateway never blocks or fails a login).

use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Bounded in-memory ledger: enough to review a login storm, small enough
/// that a runaway peer cannot grow the process without bound.
const EVENT_LOG_CAP: usize = 512;
/// Failure-burst window: >= [`FAILURE_SPIKE_COUNT`] failures within this
/// many milliseconds escalates the tier to ALERT.
const FAILURE_SPIKE_WINDOW_MS: u64 = 5 * 60 * 1000;
/// Failure-burst threshold (matches the existing lockout's "5 consecutive
/// failures" granularity but trips earlier so the burst is visible before
/// the lockout silences it).
const FAILURE_SPIKE_COUNT: usize = 3;
/// Registry growth caps: distinct device entries and distinct location
/// labels are both bounded, so no login pattern — even one holding valid
/// credentials or sourcing many addresses — can grow server memory without
/// limit. The ledger stays usable by evicting the least-recently-seen
/// device and refusing to extend the location set past the cap.
const MAX_TRACKED_DEVICES: usize = 4096;
const MAX_TRACKED_GEOS: usize = 4096;
/// Minimum spacing between Herald fan-outs for the same device: repeated
/// NOTICE/ALERT-grade events are still ledgered with their tier, only the
/// delivery is throttled (a login storm must not become a task storm).
const NOTIFY_THROTTLE_MS: u64 = 60_000;
/// Herald delivery timeout: the gateway is best-effort by design.
const HERALD_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------
// Location resolution
// ---------------------------------------------------------------------

/// Resolves a peer IP into a coarse location label. P0 ships a
/// network-prefix proxy (country/province grade is an explicit P2 upgrade
/// via a GeoIP/ASN resolver); the trait keeps that swap local.
pub trait GeoResolver: Send + Sync {
    fn resolve(&self, ip: &str) -> String;
}

/// Location labels from IP prefixes: /24 for IPv4, /48 for IPv6. Anything
/// unparseable lands on a single shared `unknown` bucket (loopback and
/// header-less requests included) — deviation against `unknown` still
/// works, it just has no geographic meaning.
pub struct PrefixGeoResolver;

impl GeoResolver for PrefixGeoResolver {
    fn resolve(&self, ip: &str) -> String {
        let parsed: std::net::IpAddr = match ip.trim().parse() {
            Ok(ip) => ip,
            Err(_) => return "unknown".to_string(),
        };
        match parsed {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                format!("v4-{}.{}.{}", o[0], o[1], o[2])
            }
            std::net::IpAddr::V6(v6) => {
                let segs = v6.segments();
                format!("v6-{:x}:{:x}:{:x}", segs[0], segs[1], segs[2])
            }
        }
    }
}

// ---------------------------------------------------------------------
// Herald gateway (optional)
// ---------------------------------------------------------------------

/// Herald REST gateway client (`POST {base}/api/v1/notify`). Configured via
/// `PERSONA_HERALD_URL` (+ optional `PERSONA_HERALD_CHANNELS`,
/// `PERSONA_HERALD_API_KEY`); absent configuration = notifications disabled
/// and the ledger alone remains.
pub struct HeraldNotifier {
    endpoint: String,
    channels: Vec<String>,
    api_key: Option<String>,
    client: reqwest::Client,
}

impl HeraldNotifier {
    /// Builds a notifier for a Herald base URL (the `/api/v1/notify` path is
    /// appended here, callers pass e.g. `http://127.0.0.1:8080`).
    pub fn new(base_url: &str, channels: Vec<String>, api_key: Option<String>) -> Self {
        Self {
            endpoint: format!("{}/api/v1/notify", base_url.trim_end_matches('/')),
            channels,
            api_key,
            client: reqwest::Client::new(),
        }
    }

    /// Sends one notification. Herald answers HTTP 200 even for total
    /// provider failure (the body `code` turns 422), so the body code is
    /// checked too.
    pub async fn send(&self, level: &str, title: &str, body: &str) -> Result<(), String> {
        let payload = serde_json::json!({
            "type": "persona.login",
            "level": level,
            "title": title,
            "body": body,
            "channels": self.channels,
        });
        let mut request = self
            .client
            .post(&self.endpoint)
            .timeout(HERALD_TIMEOUT)
            .json(&payload);
        if let Some(key) = &self.api_key {
            request = request.header("x-api-key", key);
        }
        let response = request
            .send()
            .await
            .map_err(|e| format!("herald unreachable: {e}"))?;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!("herald responded HTTP {status}"));
        }
        // Total provider failure: HTTP 200 with {"code": 422, ...}
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
            if value.get("code").and_then(|c| c.as_i64()).unwrap_or(0) != 0 {
                return Err(format!(
                    "herald rejected delivery: {}",
                    text.chars().take(200).collect::<String>()
                ));
            }
        }
        Ok(())
    }
}

/// Fire-and-forget delivery: a dead gateway logs a warning and moves on.
pub(crate) fn dispatch_login_notice(
    notifier: &Arc<HeraldNotifier>,
    level: &str,
    title: String,
    body: String,
) {
    let notifier = Arc::clone(notifier);
    let level = level.to_string();
    tokio::spawn(async move {
        if let Err(e) = notifier.send(&level, &title, &body).await {
            tracing::warn!(target: "persona_server::login_watch", error = %e, "herald notification failed");
        }
    });
}

// ---------------------------------------------------------------------
// Ledger and classification
// ---------------------------------------------------------------------

/// Severity tiers (snake_case on the wire for the devices endpoint/events).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Info,
    Notice,
    Alert,
}

/// One ledgered login attempt (success or failure).
#[derive(Debug, Clone, Serialize)]
pub struct LoginEvent {
    /// Device-domain device name, or the account-domain lock key
    /// `account:{id}:{device}` for account SRP logins.
    pub device: String,
    pub success: bool,
    pub ip: String,
    pub geo: String,
    pub at_ms: u64,
    pub new_device: bool,
    pub tier: Tier,
}

/// Per-device registry entry (in-memory; a restart resets it by design).
#[derive(Debug, Clone, Serialize)]
pub struct DeviceRecord {
    /// Device-domain device name, or the account-domain lock key
    /// `account:{id}:{device}`.
    pub device: String,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub last_ip: String,
    pub last_geo: String,
    /// Location label -> sighting count (BTreeMap so the devices endpoint
    /// renders deterministically).
    pub geo_counts: BTreeMap<String, u64>,
    pub ok_count: u64,
    pub fail_count: u64,
    /// Timestamps of recent failures (bounded; the burst detector reads it).
    pub failures: VecDeque<u64>,
}

impl DeviceRecord {
    fn new(device: &str, now_ms: u64, ip: &str, geo: &str) -> Self {
        Self {
            device: device.to_string(),
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
            last_ip: ip.to_string(),
            last_geo: geo.to_string(),
            geo_counts: BTreeMap::new(),
            ok_count: 0,
            fail_count: 0,
            failures: VecDeque::new(),
        }
    }
}

#[derive(Default)]
struct Registry {
    devices: HashMap<String, DeviceRecord>,
    /// Every location label the registry has ever observed (drives the
    /// "unseen location" leg of ALERT).
    seen_geos: HashSet<String>,
    events: VecDeque<LoginEvent>,
    /// Per-device last fan-out time (the throttle for NOTICE/ALERT
    /// delivery; key set is bounded by the device cap's eviction).
    last_notified_ms: HashMap<String, u64>,
}

/// Login awareness facade held in `AppState` (Arc-shared, clone-cheap).
pub struct LoginWatch {
    inner: Mutex<Registry>,
    notifier: Option<Arc<HeraldNotifier>>,
    resolver: Arc<dyn GeoResolver>,
    /// Injectable clock (tests pin time to exercise the burst window).
    now_ms: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl LoginWatch {
    /// Production wiring: prefix resolver, optional notifier, wall clock.
    pub fn new(notifier: Option<Arc<HeraldNotifier>>) -> Self {
        Self {
            inner: Mutex::new(Registry::default()),
            notifier,
            resolver: Arc::new(PrefixGeoResolver),
            now_ms: Box::new(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64
            }),
        }
    }

    /// Test wiring: injectable resolver + clock.
    pub fn with_parts(
        notifier: Option<Arc<HeraldNotifier>>,
        resolver: Arc<dyn GeoResolver>,
        now_ms: Box<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self {
            inner: Mutex::new(Registry::default()),
            notifier,
            resolver,
            now_ms,
        }
    }

    /// Records one login attempt, classifies it and (for NOTICE/ALERT) fans
    /// out to Herald. Returns the ledgered event. Never blocks on delivery:
    /// the gateway call is spawned.
    pub fn record_login(&self, device: &str, success: bool, ip: &str) -> LoginEvent {
        let geo = self.resolver.resolve(ip);
        let now = (self.now_ms)();
        let (event, notify) = {
            let mut registry = self.inner.lock().unwrap_or_else(|e| e.into_inner());

            let new_device = !registry.devices.contains_key(device);
            // Device cap: make room before inserting a brand-new entry by
            // evicting the least-recently-seen device (its throttle marker
            // goes with it).
            if new_device && registry.devices.len() >= MAX_TRACKED_DEVICES {
                if let Some((oldest, _)) = registry
                    .devices
                    .iter()
                    .min_by_key(|(_, r)| r.last_seen_ms)
                    .map(|(k, r)| (k.clone(), r.last_seen_ms))
                {
                    registry.devices.remove(&oldest);
                    registry.last_notified_ms.remove(&oldest);
                }
            }
            let geo_seen_in_registry = registry.seen_geos.contains(&geo);
            // Bootstrap leg: the registry's very first sighting ever.
            let first_sighting_overall = new_device && registry.devices.is_empty();
            let record = registry
                .devices
                .entry(device.to_string())
                .or_insert_with(|| DeviceRecord::new(device, now, ip, &geo));
            let geo_new_for_device = !record.geo_counts.contains_key(&geo);

            // Failure-burst detection runs on the pre-update deque plus this
            // attempt when it failed.
            let burst = {
                let mut count = record
                    .failures
                    .iter()
                    .rev()
                    .take_while(|&&t| now.saturating_sub(t) <= FAILURE_SPIKE_WINDOW_MS)
                    .count();
                if !success {
                    count += 1;
                }
                count >= FAILURE_SPIKE_COUNT
            };

            let tier = classify_tier(
                now,
                success,
                new_device,
                geo_new_for_device,
                geo_seen_in_registry,
                first_sighting_overall,
                burst,
            );

            // Update the registry after classification so the tiers above
            // read the pre-login state.
            if !success {
                record.fail_count += 1;
                record.failures.push_back(now);
                while record.failures.len() > FAILURE_SPIKE_COUNT * 4 {
                    record.failures.pop_front();
                }
            } else {
                record.ok_count += 1;
            }
            record.last_seen_ms = now;
            record.last_ip = ip.to_string();
            record.last_geo = geo.to_string();
            *record.geo_counts.entry(geo.clone()).or_insert(0) += 1;
            // Location cap: past the cap new labels are not recorded, so the
            // "unseen location" horizon simply stops extending (a fresh label
            // keeps classifying as unseen — the conservative reading — and
            // the resulting fan-out is held in check by the notify throttle).
            if registry.seen_geos.len() < MAX_TRACKED_GEOS {
                registry.seen_geos.insert(geo.clone());
            }

            let event = LoginEvent {
                device: device.to_string(),
                success,
                ip: ip.to_string(),
                geo,
                at_ms: now,
                new_device,
                tier,
            };
            registry.events.push_back(event.clone());
            while registry.events.len() > EVENT_LOG_CAP {
                registry.events.pop_front();
            }
            let notify = tier != Tier::Info
                && registry
                    .last_notified_ms
                    .get(device)
                    .is_none_or(|&t| now.saturating_sub(t) >= NOTIFY_THROTTLE_MS);
            if notify {
                registry.last_notified_ms.insert(device.to_string(), now);
            }
            (event, notify)
        };

        if notify {
            if let Some(notifier) = &self.notifier {
                let (level, title) = notice_text(&event);
                let body = format!(
                    "device: {} | ip: {} | location: {} | result: {} | at: {}",
                    event.device,
                    event.ip,
                    event.geo,
                    if event.success { "success" } else { "failed" },
                    chrono::DateTime::from_timestamp_millis(event.at_ms as i64)
                        .map(|t| t.to_rfc3339())
                        .unwrap_or_else(|| event.at_ms.to_string()),
                );
                dispatch_login_notice(notifier, level, title, body);
            }
        }
        event
    }

    /// Device registry snapshot for `GET /api/v1/auth/devices`, newest
    /// activity first.
    pub fn snapshot_devices(&self) -> Vec<DeviceRecord> {
        let registry = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut records: Vec<DeviceRecord> = registry.devices.values().cloned().collect();
        records.sort_by_key(|r| std::cmp::Reverse(r.last_seen_ms));
        records
    }

    /// Recent ledger events, newest first (bounded by [`EVENT_LOG_CAP`]).
    pub fn recent_events(&self) -> Vec<LoginEvent> {
        let registry = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        registry.events.iter().rev().cloned().collect()
    }
}

/// Tier classification (pure, pre-update state). `first_sighting_overall`
/// is the bootstrap leg: an empty registry has no "usual", so the very
/// first device ever seen logs INFO even though it is technically new.
fn classify_tier(
    _now: u64,
    success: bool,
    new_device: bool,
    geo_new_for_device: bool,
    geo_seen_in_registry: bool,
    first_sighting_overall: bool,
    failure_burst: bool,
) -> Tier {
    if failure_burst {
        return Tier::Alert;
    }
    if success && first_sighting_overall {
        return Tier::Info;
    }
    if new_device && !geo_seen_in_registry {
        return Tier::Alert;
    }
    if new_device || (geo_new_for_device && success) {
        return Tier::Notice;
    }
    Tier::Info
}

/// Herald level + title for a NOTICE/ALERT event.
fn notice_text(event: &LoginEvent) -> (&'static str, String) {
    match event.tier {
        Tier::Alert => (
            "critical",
            if event.new_device {
                format!(
                    "Alert: login from a new device in an unseen location ({})",
                    event.device
                )
            } else {
                format!("Alert: repeated login failures ({})", event.device)
            },
        ),
        Tier::Notice => (
            "warning",
            if event.new_device {
                format!("New device login: {}", event.device)
            } else {
                format!("Login from a new location: {}", event.device)
            },
        ),
        Tier::Info => ("info", format!("Login: {}", event.device)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct StaticResolver;
    impl GeoResolver for StaticResolver {
        fn resolve(&self, ip: &str) -> String {
            // Tests drive locations through distinct IPs: 1.2.3.x vs 9.9.9.x
            if ip.starts_with("1.2.3.") {
                "loc-home".to_string()
            } else if ip.starts_with("9.9.9.") {
                "loc-far".to_string()
            } else {
                "unknown".to_string()
            }
        }
    }

    /// Capturing Herald stub: records posted payloads, answers 200/{"code":0}.
    struct CaptureHerald {
        url: String,
        seen: Arc<Mutex<Vec<serde_json::Value>>>,
        reply_status: u16,
    }

    async fn spawn_capture(status: u16) -> (CaptureHerald, std::net::SocketAddr) {
        let seen: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_for_app = Arc::clone(&seen);
        let app = axum::Router::new().route(
            "/api/v1/notify",
            axum::routing::post(move |body: String| async move {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    seen_for_app.lock().unwrap().push(v);
                }
                (
                    axum::http::StatusCode::from_u16(status).unwrap(),
                    axum::Json(serde_json::json!({"code": if status == 200 { 0 } else { 422 }})),
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.ok() });
        (
            CaptureHerald {
                url: format!("http://{addr}"),
                seen,
                reply_status: status,
            },
            addr,
        )
    }

    fn watch_with_clock(clock: Arc<AtomicU64>) -> LoginWatch {
        LoginWatch::with_parts(
            None,
            Arc::new(StaticResolver),
            Box::new(move || clock.load(Ordering::SeqCst)),
        )
    }

    fn watch() -> LoginWatch {
        watch_with_clock(Arc::new(AtomicU64::new(1_000_000)))
    }

    fn advance(clock: &Arc<AtomicU64>, ms: u64) {
        clock.fetch_add(ms, Ordering::SeqCst);
    }

    #[test]
    fn prefix_resolver_labels_v4_v6_and_unknown() {
        assert_eq!(PrefixGeoResolver.resolve("192.168.5.20"), "v4-192.168.5");
        assert_eq!(
            PrefixGeoResolver.resolve("2001:db8:1a2b:3c4d::1"),
            "v6-2001:db8:1a2b"
        );
        assert_eq!(PrefixGeoResolver.resolve("not-an-ip"), "unknown");
        assert_eq!(PrefixGeoResolver.resolve("localhost"), "unknown");
    }

    #[test]
    fn very_first_sighting_of_an_empty_registry_is_info_bootstrap() {
        let watch = watch();
        let event = watch.record_login("owner-laptop", true, "1.2.3.4");
        assert_eq!(event.tier, Tier::Info);
        assert!(event.new_device);
        assert_eq!(event.geo, "loc-home");
    }

    #[test]
    fn new_device_in_a_known_location_is_notice() {
        let watch = watch();
        watch.record_login("laptop", true, "1.2.3.4");
        let event = watch.record_login("phone", true, "1.2.3.9");
        assert_eq!(event.tier, Tier::Notice);
        assert!(event.new_device);
    }

    #[test]
    fn new_device_from_an_unseen_location_is_alert() {
        let watch = watch();
        watch.record_login("laptop", true, "1.2.3.4");
        let event = watch.record_login("stranger-box", true, "9.9.9.1");
        assert_eq!(event.tier, Tier::Alert);
        assert!(event.new_device);
    }

    #[test]
    fn established_device_from_a_new_location_is_notice() {
        let watch = watch();
        watch.record_login("laptop", true, "1.2.3.4");
        watch.record_login("phone", true, "1.2.3.4");
        let event = watch.record_login("laptop", true, "9.9.9.1");
        assert_eq!(event.tier, Tier::Notice);
        assert!(!event.new_device);
        // And back home it is INFO again.
        let back = watch.record_login("laptop", true, "1.2.3.4");
        assert_eq!(back.tier, Tier::Info);
    }

    #[test]
    fn known_device_known_location_success_is_info() {
        let watch = watch();
        watch.record_login("laptop", true, "1.2.3.4");
        let event = watch.record_login("laptop", true, "1.2.3.9");
        assert_eq!(event.tier, Tier::Info);
    }

    #[test]
    fn failure_burst_escalates_to_alert_within_the_window() {
        let clock = Arc::new(AtomicU64::new(1_000_000));
        let watch = watch_with_clock(Arc::clone(&clock));
        watch.record_login("laptop", true, "1.2.3.4");
        advance(&clock, 1_000);
        assert_eq!(
            watch.record_login("laptop", false, "1.2.3.4").tier,
            Tier::Info
        );
        advance(&clock, 1_000);
        assert_eq!(
            watch.record_login("laptop", false, "1.2.3.4").tier,
            Tier::Info
        );
        advance(&clock, 1_000);
        assert_eq!(
            watch.record_login("laptop", false, "1.2.3.4").tier,
            Tier::Alert
        );
    }

    #[test]
    fn failures_outside_the_window_do_not_burst() {
        let clock = Arc::new(AtomicU64::new(1_000_000));
        let watch = watch_with_clock(Arc::clone(&clock));
        watch.record_login("laptop", true, "1.2.3.4");
        for _ in 0..2 {
            watch.record_login("laptop", false, "1.2.3.4");
            advance(&clock, FAILURE_SPIKE_WINDOW_MS + 1_000);
        }
        let event = watch.record_login("laptop", false, "1.2.3.4");
        assert_eq!(event.tier, Tier::Info);
    }

    #[test]
    fn failed_attempts_update_the_registry_and_ledger() {
        let watch = watch();
        watch.record_login("laptop", true, "1.2.3.4");
        let event = watch.record_login("laptop", false, "1.2.3.9");
        assert!(!event.success);
        let devices = watch.snapshot_devices();
        assert_eq!(devices.len(), 1);
        let laptop = &devices[0];
        assert_eq!(laptop.ok_count, 1);
        assert_eq!(laptop.fail_count, 1);
        assert_eq!(laptop.geo_counts.get("loc-home"), Some(&2));
    }

    #[test]
    fn event_log_stays_bounded() {
        let clock = Arc::new(AtomicU64::new(1_000_000));
        let watch = watch_with_clock(Arc::clone(&clock));
        for _i in 0..(EVENT_LOG_CAP + 50) {
            watch.record_login("laptop", true, "1.2.3.4");
            advance(&clock, 1);
        }
        assert_eq!(watch.recent_events().len(), EVENT_LOG_CAP);
        // Newest first: the last recorded attempt is at the front.
        assert_eq!(
            watch.recent_events()[0].at_ms,
            1_000_000 + EVENT_LOG_CAP as u64 + 49
        );
    }

    #[tokio::test]
    async fn notice_and_alert_fan_out_to_herald_info_stays_silent() {
        let (capture, addr) = spawn_capture(200).await;
        let notifier = Arc::new(HeraldNotifier::new(
            &capture.url,
            vec!["ntfy-test".to_string()],
            Some("key-1".to_string()),
        ));
        let watch = LoginWatch::with_parts(
            Some(notifier),
            Arc::new(StaticResolver),
            Box::new(|| 1_000_000),
        );

        watch.record_login("laptop", true, "1.2.3.4"); // INFO bootstrap
        watch.record_login("phone", true, "1.2.3.9"); // NOTICE new device
        watch.record_login("stranger", true, "9.9.9.1"); // ALERT new device unseen geo
                                                         // Give the spawned deliveries a moment to land.
        for _ in 0..50 {
            if capture.seen.lock().unwrap().len() == 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let seen = capture.seen.lock().unwrap();
        assert_eq!(
            seen.len(),
            2,
            "INFO must not notify; NOTICE/ALERT must: {seen:?}"
        );
        let levels: Vec<&str> = seen.iter().map(|n| n["level"].as_str().unwrap()).collect();
        assert_eq!(levels, vec!["warning", "critical"]);
        assert_eq!(seen[0]["type"], "persona.login");
        assert_eq!(seen[0]["channels"][0], "ntfy-test");
        let body = seen[0]["body"].as_str().unwrap();
        assert!(
            body.contains("phone") && body.contains("loc-home"),
            "{body}"
        );
        assert!(
            !body.contains("password"),
            "notifications never carry vault content"
        );
        let _ = addr;
    }

    #[tokio::test]
    async fn herald_total_failure_is_surfaced_as_an_error() {
        let (capture, _) = spawn_capture(500).await;
        let notifier = HeraldNotifier::new(&capture.url, vec!["log".to_string()], None);
        let err = notifier
            .send("warning", "t", "b")
            .await
            .expect_err("HTTP 500 must be an error");
        assert!(err.contains("500"), "{err}");
        assert_eq!(capture.reply_status, 500);
    }

    #[tokio::test]
    async fn dead_herald_gateway_never_panics_or_propagates() {
        // Nothing listens on this port.
        let notifier = Arc::new(HeraldNotifier::new(
            "http://127.0.0.1:1",
            vec!["log".to_string()],
            None,
        ));
        let watch = LoginWatch::with_parts(
            Some(notifier),
            Arc::new(StaticResolver),
            Box::new(|| 1_000_000),
        );
        watch.record_login("laptop", true, "1.2.3.4"); // INFO bootstrap, silent
        let event = watch.record_login("phone", true, "1.2.3.9"); // NOTICE -> delivery attempt
        assert_eq!(event.tier, Tier::Notice);
        // The spawned task logs and exits; the record path already returned.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }

    #[test]
    fn snapshot_devices_orders_by_recent_activity() {
        let clock = Arc::new(AtomicU64::new(1_000_000));
        let watch = watch_with_clock(Arc::clone(&clock));
        watch.record_login("old", true, "1.2.3.4");
        advance(&clock, 10_000);
        watch.record_login("new", true, "1.2.3.4");
        let devices = watch.snapshot_devices();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].last_ip, "1.2.3.4");
        // Deterministic order: "new" was seen last.
        assert!(devices[0].last_seen_ms > devices[1].last_seen_ms);
    }

    struct PerIpResolver;
    impl GeoResolver for PerIpResolver {
        fn resolve(&self, ip: &str) -> String {
            format!("geo-{ip}")
        }
    }

    #[test]
    fn device_and_geo_caps_bound_registry_growth() {
        // Device cap: one more than the cap; the least-recently-seen entry
        // is evicted so the registry never grows past the bound.
        let clock = Arc::new(AtomicU64::new(1_000_000));
        let watch = watch_with_clock(Arc::clone(&clock));
        for i in 0..MAX_TRACKED_DEVICES {
            watch.record_login(&format!("dev{i}"), true, "1.2.3.4");
            clock.fetch_add(1, Ordering::SeqCst);
        }
        assert_eq!(watch.snapshot_devices().len(), MAX_TRACKED_DEVICES);
        watch.record_login("dev-new", true, "1.2.3.4");
        let devices = watch.snapshot_devices();
        assert_eq!(devices.len(), MAX_TRACKED_DEVICES, "device cap holds");
        assert!(devices.iter().all(|d| d.device != "dev0"), "oldest evicted");
        assert!(
            devices.iter().any(|d| d.device == "dev4095"),
            "recent survivor kept"
        );
        assert!(
            devices.iter().any(|d| d.device == "dev-new"),
            "newest present"
        );

        // Geo cap: past the cap new location labels are not recorded, so a
        // second device arriving at the same fresh location still classifies
        // as unseen-location ALERT (the conservative reading) and the label
        // set stops growing.
        let clock2 = Arc::new(AtomicU64::new(2_000_000));
        let watch2 = LoginWatch::with_parts(
            None,
            Arc::new(PerIpResolver),
            Box::new(move || clock2.load(Ordering::SeqCst)),
        );
        for i in 0..MAX_TRACKED_GEOS {
            watch2.record_login(&format!("gd{i}"), true, &format!("10.{i}.0.1"));
        }
        // The late legs use an IP outside the loop's "10.{i}.0.1" family so
        // their label is genuinely fresh (10.999.0.1 itself is one of the
        // loop labels at i=999).
        watch2.record_login("late-a", true, "172.31.200.7"); // unseen geo, cap full -> refused
        watch2.record_login("late-b", true, "172.31.200.7"); // same geo, still unseen
        let events = watch2.recent_events();
        assert_eq!(events[0].device, "late-b");
        assert_eq!(
            events[0].tier,
            Tier::Alert,
            "geo cap: fresh label stays unseen"
        );
        assert_eq!(events[1].device, "late-a");
        assert_eq!(events[1].tier, Tier::Alert);
    }

    #[tokio::test]
    async fn notify_throttle_suppresses_repeat_fanout_within_window() {
        let (herald, _addr) = spawn_capture(200).await;
        let clock = Arc::new(AtomicU64::new(1_000_000));
        let value = Arc::clone(&clock);
        let watch = LoginWatch::with_parts(
            Some(Arc::new(HeraldNotifier::new(
                &herald.url,
                vec!["log".to_string()],
                None,
            ))),
            Arc::new(StaticResolver),
            Box::new(move || value.load(Ordering::SeqCst)),
        );
        watch.record_login("laptop", true, "1.2.3.4"); // INFO bootstrap, silent
                                                       // Three wrong proofs: the third fires the burst ALERT and stamps the throttle.
        for _ in 0..3 {
            watch.record_login("laptop", false, "1.2.3.5");
        }
        // Further failures inside the window stay ledgered as ALERT but deliver nothing.
        watch.record_login("laptop", false, "1.2.3.5");
        watch.record_login("laptop", false, "1.2.3.5");
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(
            herald.seen.lock().unwrap().len(),
            1,
            "only the first burst ALERT delivers inside the throttle window"
        );
        // Past the window the next ALERT delivers again.
        advance(&clock, NOTIFY_THROTTLE_MS + 1_000);
        watch.record_login("laptop", false, "1.2.3.5");
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(
            herald.seen.lock().unwrap().len(),
            2,
            "post-window ALERT delivers"
        );
        // Every failure was ledgered regardless of delivery suppression
        // (3 burst + 2 suppressed + 1 post-window).
        assert_eq!(
            watch.recent_events().iter().filter(|e| !e.success).count(),
            6
        );
    }
}
