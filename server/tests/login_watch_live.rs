//! PERSONA-DEVALERT-001 live acceptance harness: the REAL `persona-server`
//! binary (subprocess, its own env) against the REAL Herald gateway, driven
//! by the real core client stack (`HttpRemoteAuthProvider`).
//!
//! CI never runs this: the test is `#[ignore]`-gated and only engages when
//! `PERSONA_LOGIN_WATCH_LIVE=1`, a Herald base URL is provided via
//! `PERSONA_LOGIN_WATCH_HERALD_URL`, and the server binary exists under the
//! workspace `target/debug`. Run it after building:
//!
//! ```text
//! cargo build -p persona-server
//! # terminal 1: heraldd serve --config <loopback config with a log provider>
//! PERSONA_LOGIN_WATCH_LIVE=1 \
//! PERSONA_LOGIN_WATCH_HERALD_URL=http://127.0.0.1:8901 \
//! PERSONA_LOGIN_WATCH_HERALD_LOG=/tmp/devalert-live/herald.out \
//! cargo test -p persona-server --test login_watch_live -- --ignored --nocapture
//! ```
//!
//! Acceptance walk (Apple/Steam-Parity login awareness):
//! 1. first-ever device login (loopback) — INFO bootstrap, nothing delivered;
//! 2. NEW device from a seen location — Herald receives a `warning` NOTICE;
//! 3. established device from a different local IP (real distinct peer
//!    address, not a spoofed header) — `warning` NOTICE;
//! 4. NEW device from a location the registry has never seen (the LAN
//!    address) — `critical` ALERT;
//! 5. failure burst (3 wrong proofs) — `critical` ALERT;
//! 6. `GET /api/v1/auth/devices` returns the structured registry.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use persona_core::auth::remote_http::HttpRemoteAuthProvider;

const BOOTSTRAP: &str = "live-bootstrap-token";
const PASSWORD: &str = "live acceptance password";

fn server_bin() -> Option<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let bin = manifest.parent().unwrap().join("target/debug/persona-server");
    bin.exists().then_some(bin)
}

async fn wait_ready(base: &str) {
    for _ in 0..50 {
        if let Ok(resp) = reqwest::Client::new().get(format!("{base}/health")).send().await {
            if resp.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("server never became ready at {base}");
}

async fn login(base: &str, device: &str, password: &str) -> Result<(), anyhow::Error> {
    let provider = HttpRemoteAuthProvider::new(base)?;
    provider
        .begin_login(device)
        .await?
        .finish(password)
        .await
        .map(|_| ())
}

async fn register_device(base: &str, device: &str) {
    let provider = HttpRemoteAuthProvider::new(base).unwrap();
    provider
        .register_device(BOOTSTRAP, device, PASSWORD)
        .await
        .unwrap();
}

async fn herald_log_contains(log: &str, needle: &str) -> bool {
    for _ in 0..50 {
        if let Ok(body) = std::fs::read_to_string(log) {
            if body.contains(needle) {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live acceptance: needs a built server binary and a running Herald (see module docs)"]
async fn login_awareness_live_chain_reaches_herald() {
    if std::env::var("PERSONA_LOGIN_WATCH_LIVE").as_deref() != Ok("1") {
        panic!("set PERSONA_LOGIN_WATCH_LIVE=1 (and the PERSONA_LOGIN_WATCH_* vars) to run the live chain");
    }
    let herald_url = std::env::var("PERSONA_LOGIN_WATCH_HERALD_URL")
        .expect("PERSONA_LOGIN_WATCH_HERALD_URL (Herald base, e.g. http://127.0.0.1:8901)");
    let herald_log = std::env::var("PERSONA_LOGIN_WATCH_HERALD_LOG")
        .unwrap_or_else(|_| "/tmp/devalert-live/herald.out".to_string());
    let bin = server_bin().expect("build persona-server first: cargo build -p persona-server");
    let lan_ip =
        std::env::var("PERSONA_LOGIN_WATCH_LAN_IP").expect("a second local IP (LAN) for the geo-deviation leg");

    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("live.db");
    let port: u16 = std::env::var("PERSONA_LOGIN_WATCH_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(18902);
    let base = format!("http://127.0.0.1:{port}");
    let lan_base = format!("http://{lan_ip}:{port}");

    let mut server = tokio::process::Command::new(&bin)
        .env("PERSONA_SERVER_DB", &db)
        .env("PERSONA_SERVER_TOKENS", format!("bootstrap:{BOOTSTRAP}"))
        .env("PERSONA_SERVER_HOST", "0.0.0.0")
        .env("PERSONA_SERVER_PORT", port.to_string())
        .env("PERSONA_HERALD_URL", &herald_url)
        .env("PERSONA_HERALD_CHANNELS", "log")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn persona-server");
    wait_ready(&base).await;

    // Leg 1: first-ever sighting -> INFO bootstrap (nothing delivered).
    register_device(&base, "laptop-lan").await;
    login(&base, "laptop-lan", PASSWORD).await.expect("leg 1 login");

    // Leg 2: NEW device, location already seen -> NOTICE (warning).
    register_device(&base, "phone-lab").await;
    login(&base, "phone-lab", PASSWORD).await.expect("leg 2 login");
    assert!(
        herald_log_contains(&herald_log, "[warning] New device login: phone-lab").await,
        "herald must receive the new-device NOTICE"
    );

    // Leg 3: NEW device from the never-seen LAN location -> ALERT (critical).
    // Ordered BEFORE the established-device leg: once any device logs in
    // from the LAN, that location is "seen" and a new device there would
    // only be NOTICE.
    register_device(&lan_base, "stranger-box").await;
    login(&lan_base, "stranger-box", PASSWORD).await.expect("leg 3 login");
    assert!(
        herald_log_contains(
            &herald_log,
            "[critical] Alert: login from a new device in an unseen location (stranger-box)"
        )
        .await,
        "herald must receive the new-device-unseen-location ALERT"
    );

    // Leg 4: established device, second local IP = a real new location -> NOTICE.
    login(&lan_base, "laptop-lan", PASSWORD).await.expect("leg 4 login");
    assert!(
        herald_log_contains(&herald_log, "[warning] Login from a new location: laptop-lan").await,
        "herald must receive the unusual-location NOTICE"
    );

    // Leg 5: failure burst (3 wrong proofs inside the window) -> ALERT.
    for _ in 0..3 {
        let _ = login(&base, "laptop-lan", "totally wrong").await;
    }
    assert!(
        herald_log_contains(&herald_log, "[critical] Alert: repeated login failures (laptop-lan)").await,
        "herald must receive the failure-burst ALERT"
    );

    // Leg 6: the devices registry endpoint returns the structured list.
    let provider = HttpRemoteAuthProvider::new(&base).unwrap();
    let outcome = provider
        .begin_login("phone-lab")
        .await
        .unwrap()
        .finish(PASSWORD)
        .await
        .unwrap();
    let resp = reqwest::Client::new()
        .get(format!("{base}/api/v1/auth/devices"))
        .bearer_auth(&outcome.token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    let devices = body["devices"].as_array().expect("devices array");
    assert_eq!(devices.len(), 3, "three devices registered: {body}");
    let laptop = devices
        .iter()
        .find(|d| d["device"] == "laptop-lan")
        .expect("laptop-lan entry");
    assert!(laptop["geo_counts"].as_object().unwrap().len() >= 2, "{laptop}");
    assert!(laptop["fail_count"].as_u64().unwrap() >= 3, "{laptop}");
    let stranger = devices
        .iter()
        .find(|d| d["device"] == "stranger-box")
        .expect("stranger-box entry");
    assert!(stranger["last_geo"].as_str().unwrap().starts_with("v4-"), "{stranger}");

    server.kill().await.ok();
}
