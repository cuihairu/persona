use super::*;

#[test]
fn consume_rate_allows_exactly_the_cap_then_rejects_within_the_window() {
    let state = ConnectServerState::new(Arc::new(TokioMutex::new(None)));
    let id = Uuid::new_v4();
    for n in 1..=RATE_LIMIT_PER_MINUTE {
        assert!(state.consume_rate(id), "第 {n} 次在预算内");
    }
    assert!(
        !state.consume_rate(id),
        "第 {} 次必须超限（429）",
        RATE_LIMIT_PER_MINUTE + 1
    );
    // Counts are bucketed per token, not a global token bucket
    assert!(state.consume_rate(Uuid::new_v4()));
}

#[test]
fn consume_rate_sweeps_expired_windows_of_dead_tokens() {
    let state = ConnectServerState::new(Arc::new(TokioMutex::new(None)));
    // Dead slots: stale token entries whose window has expired (tokens deleted or
    // rotated are never accounted again).
    let stale = match Instant::now().checked_sub(RATE_WINDOW + Duration::from_secs(1)) {
        Some(at) => at,
        None => {
            eprintln!(
                "skip: 单调时钟不足 {}s，造不出过期窗口",
                RATE_WINDOW.as_secs()
            );
            return;
        }
    };
    // Fill past the sweep threshold (nothing is swept below it -- that is a normal
    // low-cardinality deployment).
    let mut dead = Vec::new();
    for _ in 0..(RATE_SWEEP_THRESHOLD + 1) {
        let id = Uuid::new_v4();
        dead.push(id);
        state
            .rates
            .lock()
            .unwrap()
            .insert(id, (stale, RATE_LIMIT_PER_MINUTE));
    }
    // Accounting at the threshold sweeps along the way: dead slots do not linger
    // (slow leak, audit batch 2 #10).
    let fresh = Uuid::new_v4();
    assert!(state.consume_rate(fresh));
    let rates = state.rates.lock().unwrap();
    assert_eq!(rates.len(), 1, "只有本次请求的活槽位留下");
    assert!(rates.contains_key(&fresh));
    assert!(dead.iter().all(|id| !rates.contains_key(id)));
}

#[test]
fn consume_rate_resets_the_counter_when_the_window_elapsed() {
    let state = ConnectServerState::new(Arc::new(TokioMutex::new(None)));
    let id = Uuid::new_v4();
    // Seed a slot whose window has already expired: Instant is a monotonic clock,
    // so reaching into the past requires checked_sub; when the machine has been
    // up for less than one window it cannot be constructed, so skip rather than
    // report a false failure.
    let stale = match Instant::now().checked_sub(RATE_WINDOW + Duration::from_secs(1)) {
        Some(at) => at,
        None => {
            eprintln!(
                "skip: 单调时钟不足 {}s，造不出过期窗口",
                RATE_WINDOW.as_secs()
            );
            return;
        }
    };
    state
        .rates
        .lock()
        .unwrap()
        .insert(id, (stale, RATE_LIMIT_PER_MINUTE));
    assert!(
        state.consume_rate(id),
        "过期窗口必须重置计数，否则 token 永久锁死"
    );
    // After the reset the count restarts from 1 -> the whole window budget is
    // still 120
    for _ in 1..RATE_LIMIT_PER_MINUTE {
        assert!(state.consume_rate(id));
    }
    assert!(!state.consume_rate(id));
}

#[tokio::test]
async fn rejected_requests_leave_the_rate_map_untouched() {
    let fx = fixture().await;
    for _ in 0..20 {
        // Missing token / bad Origin / bad Host / health: all of them return before
        // any accounting.
        send(fx.router.clone(), "GET", "/api/v1/connect/items", &[]).await;
        send(
            fx.router.clone(),
            "GET",
            "/api/v1/connect/items",
            &[("origin", "http://evil".to_string())],
        )
        .await;
        send_capture(
            fx.router.clone(),
            "GET",
            "/api/v1/connect/items",
            &[("host", "evil.example.com".to_string())],
        )
        .await;
        send(fx.router.clone(), "GET", "/api/v1/connect/health", &[]).await;
    }
    assert!(
        fx.state.rates.lock().unwrap().is_empty(),
        "未过检的请求不得占用 token 预算"
    );
    let auth = auth_header(&fx.token);
    for _ in 0..5 {
        let (status, _) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &auth).await;
        assert_eq!(status, StatusCode::OK);
    }
    let rates = fx.state.rates.lock().unwrap();
    assert_eq!(rates.len(), 1, "只有过检请求记账，且按 token 一条");
    assert_eq!(
        rates[&fx.token_row_id].1, 5,
        "计数应等于成功请求数（含在 handler 里被拒的请求，见下一个测试）"
    );
}

#[tokio::test]
async fn authenticated_requests_consume_budget_even_when_input_is_rejected() {
    let fx = fixture().await;
    // Seed the counter one request short of full: this proves accounting happens
    // inside the guard, before routing/extractors.
    fx.state
        .rates
        .lock()
        .unwrap()
        .insert(fx.token_row_id, (Instant::now(), RATE_LIMIT_PER_MINUTE - 1));
    let auth = auth_header(&fx.token);
    let (status, _, body) = send_capture(
        fx.router.clone(),
        "GET",
        "/api/v1/connect/items/not-a-uuid",
        &host_and_auth(&fx.token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["error"]["code"], "bad_request",
        "提取器拒绝也走统一包络（框架默认正文已由 normalize 包装）"
    );
    let (status, body) = send(fx.router, "GET", "/api/v1/connect/items", &auth).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"]["code"], "rate_limited");
}

#[tokio::test]
async fn rate_limit_is_per_token_not_per_process() {
    let fx = fixture().await;
    let second = mint_token(&fx, "second", read_scope(vec![], vec![])).await;
    let first = auth_header(&fx.token);
    for _ in 0..RATE_LIMIT_PER_MINUTE {
        let (status, _) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &first).await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, body) = send(fx.router.clone(), "GET", "/api/v1/connect/items", &first).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"]["code"], "rate_limited");
    // The other token is unaffected (a runaway client must not be able to DoS other
    // integrations)
    let (status, _) = send(
        fx.router.clone(),
        "GET",
        "/api/v1/connect/items",
        &auth_header(&second),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fx.state.rates.lock().unwrap().len(), 2);
}

// -------------------------------------------------------------------
// Scope filtering and item visibility (data-plane state transitions)
// -------------------------------------------------------------------
