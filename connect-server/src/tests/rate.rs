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
    // 计数按 token 分列，不是全局令牌桶
    assert!(state.consume_rate(Uuid::new_v4()));
}

#[test]
fn consume_rate_sweeps_expired_windows_of_dead_tokens() {
    let state = ConnectServerState::new(Arc::new(TokioMutex::new(None)));
    // 死槽位：窗口已过期的历史 token 条目（token 已删/已换后永不再记账）。
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
    // 填到超过清扫阈值（阈值以下不会清——那是正常低基数部署）。
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
    // 阈值记账顺路清扫：死槽位不留（慢泄漏，audit 批2 #10）。
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
    // 直接种一个「窗口已过期」的槽位：Instant 是单调时钟，构造过去只能
    // 靠 checked_sub；机器开机不足一个窗口时长时无法构造，跳过而非误红。
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
    // 重置后从 1 重新起算 → 整窗预算仍是 120
    for _ in 1..RATE_LIMIT_PER_MINUTE {
        assert!(state.consume_rate(id));
    }
    assert!(!state.consume_rate(id));
}

#[tokio::test]
async fn rejected_requests_leave_the_rate_map_untouched() {
    let fx = fixture().await;
    for _ in 0..20 {
        // 缺 token / 坏 Origin / 坏 Host / health：全都在记账之前返回。
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
    // 种到差一次即满：证明计数发生在 guard 内、路由/提取器之前。
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
    // 另一个 token 不受牵连（一个失控客户端不能 DoS 其他集成）
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
// scope 过滤与条目可见性（数据面状态流转）
// -------------------------------------------------------------------
