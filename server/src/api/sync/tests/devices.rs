use super::*;

#[tokio::test]
async fn device_register_list_delete_round_trip() {
    let router = router().await;
    let id = register_device(&router, "laptop").await;

    let (status, body) = send(router.clone(), get_req("/api/v1/sync/devices")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["devices"].as_array().unwrap().len(), 1);
    assert_eq!(body["devices"][0]["device_name"], "laptop");
    // 公钥 b64 往返
    let key = B64
        .decode(body["devices"][0]["public_key"].as_str().unwrap())
        .unwrap();
    assert_eq!(key, vec![7u8; 32]);

    let (status, _) = send(
        router.clone(),
        req("DELETE", &format!("/api/v1/sync/devices/{id}"), ""),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, body) = send(router.clone(), get_req("/api/v1/sync/devices")).await;
    assert_eq!(body["devices"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn device_remark_self_service_round_trip() {
    let router = router().await;
    // 单令牌配置下令牌归属设备名是 "default"（AuthTokens::single），
    // remark 端点按令牌归属名定位行——注册名必须一致。
    register_device(&router, "default").await;

    // 默认空备注
    let (_, body) = send(router.clone(), get_req("/api/v1/sync/devices")).await;
    assert_eq!(body["devices"][0]["remark"], "");

    // 设置 → 回显 → 列表反映
    let (status, body) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/devices/remark",
            &json!({ "remark": "我的笔记本" }).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["device_name"], "default");
    assert_eq!(body["remark"], "我的笔记本");

    let (_, body) = send(router.clone(), get_req("/api/v1/sync/devices")).await;
    assert_eq!(body["devices"][0]["remark"], "我的笔记本");

    // 空串 = 清除
    let (status, _) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/devices/remark",
            &json!({ "remark": "  " }).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body) = send(router.clone(), get_req("/api/v1/sync/devices")).await;
    assert_eq!(body["devices"][0]["remark"], "");
}

#[tokio::test]
async fn device_remark_is_locked_to_own_device() {
    let router = two_device_router().await;
    register_device_with_token(&router, "laptop", "tok-laptop").await;
    register_device_with_token(&router, "phone", "tok-phone").await;

    // 各自写各自的
    let (status, _) = send(
        router.clone(),
        req_with_token(
            "PUT",
            "/api/v1/sync/devices/remark",
            "tok-laptop",
            &json!({ "remark": "主力机" }).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(
        router.clone(),
        req_with_token(
            "PUT",
            "/api/v1/sync/devices/remark",
            "tok-phone",
            &json!({ "remark": "备用机" }).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // laptop 令牌再看清单：自己的备注在，phone 的备注不归它管也没被它动
    let (_, body) = send(
        router.clone(),
        request(
            "GET",
            "/api/v1/sync/devices",
            Some("Bearer tok-laptop"),
            None,
            "",
        ),
    )
    .await;
    let rows = body["devices"].as_array().unwrap();
    let laptop = rows.iter().find(|d| d["device_name"] == "laptop").unwrap();
    let phone = rows.iter().find(|d| d["device_name"] == "phone").unwrap();
    assert_eq!(laptop["remark"], "主力机");
    assert_eq!(phone["remark"], "备用机");
}

#[tokio::test]
async fn device_remark_rejects_over_limit_and_unregistered_device() {
    let router = router().await;

    // > 128 字节 → 422 validation（字段校验的统一形状）
    let (status, body) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/devices/remark",
            &json!({ "remark": "长".repeat(129) }).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"]["code"], "validation");

    // 令牌归属的设备名未登记 → 404 absent（接口形态上无跨设备路径）
    let (status, body) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/devices/remark",
            &json!({ "remark": "孤儿" }).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn device_registration_rejects_duplicate_name_and_bad_key() {
    let router = router().await;
    register_device(&router, "phone").await;
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            "/api/v1/sync/devices",
            &json!({"device_name": "phone", "public_key": b64(&[7u8; 32])}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // 公钥长度错（31B）与坏 b64 都是 422
    for bad in [b64(&[7u8; 31]), "!!!not-base64!!!".to_string()] {
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                "/api/v1/sync/devices",
                &json!({"device_name": "other", "public_key": bad}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    }
}

#[tokio::test]
async fn group_key_envelope_round_trip_and_fail_closed() {
    let router = router().await;
    let device = register_device(&router, "laptop").await;
    let envelope_bytes: Vec<u8> = (0..80).map(|i| i as u8).collect();

    // 未登记设备挂信封 → 422（fail-closed 的服务器侧一半）
    let ghost = Uuid::new_v4();
    let (status, body) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/group-keys",
            &json!({"device_id": ghost.to_string(), "envelope": b64(&envelope_bytes)}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // 正常上传 → GET 原样取回
    let (status, _) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/group-keys",
            &json!({"device_id": device.to_string(), "envelope": b64(&envelope_bytes)}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, body) = send(router.clone(), get_req("/api/v1/sync/group-keys")).await;
    let keys = body["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["device_id"], device.to_string());
    assert_eq!(
        B64.decode(keys[0]["envelope"].as_str().unwrap()).unwrap(),
        envelope_bytes
    );
    assert_eq!(keys[0]["sealed_by"], "default"); // AuthTokens::single 的设备名

    // 长度不是 80B 的信封拒绝
    let (status, _) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/group-keys",
            &json!({"device_id": device.to_string(), "envelope": b64(&[0u8; 79])}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // 吊销设备 → 信封随之消失
    send(
        router.clone(),
        req("DELETE", &format!("/api/v1/sync/devices/{device}"), ""),
    )
    .await;
    let (_, body) = send(router, get_req("/api/v1/sync/group-keys")).await;
    assert_eq!(body["keys"].as_array().unwrap().len(), 0);
}

/// 设备登记与信封端点的校验/故障臂：device_name 边界（trim 后空与
/// 129 字节）、DELETE 非法 UUID 的幂等 204、put_group_key 的
/// device_id / envelope base64 校验、信封表与 epoch 表损坏时的
/// fail-closed 500（含删除级联半途失败——幂等重试设计不把故障
/// 伪装成 204）。
#[tokio::test]
async fn device_and_group_key_error_arms() {
    let (router, state) = crate::test_support::setup(Some(TOKEN)).await;

    // device_name：trim 后为空 / 129 字节 → 422（1..=128 字节边界）
    for name in ["   ".to_string(), "x".repeat(129)] {
        let (status, body) = send(
            router.clone(),
            req(
                "POST",
                "/api/v1/sync/devices",
                &json!({"device_name": name, "public_key": b64(&[7u8; 32])}).to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["error"]["code"], "validation");
        assert!(body["error"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["field"] == "device_name"));
    }

    // DELETE 非法 UUID：按「不存在」的幂等语义处理 → 204
    let (status, _) = send(
        router.clone(),
        req("DELETE", "/api/v1/sync/devices/not-a-uuid", ""),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let device = register_device(&router, "laptop").await;
    let envelope = b64(&(0..80u8).collect::<Vec<u8>>());

    // put_group_key：device_id 非 UUID / envelope 坏 base64 → 422
    let (status, body) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/group-keys",
            &json!({"device_id": "not-a-uuid", "envelope": envelope}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let (status, body) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/group-keys",
            &json!({"device_id": device.to_string(), "envelope": "!!!not-base64!!!"}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

    // 信封表被删：已登记设备的 upsert → 500 internal（不外泄 sqlx 细节）
    sqlx::query("DROP TABLE sync_group_keys")
        .execute(&state.pool)
        .await
        .unwrap();
    let (status, body) = send(
        router.clone(),
        req(
            "PUT",
            "/api/v1/sync/group-keys",
            &json!({"device_id": device.to_string(), "envelope": envelope}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");

    // 删除级联走到一半失败（名字查询成功、信封删除报错）→ 500，
    // 整体可重试；不得谎报成功。
    let (status, _) = send(
        router.clone(),
        req("DELETE", &format!("/api/v1/sync/devices/{device}"), ""),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

    // epoch 单行表损坏：group-keys 的 epoch 读取与 rotate-begin 的
    // 事务提交都 fail-closed 500
    sqlx::query("DROP TABLE sync_group_epoch")
        .execute(&state.pool)
        .await
        .unwrap();
    let (status, _) = send(router.clone(), get_req("/api/v1/sync/group-keys")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let (status, _) = send(
        router.clone(),
        req(
            "POST",
            "/api/v1/sync/group-key/rotate-begin",
            &json!({"if_epoch": 0}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

/// 连接池关闭（等价任意底层 DB 故障）后，各 sync 读/写端点统一
/// 500 internal：register 的非 UNIQUE 插入失败、list_devices、
/// delete 的名字查询、group-keys 行读取、oplog push 落库与 pull
/// 查询——都不能把 DB 抖动折成 4xx 误导客户端。
#[tokio::test]
async fn db_failure_surfaces_internal_across_sync_endpoints() {
    let (router, state) = crate::test_support::setup(Some(TOKEN)).await;
    let device = register_device(&router, "laptop").await;
    let item = Uuid::new_v4().to_string();
    state.pool.close().await;

    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            "/api/v1/sync/devices",
            &json!({"device_name": "phone", "public_key": b64(&[7u8; 32])}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["error"]["code"], "internal");

    let (status, _) = send(router.clone(), get_req("/api/v1/sync/devices")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

    let (status, _) = send(
        router.clone(),
        req("DELETE", &format!("/api/v1/sync/devices/{device}"), ""),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

    let (status, _) = send(router.clone(), get_req("/api/v1/sync/group-keys")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

    // 校验全过的合法 op：落库失败 → 500（不是 4xx）
    let op = put_op_json(&Uuid::new_v4().to_string(), &item, 1, &device, &[0u8; 4]);
    let (status, body) = send(
        router.clone(),
        req(
            "POST",
            "/api/v1/sync/oplog",
            &json!({"ops": [op]}).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");

    let (status, _) = send(router, get_req("/api/v1/sync/oplog")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}
