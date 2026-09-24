# 同步 API

Persona Server 的端到端加密同步轨道：服务器**只中继密文**——密文操作
日志（oplog）、设备信封与组密钥信封，永远不持有解密能力。协议全貌见
[E2EE_SYNC_DESIGN](https://github.com/cuihairu/persona/blob/main/docs/E2EE_SYNC_DESIGN.md)。

全部端点需 Bearer 令牌（[认证 API](/api/authentication) 换取）。

## 端点

| 方法   | 路径                                  | 用途                                        |
| ------ | ------------------------------------- | ------------------------------------------- |
| POST   | `/api/v1/sync/devices`                | 登记本设备（设备信封上传）                  |
| GET    | `/api/v1/sync/devices`                | 列出同步组设备                              |
| DELETE | `/api/v1/sync/devices/:id`            | 吊销设备（级联删信封与同名 SRP 登记，幂等） |
| GET    | `/api/v1/sync/group-keys`             | 取组密钥信封族（随 epoch 基线下发）         |
| PUT    | `/api/v1/sync/group-keys`             | 写组密钥信封（轮换时为每台设备重封）        |
| POST   | `/api/v1/sync/group-key/rotate-begin` | 轮换互斥点：epoch CAS，抢占失败 409         |
| POST   | `/api/v1/sync/oplog`                  | 推送密文操作日志（幂等，重复推不膨胀）      |
| GET    | `/api/v1/sync/oplog`                  | 拉取操作日志（游标分页，非空页恒返回游标）  |

## 关键语义

- **冲突裁决在客户端**：服务器不解释 oplog 内容；并发修改同一凭据由
  客户端以 Lamport 时钟 LWW 定主位，败方保留为待裁决副本（人工裁决 UI）。
- **并发轮换互斥**：`rotate-begin` 在事务内做 epoch CAS（`epoch ==`
  请求携带的 `if_epoch` 才 +1 并提交），后到者收 409——防两台设备同时
  轮换产生分裂的信封族；只防诚实客户端意外并发，不防恶意绕过。
- **崩溃续跑**：轮换中途崩溃留下的混合信封态无需人工修复——重试轮换
  会以新 epoch 重跑并用新信封覆盖残留。
- **服务器可见面**：密文、设备 ID/名、操作计数与时间戳；不包含明文、
  URL、用户名等凭据内容。

## 边界

- 请求体上限 1 MiB（凭据密文 KB 级，一批 500 条足够）；无解压层（密文
  不可压，兼免解压炸弹面）。
- 附件不参与同步（本地存储；走备份通道是 v2 议题）。
- 保留策略：oplog/events 按 env 窗口滚动清理（默认不清理），窗口须
  ≥ 最慢设备离线周期——见 [STORAGE_AND_SYNC.md](https://github.com/cuihairu/persona/blob/main/docs/STORAGE_AND_SYNC.md) 部署节。

## 运维面

免认证端点：`GET /`（服务信息）、`GET /health`、`GET /metrics`
（Prometheus：同步/事件/清理计数器）。审计事件接入与查询（`/api/v1/events`）、
加密备份保管（`/api/v1/backups`）走独立 Bearer 令牌轨道，见
[STORAGE_AND_SYNC.md](https://github.com/cuihairu/persona/blob/main/docs/STORAGE_AND_SYNC.md) 端点表。
