# 自托管 persona-server（一键起）

`persona-server` 是可选的同步/备份中继。默认不用：桌面与 CLI 在不配置服务器时全功能本地可用（隐私红线：账号/同步默认关闭、显式开启）。

定位：**纯中继 + 密文保管**。服务器只见密文与最小元数据（备份是 PERSENC1 整库密文，同步 oplog 是密文载荷 + item UUID/kind/lamport/时间戳/设备公钥/信封——完整可见面清单见 `E2EE_SYNC_DESIGN.md` §9）。主密码不出设备。

## 前置

- Docker（compose v2）或本机 cargo（workspace 内 `cargo run -p persona-server`）。
- 一个强随机令牌（多设备推荐按设备拆分）。

## 一键起（compose，推荐）

```bash
export PERSONA_SERVER_TOKEN="换成强随机串"   # 单设备；多设备见下
# export PERSONA_SERVER_TOKENS="laptop:tok1,phone:tok2"  # 多设备令牌（可选叠加）
docker compose -f docker/docker-compose.deploy.yml up -d
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3000/health  # 200
```

说明：

- `PERSONA_SERVER_TOKEN` 未设置时 compose 拒绝启动（`:?` fail-closed：服务器不会以 API 禁用状态悄悄上线）。
- 多设备令牌 `PERSONA_SERVER_TOKENS="laptop:tok1,phone:tok2"`：设备名由令牌推导、客户端不可自报，备份版本按设备归属；legacy 单令牌兼容为 `default` 设备。
- 数据落命名卷 `persona-server-data`（`/data/persona-server.db` + `/data/backups`），容器重启保留。
- 健康检查：`GET /health`（免认证）；`/metrics` 免认证（Prometheus 文本）。

## 本地构建镜像

compose 默认拉 `ghcr.io/<owner>/persona-server:<tag>`。自建镜像：

```bash
docker build -f docker/Dockerfile.server -t persona-server:local .
# 把 compose 的 image 改成 persona-server:local 后同样 up -d
```

## 环境变量全表

| 变量                                   | 默认                  | 说明                                                                                    |
| -------------------------------------- | --------------------- | --------------------------------------------------------------------------------------- |
| `PERSONA_SERVER_TOKEN`                 | —（必填其一）         | legacy 单令牌；未配且 TOKENS 未配 → `/api/v1` 整体 503（fail-closed），`/health` 仍 200 |
| `PERSONA_SERVER_TOKENS`                | —                     | 多设备 `name:token,…`；非法格式启动即错                                                 |
| `PERSONA_SERVER_HOST` / `PORT`         | `0.0.0.0` / `3000`    | 监听面；只放内网/127.0.0.1 时按需改 HOST                                                |
| `PERSONA_SERVER_DB`                    | `./persona-server.db` | 事件库（WAL，与 core 身份库分离）                                                       |
| `PERSONA_SERVER_BACKUP_DIR`            | `./backups`           | 加密备份落盘目录（`{uuid}.persenc`）                                                    |
| `PERSONA_SERVER_BACKUP_MAX_VERSIONS`   | `0`（不限）           | 超出删最旧（全局跨设备）                                                                |
| `PERSONA_SERVER_OPS_RETENTION_DAYS`    | `0`（不清理）         | 同步 oplog 窗口：开窗 = 放弃向离线超窗设备补发历史；窗口须 ≥ 最慢设备的离线周期         |
| `PERSONA_SERVER_EVENTS_RETENTION_DAYS` | `0`（不清理）         | 审计事件副本保留，按 SIEM 摘取周期定                                                    |

## 客户端接线

备份链（CLI）：`PERSONA_SERVER_URL` + `PERSONA_SERVER_TOKEN` 都非空才启用（fail-closed）；`persona backup push/list/pull/restore/delete`。push 不要求解锁；restore 先确认后输口令、staged 复验成功才换库、旧库留 `.bak`。

同步（桌面）：设置页同步 pane 填 URL + token（token 真值进 OS keyring，库里只留占位）→ 设备管理区 join/authorize/revoke → `sync_now` 推拉。第一台设备 join 时空组自动建组（`bootstrap_group_if_empty`）；被吊销设备的短期令牌即刻失效（等 TTL 之外），历史密文前向安全靠手动「轮换组密钥」。

设备认证（SRP，DR-2）：`POST /api/v1/auth/register` 需既有 Bearer 作引导链（客户端本地生成 salt/verifier 上传，密码永不出机）→ `challenge` → `verify` 换 15 分钟短期 token；连续 5 次失败锁 15 分钟。静态令牌路径保留共存（备份链与事件上报不打断）。

## 端点速查（认证 = Bearer，静态或 SRP 短期）

- `/api/v1/events`（POST/GET）：审计事件批量 ≤500/body ≤1MiB，`client_event_id` 部分去重，游标分页。
- `/api/v1/backups`（POST/GET/DELETE）：流式落盘 256 MiB 上限、同设备最新版本 sha256 去重、下载 ETag=sha256。
- `/api/v1/sync/devices`（POST/GET/DELETE）：设备注册（公钥+设备名）/列出/吊销。
- `/api/v1/sync/group-keys`（GET/PUT）：设备信封取/传；`rotate-begin` 以 epoch 乐观锁抢写信封窗口（409 = 后到者重读重试）。
- `/api/v1/sync/oplog`（POST/GET）：push ≤500 条/批幂等（`op_id`），pull 游标增量。服务器不排序不合并（DR-4，裁决在客户端 LWW + 冲突双版本）。

## 运维注意

- 备份去重是密文级 sha256：PERSENC1 随机 salt+nonce 使每次 fresh push 密文不同，去重仅防同密文重试；版本数由 `BACKUP_MAX_VERSIONS` 封顶。
- oplog/事件保留窗口一旦开，离线超窗设备靠本地事实源 + 重推幂等补齐（INSERT OR IGNORE 原样回填），视图仍收敛。
- 服务器不防篡改/回滚/扣留（与备份保管同款边界，THREAT_MODEL 已登记）；设备被攻破的爆炸半径 = 该设备可见的全部同步数据（与本机被攻破同级）。
