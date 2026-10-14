> [English](REMOTE_AUTH.md) | **中文**

# 远程认证（SRP 风格抽象）

Persona 为未来的客户端-服务器同步模型做准备，对外暴露一个与协议无关的抽象，用以镜像 Secure Remote Password（SRP）的工作流程。其目标是在不把主密码发送到服务器的前提下，仍能派生出双向认证的会话密钥。

## 组件

- `SrpParameters`：服务器提供的 模数/生成元/盐 元组（hex 编码以便传输）。
- `SrpHandshake`：客户端与服务器的公开值（SRP 术语中的 `A`/`B`）。
- `SrpProof`：消息认证（`M1`/`M2`）。
- `RemoteAuthProvider`：开启/终结握手的 trait。
- `MockRemoteAuthProvider`：默认的内存占位实现，使 CLI 可以离线运行。

## 流程

1. 客户端调用 `begin(username)`，返回：
   - 随机 `user_id`（在真实服务器 ID 存在之前为 UUID 占位）。
   - `SrpParameters`（当前以小数值模拟）。
   - `SrpHandshake`，包含服务器公开值与一个占位的客户端公开值。
2. 客户端在本地派生其证明，并调用 `finalize(challenge, client_proof)`。
3. Provider 验证客户端证明，返回 `RemoteAuthResult`（服务器证明 + 会话密钥指纹）。
4. 更高层现在可以把该指纹绑定到解锁密钥/会话。

mock provider 仅服务于测试/UI 串联；服务器实现将提供真正的 SRP 运算，并持久化 salt/verifier。

## 真实实现（2026-09，E2EE 同步一期）

服务器端 SRP 已上线：

- `core/src/auth/srp.rs` — 生产级 SRP-6a 运算（RFC 5054 4096 位组、SHA-256、Argon2id 预哈希），客户端与服务器共用；正确性由 RFC 5054 附录 B 的互操作测试向量锁定。
- `server/src/api/auth.rs` — `POST /api/v1/auth/register`（需要一个已存在的 bearer token）、`/challenge`、`/verify`（签发 15 分钟 bearer token；失败 5 次后锁定）。静态 `PERSONA_SERVER_TOKENS` bearer 路径与之并存。
- 威胁模型登记：`docs/THREAT_MODEL.md`，章节「SRP 设备认证端点」；设计决策见 `docs/E2EE_SYNC_DESIGN.md`（DR-2）。

客户端 HTTP 对接也已上线（2026-09-22）：

- `core/src/auth/remote_http.rs`（feature `remote-auth`）— `HttpRemoteAuthProvider`（`register_device` / `begin_login` / `PendingRemoteLogin::finish`）驱动真实的三端点流程，并在交出 token 之前验证服务器证明 `M2`。上面的 mock trait 仍作为 UI 接缝保留：其两步形态无法承载真正的 SRP 会话（`a_priv` 必须从 `A` 到 `M2` 验证归属同一持有者），因此真实客户端是独立的类型，未来的 OPAQUE 工作只替换本文件。
- 跨端集成测试：`server/src/api/auth.rs::tests::http_provider_full_round_trip_over_real_tcp` 在真实 TCP 上针对服务器路由跑完整的 register → challenge → verify 流程，并断言签发的 SRP token 能与静态 token 一样通过 `require_bearer`。

## 账号域 SRP（2026-10，M2）与配对中继（S1）

同一套 SRP 运算还支撑另外两个远程认证面：

- **账号域** — `POST /api/v1/accounts/{id}/srp/register|challenge|verify`（服务器：`server/src/api/accounts.rs`）：persona-account 线的口令认证，配套 Passkey（WebAuthn）仪式、一次性恢复码，以及账号作用域的设备/会话管理。bearer 门禁的写路径：srp/register、恢复码生成、devices、sessions。红线验证脚本：`scripts/verify-account-redline.sh`（10 条在线断言：公开 register、fail-closed 401、一次性恢复码、session-evidence 422、设备/会话族 401）。
- **同步组配对中继客户端** — `core/src/sync/pairing.rs::relay`（同一个 `remote-auth` feature）：`PairingRelayClient` 驱动零账号配对邮箱（`/api/v1/pairing/*`，无 bearer）完成动态口令 PAKE 握手；状态见 `docs/sync-group-mode.md` §四。验证脚本：`scripts/verify-sync-group-pairing.sh`。
