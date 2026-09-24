# 认证 API

Persona Server 的设备认证轨道：基于 SRP（Secure Remote Password）的设备
登录，换取短期 Bearer 令牌。协议设计见
[E2EE_SYNC_DESIGN](https://github.com/cuihairu/persona/blob/main/docs/E2EE_SYNC_DESIGN.md)。

## 认证模型

- **设备即身份**：每台设备以设备名在服务器登记 SRP 盐与 verifier；同名
  视为同一设备（重装重登记即覆盖）。
- **令牌**：`/auth/verify` 成功后发放短期令牌（约 15 分钟 TTL），后续
  `/api/v1/*` 请求以 `Authorization: Bearer <token>` 携带。
- **fail-closed**：服务器未配置令牌轨道时，受保护端点一律 503，不降级
  放行。
- **吊销即时生效**：删除设备会立即吊销其内存中的短期令牌与未决握手，
  不等 TTL 过期。

## 端点

| 方法 | 路径                        | 认证         | 用途                                       |
| ---- | --------------------------- | ------------ | ------------------------------------------ |
| POST | `/api/v1/auth/register`     | 需既有 Bearer | 登记/覆盖本设备的 SRP 盐与 verifier（引导链） |
| POST | `/api/v1/auth/challenge`    | 免           | 发起 SRP 挑战                              |
| POST | `/api/v1/auth/verify`       | 免           | 提交 SRP 证明，换取短期 Bearer 令牌        |

`challenge` / `verify` 免认证——它们本身就是换取令牌的登录步骤；
`register` 走 Bearer 保护（新设备由已认证会话引导接入）。

## 边界

- 请求体上限 64 KiB（盐 / verifier / SRP 公开值都远小于此，防异常载荷）。
- 服务器只保存 verifier，永远不接触主密码或库密钥。
- 认证成功只证明「这台设备登记过」，不等于已加入同步组——同步组授权
  见[同步 API](/api/sync)。

## 与客户端的衔接

桌面端「设置 → 同步设备」完成上述握手；CLI 走环境变量配置
（见 [STORAGE_AND_SYNC.md](https://github.com/cuihairu/persona/blob/main/docs/STORAGE_AND_SYNC.md) 的客户端配置节）。
