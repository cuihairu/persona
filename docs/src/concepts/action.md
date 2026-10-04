# 动作（Action）

**一句话**：动作是作用于某个[材料](./material)的具体操作——reveal、
copy、fill、TOTP、generate、sign、save。**动作才携带权限语义**：
一份 SSH key 没有权限，`sign` 这个动作才有；一次填充没有权限，
`request_fill` 这个动作（连同它的 user gesture、domain binding）才是。

把 Material 与 Action 分开的直接结果是：

- **客户端不接触明文也能工作**——浏览器扩展只发动作请求，core 裁决后返回
  结果（或拒绝）；这正是「扩展不拥有密码」在协议层的体现；
- **同一种材料的多种动作可以有不同的门槛**——查看密码要再认证，自动填充
  也只在该站已建信任时发生，签名要确认或生物识别；
- **审计跟着动作走**——审计记录的是「谁在什么上下文请求了什么动作」，
  而不是「哪个条目被读了一次」。

## 现状：动作清单与闸门

crypto 动作（bridge 协议消息类型，均要求配对 + session HMAC 认证）：

| 动作         | 协议消息            | 闸门（core 裁决）                                               |
| ------------ | ------------------- | --------------------------------------------------------------- |
| 建议         | `get_suggestions`   | origin + active identity + match strength                       |
| 填充         | `request_fill`      | user gesture + origin binding（fetch 到的凭据内容只回给本页）   |
| TOTP 获取    | `get_totp`          | user gesture + origin binding                                   |
| 复制         | `copy`              | user gesture（由桌面/CLI 执行剪贴板，含 30s 自动清除）           |
| 通行密钥创建 | `passkey_create`    | user gesture + 桌面审批                                          |
| 通行密钥断言 | `passkey_assert`    | user gesture + 桌面审批                                          |
| 保存/更新    | `save_credential`   | user gesture + 桌面审批（credential_save）+ origin binding + 审计 |
| 密码生成     | `generate_password` | 认证 session；纯生成不落库                                       |

协议细节见 [BRIDGE_PROTOCOL](https://github.com/cuihairu/persona/blob/main/docs/BRIDGE_PROTOCOL.md)。

本地动作（core 直连入口）：

| 动作     | 入口                 | 闸门                                       |
| -------- | -------------------- | ------------------------------------------ |
| reveal   | CLI/桌面             | 解锁 + 敏感操作再认证 + 30s 自动隐藏       |
| SSH 签名 | SSH Agent            | 策略引擎：known_hosts、确认、速率限制、生物识别优先级 |
| 导出     | `persona export`     | 解锁 + 目标加密策略确认                    |
| 钱包签名 | 桌面/wallet（试验）  | 确认模态：地址/金额/链/防地址投毒提示      |

## 规划

- 每个动作的「自动 / 确认 / 拒绝」三元组可被[规则层](./policy#愿景规则层规划未实现)定制；
- 未来的 [Principal](./principal)（Agent）会获得**动作级白名单**
  （例如 codex 只允许 `git` 相关签名，禁止钱包签名），而无需获得材料本身。