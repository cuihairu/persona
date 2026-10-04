# 身份材料（Material）

**一句话**：身份材料是分身名下被保护的**数据资产**——密码、SSH 密钥、
API key、TOTP、钱包、通行密钥都是材料。「材料」统一了它们的存储、加密、
审计与授权语义：一种材料可以被多种[动作](./action)作用于，但材料本身
不携带任何权限。

## 现状：有哪些材料

core 数据模型里，材料落在三张表里（全部通过 `identity_id` 归属分身）：

| 存储表           | 材料                                                                                                                                                                       |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `credentials`    | `CredentialType`：Password、TwoFactor(TOTP)、ApiKey、SshKey、CryptoWallet、BankCard、GameAccount、ServerConfig、Certificate、SecureNote、SoftwareLicense、Identity、Custom |
| `crypto_wallets` | 加密钱包（BTC/ETH/Solana，BIP-143 / EIP-155 / EIP-1559 派生与签名）                                                                                                        |
| `passkeys`       | WebAuthn 通行密钥（RP 绑定、attestation 留存）                                                                                                                             |

安全属性（详见 [安全设计](/design/security) 与
[Key Hierarchy](https://github.com/cuihairu/persona/blob/main/docs/KEY_HIERARCHY.md)）：

- 每条凭据用**独立 item key** 加密（AES-GCM），master key 只包裹 item key——
  单项泄露不影响其它材料；
- URL、用户名等是**展示/绑定字段**：浏览器 fill/save 按 TLD+1 域名绑定；
  敏感内容（密码、TOTP secret、私钥）只存在于解密后的瞬时内存；
- 审计日志只记资源 ID、动作、摘要，不记材料内容。

## 材料与分身的关系

一份材料**只能属于一个分身**，但一个分身可以拥有任意多份材料；
同一实体的多份材料（GitHub 密码 / GitHub SSH key / GitHub API key）
是独立条目，各自轮换、各自审计、各自授权。

## 材料 ≠ 动作

材料只是数据。「reveal 它」「用它填充」「让 SSH Agent 用它签名」是动作
([动作](./action))，动作才触发策略检查与审计。这个分离的直接推论：

- 浏览器扩展**不拥有密码**——它只请求 `request_fill` / `save_credential`
  这类动作，由本地 core 裁决；
- SSH 私钥**永不导出**——外部程序请求的是签名结果，不是密钥本身
  （默认不得导出私钥，见 [SSH Agent Features](https://github.com/cuihairu/persona/blob/main/docs/SSH_AGENT_FEATURES.md)）。

## 规划

- 材料的**可配置策略**（哪些动作需要确认/禁止）→ [策略](./policy) 的规则层；
- 材料级分享与组密钥（同步组）已落地的部分见 E2EE 同步设计。
