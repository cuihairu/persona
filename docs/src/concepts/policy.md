# 策略（Policy）

**一句话**：策略决定「谁、在什么[上下文](./context)里、对哪个
[材料](./material)的哪个[动作](./action)」被放行、被确认、还是被拒绝。

**Policy 不是安全的实现细节，而是与 Identity/Material 平级的一级模型。**
Persona 的全部敏感路径都从属于同一个裁决语义:

```text
Action（请求动作）
   │
   ▼
Policy Engine（core 内）
   │
 ├─ allow        → 执行并审计
 ├─ confirm      → 桌面/CLI 确认后执行
 └─ deny         → 拒绝并审计
```

## 已落地的策略（硬门槛 + 可配置）

| 域        | 规则                                                                                        | 配置方式                       |
| --------- | ------------------------------------------------------------------------------------------- | ------------------------------ |
| 浏览器    | fill/copy/TOTP 必须 user gesture                                                            | 自动 fill 开关（按站点默认值） |
| 浏览器    | TLD+1 **origin binding**（`validate_origin_binding`，match ≥ 60）                           | 不可关闭——硬门槛               |
| 浏览器    | 阻塞/可疑域拒绝填充与保存（钓鱼防护）                                                       | 域策略表可维护                 |
| 写路径    | `save_credential` 需 user gesture + 桌面审批闸门（auto/require/off）+ origin binding + 审计 | 桌面设置里的审批模式           |
| SSH Agent | known_hosts、deny-all、速率限制、每密钥/每主机规则、确认/生物识别优先级                     | `persona ssh policy` 可配      |
| 解锁层    | 自动锁、敏感操作再认证                                                                      | 客户端可配                     |
| 自动化    | 非交互模式需显式环境变量启用（CI 场景）                                                     | `PERSONA_NON_INTERACTIVE` 等   |
| 全域      | 所有敏感动作进审计日志（脱敏）                                                              | 不开                           |

三条原则：

1. **策略在 core，不在客户端 UI**——CLI/桌面/扩展/Agent 都不能绕过
   core 直接读写敏感明文（[安全设计](/design/security) 的顶层约束）；
2. **硬门槛不能配置掉**——origin binding、user gesture、审计这类
   安全不变量没有开关；
3. **可配置的只是体验**——哪些自动、哪些要确认、哪些按站点记忆。

## 愿景：规则层（规划，未实现）

未来提供用户可配置的规则（YAML 愿景示例，非现状）：

```yaml
identity: work
rules:
  aws:
    access_key:
      allow: false # 工作分身的 AWS key 禁止从浏览器使用
  ssh:
    hosts: ["*.company.com"]
    require_confirmation: true
  browser:
    domains: [github.com, company.com]
```

该规则层落地后，上面那张「已落地」表里的可配置项会成为规则引擎的
**内建默认集**，规则引擎本身依然是 core 内、不绕过硬门槛的那一层。
实现节奏见[路线图](https://github.com/cuihairu/persona/blob/main/docs/ROADMAP.md)。
