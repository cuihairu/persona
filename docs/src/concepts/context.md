# 上下文（Context）

**一句话**：上下文是客户端**可观察到**的环境事实集合，用来回答「我现在在哪、
在做什么」，从而建议分身、参与策略判断。

关键约束：**Context 是观察事实，不是用户声明**。用户没有「手动切换网页身份」
这个动作——网址就是网址；本机目录就是目录。所以上下文的能力上限是**建议**
与**默认选择**，而不是伪造身份。

## 已落地的上下文维度

| 维度        | 事实来源                                    | 已消费方                                                              |
| ----------- | ------------------------------------------- | --------------------------------------------------------------------- |
| 页面来源    | 浏览器扩展的 page origin                    | 建议查询、**origin binding**（TLD+1 域名绑定，不匹配即拒绝填充/save） |
| 站点偏好    | 每站点 autofill 默认值                      | 密码/TOTP 默认条目、`savePromptDisabled`                              |
| 当前身份    | `workspaces.active_identity_id`（全局指针） | 所有入口的建议过滤、新凭据归属                                        |
| SSH 会话    | SSH Agent 的 key + host                     | 每密钥/每主机策略、known_hosts、确认门槛                              |
| 信任/威胁态 | 域策略表                                    | 可信域才允许激进自动填充；阻塞/可疑域拒绝一切填充与保存               |

注意「当前身份」本身也参与了上下文：CSS（上下文无关）的另一面是——身份是
**显式**组件，上下文是**隐式**组件，两者合并出最终建议。浏览器扩展的
`suggesting_for` 正是起源+当前身份的组合。

## 规划方向（路线图，未实现）

```text
Context:
    repository = github.com/cuihairu/persona
    directory  = ~/workspace/persona
    host       = dev-pc
    terminal   = zsh
    user       = cuihairu

        ↓（建议）

Identity: OpenSource
```

- 终端/CLI 场景：cwd 所在仓库、主机名 → 建议该用得上的分身；
- 浏览器场景：把「访问 github.com 时该用哪个分身」做成每站点记忆，
  而不是每次手动切换；
- CLI 里 `persona ssh --identity` 已标注 "reserved for future use"，
  正是为这类语义留的口子。

完整设计见
[CONTEXT_AWARE_DESIGN](https://github.com/cuihairu/persona/blob/main/docs/CONTEXT_AWARE_DESIGN.md)
（阶段 0：确定性打分、静态映射表 + 可选历史学习、CLI 先行）。
在此之前，机制只有一个硬规则：**上下文只会影响建议与默认值，永远不会绕过
策略放行一个动作**。
