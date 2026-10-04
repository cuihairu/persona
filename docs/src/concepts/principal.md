# 主体（Principal）——预留方向

**一句话**：主体是动作的发起者抽象——人、AI Agent 或设备，都只是主语的
一种。这是一个**预留方向**：Persona 的模型不会把世界写死在「人 ↔ 凭据」，
而是「主体 → 分身 → 材料 → 动作」，这样 Agent 和 CI 天然可以进入模型。

```text
Principal
 ├── Human    （cuihairu）
 ├── Agent    （codex / claude / CI runner —— 预留）
 └── Device   （desktop / laptop / server / phone —— 预留）
```

## 为什么值得预留

你最近在用的 AI 编程工具（Claude Code、Codex、CI、多 Agent、多机器）都在
消费 SSH、API key、npm token 之类的材料。它们真正需要的不是「拿到凭据」，
而是「获得经过策略检查的受控动作」——例如：

```text
Agent: codex
Context: github.com/cuihairu/persona
Allowed:  git fetch / git commit / git push（受控签名）
Denied:   AWS production、personal GitHub、wallet signing
```

把「请求方是谁」在模型/审计里显式建模后，上面这条会变成一条**策略规则**，
而不是一段需要人工盯防的脚本。现在 Persona 的很多机制已在为这件事铺路：
配对 + session 绑定到扩展实例、审计记录请求来源、非交互模式的显式环境变量
开关、动作级闸门——差的只是把「发起者」抽象成模型里的第一公民。

## 现状（诚实边界）

- **未实现**独立的主体模型：2026-10 的代码里没有 `principals` 表、
  没有按主体区分的授权规则；
- 已有雏形：CLI 非交互模式（CI 场景）、桥配对/session 认证、
  审计的请求来源字段、SSH Agent 的 key/host 策略维度；
- API 语义上没有把「用户」写死成唯一主语——`cmds`/service 都以
  identity + action 为核心，不依赖「Vault 属于哪个账号」。

## 规划方向（不承诺时间线）

1. 审计里先给动作补上 topic（human/agent/device + 进程标识）；
2. 桥协议/CLI 增加可选的 `principal_id` 字段（向后兼容必填变可选）；
3. 规则层面允许按 principal 裁剪 [动作](./action) 白名单——Agent 只能
   拿到被白名单的动作，永远拿不到材料本身。

在 (1)(2)(3) 落地前，以上所有描述都是**方向**，不是功能承诺。