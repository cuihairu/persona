# Persona 深度架构审查（外部分析落档）

> 来源: ChatGPT 分享链接 https://chatgpt.com/s/t_6adcc933ec608191a1ed6a155250ed40
> 提取日期: 2026-10-24。**本文件是外部建议,不是本仓事实的陈述**——每一条都必须对照源码核实后才可执行。
> 已核实的条目在下表标注证据;未核实的标注「待核」。

## 核验结论(落地前必读)

| # | 审查论断 | 核验结果 | 证据 |
|---|---|---|---|
| 1 | switchIdentity 前后端状态分叉(先更UI、吞异常、无条件成功toast) | **属实,已定位** | desktop/src/hooks/usePersonaService.ts:322-334 |
| 2 | 应体系化 Principal/Action 层 | **部分已存在,非从零补** | core/src/service.rs、core/src/connect/token.rs、core/src/storage/connect_repository.rs 已有 principal;storage/auto_lock_policy_repository.rs 有 policy |
| 3 | 跨进程缺统一本地会话/授权中心 | 待核(方向性判断,与架构现状相符) | — |
| 4 | 「局域网直传」名不副实,实为 persona-server 换 base_url | 待核 | — |
| 5 | 同步冲突:保留「冲突保留+人工裁决」,不追零冲突 | 设计取向建议,无需核 | — |
| 6 | 第一阶段未达"放心承担全部凭据"标准;第二阶段统一Runtime/Agent授权未完成 | 定性评估,与 todo 现状不矛盾 | — |

## 一、整体判断

产品方向合理(Rust Core + 多客户端)。最大问题不是功能数量,而是身份上下文、凭据权限、安全策略与跨进程运行时没有形成统一闭环:多个进程各持核心服务实例、靠同一个持久化工作区协调,却没有统一的本地会话与授权中心;SQLite 只解决事务并发,不提供跨进程解锁状态、活动身份通知、权限撤销与用户确认流程。

## 二、已核实的缺陷:身份切换前后端状态分叉

`switchIdentity`(usePersonaService.ts:322)三连:
1. `setCurrentIdentity(identity)` 先更 UI(乐观更新);
2. `await personaAPI.setActiveIdentity()` 失败进 `catch { // ignore }`,异常被吞;
3. 无论成败弹 `toast.success('已切换到 B')`。

后果:后端切换失败时界面显示身份 B、Workspace 停留 A、CLI/浏览器可能仍按 A 工作,用户被成功提示误导。对身份管理系统,这是身份上下文可信性问题。

**修法(审查建议)**:以服务端成功提交为准再更新 UI;失败保留原身份并显示错误。

## 三、架构建议(待核后执行)

- 保留现有 Identity 模型,不重做 CRUD;把已有的 principal/policy 连成正式的 Principal + Action 体系。AI Agent 不发完整 API Key,授予有限操作权限。
- Policy 已有统一裁决函数,但还不是完整策略体系(审查称已检查 core/src,具体函数待核)。
- 跨进程:建立统一的本地会话与授权中心(解锁状态、活动身份通知、权限撤销、用户确认)。
- 同步:「局域网直传」命名需与实现核对后纠偏;保留凭据级冲突保留+人工裁决,不引入盲目覆盖。
- 成功标准:不是"做完 1Password 全部功能",而是身份切换、上下文选择、统一授权、跨客户端一致性。验收不只看测试绿,要建端到端场景与跨平台能力矩阵(编译成功/模拟测试/真实交互/长期运行分层)。

## 落地跟踪

- [x] R-P1 switchIdentity 改为服务端成功后才更新 UI,失败保留原身份并报错 — commit 5883ec2
- [x] R-P2 同类乐观更新模式全仓排查(desktop/src/hooks/ 下同款"先 setState 后 await"模式) — commit 5fec32d,排查清单见下表
- [ ] R-P3 Principal/Action 体系化设计文档(基于已有 principal/policy 代码,不重做 CRUD)
- [ ] R-P4 跨进程统一会话/授权中心方案(先调研现状再定方案)
- [ ] R-P5 同步「局域网直传」命名与实现核对,名实不符则纠偏
- [ ] R-P6 端到端验收场景清单 + 跨平台能力矩阵(区分编译/模拟/真实交互/长期运行)

## R-P2 排查清单(同款"先 setState 后 await 且吞异常",2026-10-24)

判定口径:先落 setState(store 或本地 state)→ await 服务端调用 → 失败被吞(空 catch / catch 只留注释 /
不查 `response.success`),且此前落下的状态既未回滚也未向用户交代。局部 UI 草稿态(开关、输入框)或
`finally` 里回滚的不计。

### 已修(同款)

| 位置 | 落下状态 → await 的调用 | 原吞法 | 修法 |
|---|---|---|---|
| hooks/usePersonaService.ts:327 `switchIdentity` | `setCurrentIdentity` → `setActiveIdentity` | catch 只留 `// ignore`,不查 `.success`,且无条件 `toast.success` | R-P1:先 await 并查 `.success`,成功才落身份/拉凭据/弹成功;失败保留原身份 + `setError` + `toast.error`;`silent` 只抑制成功提示不抑制失败 |
| hooks/usePersonaService.ts:233 `createIdentity` | `setCurrentIdentity(response.data)` → `setActiveIdentity` | catch 只留 `// ignore`,随后照弹 `toast.success('身份创建成功')` | 创建已成功不撤销,但激活失败改为 `toast.error('身份已创建，但设为当前身份失败')`——不再让用户以为已全局切换 |
| hooks/useQuickAccessBridge.ts:42 `apply` | `setPendingCredentialSelection` + `setCurrentIdentity` → `setActiveIdentity` | catch 只留注释,不查 `.success` | 跳转不阻断,但失败改为 `setError` + `toast.error`(同 `svc.switchFailed` 口径),不再静默 |
| hooks/usePasskeyApprovals.ts:76 `respond` | `setQueue(filter)` 移出审批项 → `passkeyApprovalRespond` | catch 只留注释,不查 `.success` | 改为以服务端确认为准才移出队列;失败留在队列可重试 + `toast.error`。否则 Allow 静默丢失,浏览器请求挂到后端 120s 超时 |
| hooks/useSshApprovals.ts:72 `respond` | 同上(`sshApprovalRespond`) | 同上 | 同上,agent 连接同样挂 120s |

### 已排查、判定无需修

| 位置 | 结论 |
|---|---|
| hooks/usePersonaService.ts:199 `loadIdentities` 的 `setActiveIdentity` catch | 有回滚(`setCurrentIdentity(response.data[0])`)且回滚目标就是当前已落下的值(`selected` 在无 match 分支恒等于 `data[0]`);不宣称成功、下次 `loadIdentities` 自愈,故不加 error 提示(启动期闪错误条无动作价值) |
| `switchIdentity` / `toggleCredentialFavorite` / `fetchFavicon` / `deleteCredential` / ssh agent 四动作 | 先 await 再查 `.success` 才落状态,失败走 `setError`/`toast.error`——本仓正确范本 |
| `createIdentity`/`deleteIdentity` 里"删除已确认后才清 session"、`lockService` 的一串清空 | 清空属复位而非乐观提交(await 在前、只在 `response.success` 分支内落) |
| hooks/useReauth.ts `setIsVerifying(true)` → `reauthVerify` | 查 `.success`,catch `setError`,`finally` 复位 loading flag——局部加载态,属排除项 |
| hooks/useFavicons.ts `setFaviconEntries` / `setFaviconMisses` | await 在前,setter 在 `resp.success` 分支内;catch 只留注释但前面无状态可回滚(纯预取,注释说明故意不记 miss 以便重试) |
| hooks/useDataLossRisk.ts `setState` | await 在前,catch 落的是安全侧默认值(`{loading:false, level:'none'}`),非未回滚的乐观提交 |
| hooks/useTheme.ts `setTheme` 的空 `.catch` | 无 await、无前置 setter(只读 theme、改 DOM class) |
| hooks/useAutoLockEvents.ts 一串清空 | 事件驱动(后端已锁),`touch_activity` 是 fire-and-forget,`lastTouchRef` 是 ref 不是 state |
| useEscapeToClose / useGlobalShortcut / components/ErrorHandling.tsx 的 error handler | 全同步,无 await |

范围:desktop 全仓 `hooks/`(11 个文件)+ `components/ErrorHandling.tsx` 的导出 hook 已逐个读完;
mobile / browser / cli / server / website 下无 `hooks/` 目录,browser 扩展是纯 TS 无 React hook,无同类面。
