# TODO

- [x] 缺陷：一键启用后，配置的按钮开关状态未联动（来源：用户 2026-10-14；修复 `9abce66` 前端回读 + `dc6021c` 落盘往返测试；前端 14 测试 + 后端 3 测试全绿）
- [x] 缺陷：右键菜单未国际化（来源：用户 2026-10-14；修复 `4b0ebac`；jest 80 测试 + cargo test --lib 265 测试全绿）
- [x] 文档首页预览图拆分：电脑版 / 手机版分开展示（来源：用户 2026-10-14；修复 `8f9ab29`）
- [x] 文档双语未落地（来源：用户 2026-10-14；README `012c466` + docs `7087914`；docs 30 个工程文档补 `*.zh.md` 共 7582 行）
- [x] R-P1 switchIdentity 改为服务端成功后才更新 UI（来源：2026-10-24 原型外部审查；修复 `5883ec2`）
- [x] R-P2 desktop/src/hooks/ 同款乐观更新模式排查（来源：2026-10-24 审查；修复 `5fec32d`；修 5 处 + 判定无需修 9 类；desktop 56 套件 736 例全绿）
- [x] R-P3 Principal/Action 体系化设计文档（来源：2026-10-24 审查；修复 `37ffc6d`；docs/src/design/principal-action.md + /zh/）
- [x] R-P4 跨进程统一会话/授权中心调研与方案（来源：2026-10-24 审查；修复 `4a0bb00`；docs/src/design/session-center.md + /zh/）
- [x] R-P5 同步「局域网直传」命名与实现核对（来源：2026-10-24 审查；修复 `b100345`；名实不符，已更名「局域网自建中转 / LAN self-hosted relay」6 处）
- [x] R-P6 端到端验收场景清单 + 跨平台能力矩阵（来源：2026-10-24 审查；修复 `25662c9`；docs/src/development/acceptance-matrix.md + /zh/）
- [x] DOC-GIF 配置开关效果动态图（来源：用户令；修复 `cd902aa`；SettingsModal 4 开关 off/on 对比图 + GIF 入 `docs/branding/ui/config-switches/`，流水线 `scripts/doc-config-switch-gif.mjs` 可重跑，兼 17 条断言回归测试全绿）

- [x] Connect API unix socket 传输：`persona connect serve --unix-socket [PATH]`（socket 文件 0600 + accept 层 SO_PEERCRED 属主 uid 校验 fail-closed，异 uid 连接进 HTTP 解析前丢弃；Host 白名单仅 TCP 强制——unix 无名字解析面；`--port` 同给硬报错；Windows 显式报错给 TCP 替代指引）。陈旧残骸接管口径收口 `persona_core::socket::is_stale_socket`（ssh-agent 改 re-export 同源）。来源：用户 2026-11-07；修复 `209b24e`；门禁：nextest 2096 全绿 + doctest 绿 + clippy -D warnings 绿 + fmt 绿 + `x86_64-pc-windows-gnu --all-targets` check 干净；openclaw（Windows Server 2022，stable 1.99.1 msvc）实机验收（2026-11-07）：`cargo test -p persona-connect-server` 38 过（含 `unix_transport_is_rejected_on_windows_with_tcp_fallback_hint`）、`-p persona-cli connect` 19 过、行为冒烟 `connect serve --unix-socket` 在**要主密码之前**即报平台错误给 TCP 指引（exit 1）；实机抓到并修复 1 个跨平台断言 bug（路径形态断言按 `/` 字符串后缀匹配，Windows 反斜杠必炸 → `Path::ends_with` 组件级比较，commit `fc392f9`）

- [x] Connect unix socket 传输的覆盖率收尾（PR #148）：serve 信号注入缝（serve_until）、Accept trait 泛型 + FlakyAccept 错误注入、peer_gate/socket_path_from 纯函数化与配套测试，补掉可覆盖缺口（patch 82.33%→**95.41%**（codecov.yml target 90%），project 由 97.13%/-0.05% 红翻 **97.20%/+0.06%** 绿（终态随 main `e46523d` 复核））；并确立 codecov.yml 政策：patch target 90%（跨平台 cfg 分支与防御性不可达行在单平台覆盖率下结构性够不到97%，真实缺口仍红），project 保持 auto 零容忍。来源：用户 2026-11-08 令（A+B+C）；代码修复 `aab309d`；门禁：connect-server 45 + cli connect 21 测试绿 + clippy -D warnings 绿 + fmt 绿 + windows-gnu --all-targets 干净

## 未完成

- [ ] mermaid 12 升级待手动评估：vitepress-plugin-mermaid@2.0.17 peer 仅支持 mermaid 10||11，#132（2026-11-06 dependabot PR 被直接合入）令 docs workflow `npm ci` ERESOLVE 红。已回退 docs mermaid→^11.17.2 并同步 package-lock（干净环境 npm ci + vitepress build 双绿验证）。重启条件：vitepress-plugin-mermaid 发布声明支持 mermaid 12 的版本（当前 latest 2.0.17 仍 10||11，2026-11-06 核）
- [ ] OS 自动填充集成：iOS AutoFill 供体、macOS 系统填充；Passkey 的 OS 平台认证器（macOS LocalAuthentication / Windows Hello）同属此缺口。解锁条件：需对应平台机器（iOS=macOS+Xcode、鸿蒙=DevEco），本机 Linux 无环境。2026-10-16 巡检复核：条件仍成立（本机 Linux，无 Xcode/DevEco）
- [x] 桌面应用级填充：Windows 桌面应用内的填充注入（现状仅浏览器桥）· 已实现并 openclaw 真机验收闭环（2026-11-05，commit `35918bb`+`745dca2`）。#22 口径保持：浏览器填充仍归浏览器扩展，本路径只服务**原生桌面应用**。设计与实现：`desktop/src-tauri/src/desktop_fill.rs`（选型见 `docs/src/design/desktop-fill.md` + `/zh/`，docs 侧边栏已登记）——① 首选 WM_SETTEXT 直写经典 Win32 EDIT 控件（EnumChildWindows 枚举，用户名=首个非密码框、密码=首个合格 ES_PASSWORD 框、无合格密码框整体拒绝注入——历史"第二框"启发式已于 2026-11-06 移除，改密对话框同样拒绝）；② 剪贴板中转 helper 已建但**未接线**——生产路径从不调用，不构成活动 fallback；系统剪贴板不提供保密（备份/恢复只缩短暴露窗口），启用前须在 UI 披露该边界；③ UIA 刻意不做（记录为后续扩展点，不留空壳桩）。目标捕获：热键唤起浮窗时 show 前拍前台窗口快照（hwnd+标题+pid，本进程窗口排除），注入时重验证（IsWindow+pid+标题前缀，防 HWND 复用，失效即丢弃并如实报错）。命令层 `fill_target_status`/`desktop_fill_credential`，浮窗 ⌘F 绑定 + i18n（en/zh-CN），非 Windows 平台如实报未实现。门禁（2026-11-05 当时自报、原始输出当时未归档——真机原始日志自 run1 起入仓，见下；第五轮门禁数字见第五轮报告）：desktop/src-tauri cargo test --workspace 绿（267 lib 含 2 个 Linux 侧 desktop_fill 纯函数测试）+ `x86_64-pc-windows-gnu` check 干净 + tsc 干净 + jest 56 套件 743 例全绿（含 3 个新 ⌘F 用例）。openclaw（Administrator@10.240.0.3，Windows Server 2022 x64，msvc + RUSTUP_TOOLCHAIN=stable）真机验收：发现并修复裸 cargo 测试二进制无内嵌 manifest → 加载器绑 comctl32 5.x 缺 `TaskDialogIndirect` 报 STATUS_ENTRYPOINT_NOT_FOUND（`windows/app.manifest` 声明 Common-Controls 6 + RUSTFLAGS /MANIFEST:EMBED 解决）；`cargo test --lib desktop_fill` 5 例全绿——含真窗+真 EDIT 控件的 WM_SETTEXT 注入/WM_GETTEXT 读回一致（`settext_injection_roundtrip_on_real_window`）、无密码样式启发式、全密码框拒绝、HWND 复用/死句柄/本进程窗口拒绝、剪贴板备份恢复闭环。边界诚实记录：自绘 UI（Electron/Qt/浏览器）不适用（浏览器归扩展），macOS/Linux 桌面填充为后续议题。2026-11-06 修订注记（安全评审加固收口，commit `5e81ef0`→`d601c14`）：① ES_PASSWORD 强制——密码必须落首个 ES_PASSWORD 样式框，目标窗口无密码样式框整体拒绝（历史"第二个框"启发式移除）；② 注入时指纹重验证——hwnd 存活 + pid 一致 + 类名 + 进程 exe 路径全匹配（同标题伪装进程拒绝、销毁重建在注入前完成时拒绝，CAPTURED_TARGET_INVALID；同进程同指纹的 HWND 值复用平台无法区分，如实记录为剩余限制，由确认面兜底）；③ 确认面——浮窗展示目标应用名与标题，`desktop_fill_credential` 无 `confirmed=true` 拒绝，不存在静默注入入口；确认经 `snapshot_id` 绑定到具体捕获（第三轮 P1 收紧）：异步解密在途期间目标被重新捕获（`FILL_TARGET_CHANGED`）或浮窗收起清槽（`FILL_TARGET_DISCARDED`）时在途请求如实拒绝，绝不转投新目标；④ 跨进程套件全绿（当时 4/4，run3 起 5/5；独立靶进程 `fill-test-host`，openclaw Server 2022 交互式会话）：关键判定——跨进程 WM_GETTEXT 读 ES_PASSWORD 返回空串（WM_SETTEXT 写入成功、普通框可跨进程读回）是 openclaw Server 2022 的**实测观察**（2026-11-06，不做跨版本通用断言，套件只记录观察值），非注入失败；注入成功断言改为不依赖跨进程密码读回：WM_SETTEXT 返回值 + ES_PASSWORD 样式/EM_GETPASSWORDCHAR 跨进程断言 + 靶进程内同进程读回逐字符一致。2026-11-06 第三轮修订（确认绑定快照 + 测试诚实性收口）：① P1 确认绑定——捕获时生成 `snapshot_id`，`fill_target_status` 随就绪态下发，前端确认时原样带回，后端在异步解密（在途窗口）完成后持锁按 id 绑定（`bind_confirmed_snapshot` 纯函数，平台无关 5 例测试覆盖「确认 A→重捕获 B 拒绝」「清槽后在途请求拒绝」「缺 id 拒绝」），失效清槽只清本请求确认的那份快照；② 跨进程套件补真竞态用例——`fill-test-host` 新增竞态钩子（子类化 username 框，第一条 WM_SETTEXT 写入完成即在消息处理内同步销毁重建），断言在途注入整体拒绝且密文不落重建窗口；旧「销毁重建」用例改注为注入前完成 + 同进程同指纹 HWND 值复用限制如实描述；跨进程读 ES_PASSWORD 恒空断言降级为实测观察注记（成功判据仍为靶进程同进程读回）；③ 剪贴板备选告警补齐——非文本内容被清空返回告警、粘贴失败/panic 分支的恢复告警落 tracing::warn 不再吞掉（补非文本种子测试）；④ 文档口径收口（gap 中英/#12、desktop-fill.md、本条）：「隐藏即丢弃」限定为浮窗 toggle/关闭路径清槽 + snapshot 绑定后在途确认如实拒绝，「无静默路径」限定为确认+绑定双门禁且 Win32 校验非原子竞态窗口仍在，「竞态拒绝」限定为注入前销毁重建与在途钩子两类已证场景，「Windows 恒隐藏」降级为 Server 2022 实测观察。。原始日志已归档入仓 `docs/review/evidence/openclaw-2026-11-06-desktop-fill/`（run1–run7，均为任务 PersonaFillTest /IT 真实输出）：run1（`d601c14`，此前 README 声称的两份 .log 补归档于 run1-d601c14/）+ run3（`a283573`：lib 12/12 + xproc 5/5） + run4 红（`7e52d7b`）+ run5（`4644114`，两个剪贴板用例红）+ run6 绿（`a9d2eed`：lib 17/17 + frame 6/6 + xproc 5/5） + run7 红（`ab42d44` 旧命令层：命令层套件 3 过 2 红、lib/frame/xproc 全绿）。2026-11-06 第五轮修订（命令层取消时序收口）：① 新增**真实命令层**取消时序套件 `fill-test/tests/desktop_fill_command_cancel.rs`（5 例：确认门、缺 snapshot_id、在途清槽拒绝 + 两个 mid-fill 时序用例），端到端驱动 `desktop_fill_credential`（mock runtime + 真服务解密 + 真实跨进程靶窗），取消时点由靶进程暂停钩子确定性钉死（在宿主 `HOOK_PAUSED` 与其放行命令之间改槽位——第一字段写入后、密码写入前，不靠轮询）——补上第四轮只直测引擎层 `execute_fill`、命令层自建重查闭包从未被真命令路径执行的缺口；② READBACK 改长度前缀协议（空字段 `0:`，单字段残留不被吞成双空） + 宿主确定性暂停钩子；③ 红先行：旧命令层真机红跑 run7（`cmdcancel_exit=101`，两个 mid-fill 用例在 `assert!(!resp.success)` 处失败——旧层返回成功未中止，其后密码读回断言未执行，日志不直接证明密码落框），实现侧 `8642e9b`（逐字段重查）在 main，绿侧复验将随第五轮报告 `docs/review/2026-11-06-desktop-fill-fifth-pass.md` 在后续提交归档；④ 文档过满表述收紧：「绝不把任何字段转投新目标」改为「重查不改投写入」并显式保留重验证→写入非原子窗口，「就绪态反映验证后的真实状态」降为「最近一次验证时的槽位状态」，首段「第二框」启发式/剪贴板备选改为已移除/已建未接线口径（gap 中英 #12、desktop-fill.md 中英、本条）
- [ ] Web 端：1Password.com 形态的浏览器端（低优先，出现真实需求再评估）。2026-10-16 巡检复核：未出现真实需求信号
- [ ] M5 浏览器插件接账号（Safari 侧）：Swift 宿主端实现桥协议 v7（报文 → `persona bridge` 子进程封装）。解锁条件：需 macOS+Xcode 实机（挂起待实机批次，docs/BRIDGE_PROTOCOL.md §20 + browser/safari-extension/README.md）。2026-10-16 巡检复核：条件仍成立（本机无 macOS）
- [x] Windows 实机测试与优化：编译层（x86_64-pc-windows-gnu 全绿）与 CI 守卫（rust-windows + rust-windows-desktop job）已收口，缺实机行为验收。修复 `1281714`；openclaw 实机验收（Administrator@10.240.0.3，Windows Server 2022 x64，msvc 工具链 + RUSTUP_TOOLCHAIN=stable 1.99.1，rsproxy 镜像，2026-11-03）：① `cargo build --workspace` EXIT 0（4m56s，仅 1 条无害 dead_code 警告）——编译层实机收口；② `cargo test -p persona-core` EXIT 0（1196 例全绿：1169+2+6+3+6+2+1+7，含 webauthn/openssl 依赖路径；vendored openssl 需 perl+MSVC cl.exe——git 自带 MinGit 无 perl 且 github 对远端不可达，用 Strawberry Perl 5.42.3.1 portable（本地下行+scp）+ BuildTools 2022 vcvars64 环境解决）；③ `cargo test -p persona-cli` EXIT 0（含 bridge/credential/totp/ssh 集成套件）；④ `cargo test -p persona-ssh-agent` EXIT 0；⑤ CLI 运行验收（acceptance-ws 全流程）：init/add/credential add+list/password generate（random 20 + words 6）/totp setup+code 全 EXIT 0；⑥ SSH agent 命名管道 E2E：ssh generate → add-to-agent（agent 监听 `\\.\pipe\agent.socket`，PERSONA_NON_INTERACTIVE=1 走 env 密码）→ NamedPipeClientStream 连接 OK → ssh status（PID 17036，Agent keys: 1）→ stop-agent（EXIT 0，agent 进程与管道均消失）。M4 剩余子项与理由：named-pipe 审批流（需桌面 UI 审批弹窗，CLI 无对应路径）；biometric gating（本机 0 个 Biometric 设备，Windows Hello 物理不可行）；NSIS 安装器（远端无 NSIS 且 github 不可达，需下载安装 + tauri 前端构建链，不在本批验收范围）。2026-11-03 巡检复核：核心实机行为验收闭环，条件满足
- [ ] SCIM/SSO bridging（future）。2026-10-16 巡检复核：无触发信号，维持 future
- [ ] Watchtower 外联扩展：domain breach alerts / dark web monitoring / OSINT 标识符查询。押后（2026-09-22 决策）；重启条件 = 1Password 对齐完成 + THREAT_MODEL 变更门槛 + 明确 opt-in 形态。2026-10-16 巡检复核：条件仍成立（1Password 对齐虽收口但 THREAT_MODEL 无变更、opt-in 形态未定；FEATURE_GAP_ANALYSIS.md:90 口径未变）
- [ ] #21 团队与共享：家庭/团队共享库 + 共享条目权限，依赖账号体系。2026-10-01 用户裁定登记待办、暂不实现（docs/FEATURE_GAP_ANALYSIS.md #21）。2026-10-16 巡检复核：裁决未变，维持搁置（不重开）

## 代码深审 2026-11-01（P2/P3 待办；来源 docs/review/2026-11-01-code-review.md）

- [x] P2 · JS-1 · 安全 · 扩展 passkey 桥未绑定 origin：`handlePasskeyPageMessage` 校验 `payload.origin === location.origin`（content.ts:1685-1695,1740-1790），不符丢弃 · 修复 `0e569d1`；`isTrustedPasskeyOrigin`（passkeyOrigin.ts:12，`new URL(origin).origin === pageOrigin`，非字符串/畸形 URL 一律 false）覆盖 dialog/native 门与 assertion/list 路径两处；passkeyOrigin.test.ts 6 例回归全绿（同源 true / 攻击者 / undefined / null / 42 / 畸形字符串 false）
- [x] P2 · JS-2 · 安全 · NMH 配对 HMAC 密钥持久化：`pairingKeyB64`/`sessionId` 移入 `chrome.storage.session`（nativeBridge.ts:576,376；违反 cloudSync.ts:16 纪律） · 修复 `f9c42ac`；配对状态只写 `chrome.storage.session`（内存区，退出即清），并做一次性迁移：legacy `storage.local` 副本迁入 session 后 `storageLocalRemove` 擦除盘区残留；nativeBridge 测试套件全绿
- [x] P2 · JS-3 · 健壮性 · sync pull 成功路径 JSON 解析加 try/catch（cloudSync.ts:396，对齐 :389 错误体） · 修复 `64be325`；成功路径 `resp.json()` 包 try/catch，解析失败转 `oplog_pull_failed (HTTP <status>): malformed JSON response` 而非裸 SyntaxError 上抛（untrusted 输入，对齐 :389 错误体纪律）
- [x] P2 · JS-4 · 竞态 · QuickSearch/QuickAccessPanel 防抖竞态加请求序号守卫（QuickSearch.tsx:66-69、QuickAccessPanel.tsx:176-179） · 修复 `3dadc71`；cleanup stale 守卫（clearTimeout 不能取消在途 await，慢响应不得覆盖新查询结果；`let stale=false` + cleanup 置 true）覆盖 QuickSearch 与 QuickAccessPanel 两处 + 回归测试（迟到的旧响应不覆盖新结果）；desktop 738 测试全绿
- [x] P2 · JS-5 · 竞态 · 身份切换凭据串号：`loadCredentialsForIdentity` 加序号守卫/AbortController（usePersonaService.ts:340-341,359） · 修复 `b1ff8e6`；`switchSeq` + `credentialLoadSeq` 双序号守卫（switchIdentity 慢完成不覆盖 currentIdentity、慢凭据响应不覆盖新身份）；usePersonaService.test.tsx 36 例全绿（含 2 例新增竞态回归），desktop `npx tsc --noEmit` 干净
- [x] P2 · 安全 · blob 附件 `storage_path` 路径穿越防御：retrieve_file/delete_file 加 travel.rs 同款逃逸检查（blob.rs:199,214,251,265；当前写入方安全，防御纵深） · 修复 `6a64c0e`；新增 `resolve_within_root`（拒绝对路径/`..`/`.` 组件，口径同 travel.rs:538）覆盖 retrieve/delete × 单文件/分块 4 处；blob 15 测试全绿（含新增 `test_storage_path_traversal_rejected` 根外诱饵文件不受读写），clippy -p persona-core 干净
- [x] P2 · 可用性 · CLI 读 agent socket 无界长度分配：ssh.rs:785/824 加长度上限（与 BUG-1 同法） · 修复 `e37c372`；`MAX_AGENT_RESP_LEN`（16MiB）查前分配，覆盖 unix/windows 双路径 query_agent_identities；新增 `query_agent_identities_rejects_oversized_length`（u32::MAX 长度前缀分配前拒绝），cli 3 例全绿，clippy -p persona-cli 干净
- [x] P2 · 竞态 · agent socket bind TOCTOU + 无条件删除：transport.rs:82-90 改 bind 失败不先删/验证陈旧（passkey_bridge.rs:177 同） · 修复 `ca27e8f`；unix bind 改"先 bind 失败才查陈旧"：活 socket 报错拒绝劫持、仅陈旧残骸（非 socket/连不上）删后重试；新增 `is_stale_socket` 并复用于 passkey_bridge.rs 审批 socket；transport 6 测试全绿（新增 live 拒绝 + 陈旧接管 2 例），clippy -p persona-ssh-agent 干净，desktop/src-tauri cargo check 通过
- [x] P3 · 健壮性 · PERSENC1 头部长度溢出：file_crypto.rs:113-116 改 checked_add/界检查 · 修复 `3ebf39b`；decrypt_bytes 的 enc_len 切片改 `cursor.checked_add(enc_len)`（u64 长度前缀不受信，溢出即 Bad ciphertext len 而非 panic）；file_crypto 5 测试全绿（新增 enc_len=u64::MAX 用例）
- [x] P3 · 健壮性 · Web3 keystore scrypt 参数溢出：wallet_encryption.rs:306 改 checked_mul + 先校验参数 · 修复 `ae9159b`；import/export 两侧 128*r*n 改 checked_mul（u32::MAX×u32::MAX 溢出即 work factor too high 而非 panic/回绕）；wallet_encryption 29 测试全绿（新增 `keystore_rejects_overflowing_scrypt_work_factor`）
- [x] P3 · 健壮性 · stop_agent 陈旧 pidfile 误杀：ssh.rs:1508-1512 kill 前验证 /proc/<pid>/cmdline · 修复 `72a9839`；`stop_agent_pid` 改三态（Stopped/AlreadyGone/Refused）：kill 前读 /proc/<pid>/cmdline 确认是 persona-ssh-agent，PID 复用即拒绝不误杀，进程已不在则当陈旧 pidfile 清理；cli stop_agent 3 测试全绿（含验证分判 stale/reused），clippy -p persona-cli 干净。跟进加固 `85f60fa`（2026-11-03）：unix 杀进程从 fork 外部 `kill` 改为直接 `libc::kill` 发 SIGTERM——全量门禁跑 cli 套件时（2169s、swap 挤满）fork 失败被误判为 Refused 留下 pidfile，`stop_agent_handles_missing_empty_and_live_pid_files` 假红一次；另非数字 pidfile 按陈旧清理（原按 Refused 拒绝）；persona-cli 全套 517 过 0 失败，clippy --workspace --all-targets --all-features -D warnings 干净
- [x] P3 · 卫生 · server-18996.log 运行时日志被 git 跟踪：git rm --cached + .gitignore 加 `*.log` · 修复 `317f0d5`；`git rm --cached server-18996.log`（文件留盘），.gitignore 加 `*.log`（`git check-ignore` 验证已忽略）
- [x] P3 · 卫生 · website `lint` 死脚本：删脚本或装 eslint 依赖+配置（website/package.json；CI 不跑） · 修复 `cc1ea45`；删死 `lint` 脚本（无 eslint 依赖/配置，CI 从不跑，运行即 command not found）；website/package.json JSON 校验通过

## 漏洞扫描遗留（2026-11-03 全舰队扫描，源 scratch/vuln-scan-*.md）

- [ ] VULN-PERSONA-001 [中危·RUSTSEC-2026-0387] crypto-bigint 0.5.5→0.7.6+【部分收口，余项上游阻塞】：① 0.7 链已收口——desktop/src-tauri 与 fuzz 两工作区 lock 的 crypto-bigint 0.7.5→0.7.10（≥patched 0.7.6，dependabot bump 落地）；验证：desktop/src-tauri `cargo build --workspace` EXIT 0 + `cargo test --workspace` 全绿（267 lib + 10 集成，2026-11-05 本机 Linux）、fuzz `cargo fuzz build` 全量编译 EXIT 0（nightly ASAN，11m）+ 4 目标 `-runs=1000` 冒烟自报全 DONE 无 crash（**修订注记 2026-11-06**：以上测试数字为执行席位自报，原始退出码/日志未归档，无独立核验——见 codex 2026-11-05 审查第 3 条；后续重跑须留存原始输出）；② 0.5.5 残留**锁图未见本仓库内可清零的路径（如实口径，2026-11-06 复核降级）**：锁图中存在 alloy-consensus → k256 0.13 → ecdsa 0.16 → elliptic-curve 0.13 → crypto-bigint 0.5.5 的链，另有 alloy-primitives → k256 0.13 的锁图边（alloy-primitives 为 core 直接依赖）——锁图边 ≠ 实际启用：desktop 工作区 `cargo tree --offline --locked --target all -i crypto-bigint@0.5.5` 输出为空（nothing to print），默认构建是否实际启用该链**两个方向都未验证**；k256 0.14（→elliptic-curve 0.14→crypto-bigint 0.7）上游 2026-07 已发布，但 alloy 至今无采用它的 release；上游版本/feature/换库哪条路能清零均未取得可复现证据——维持「等 alloy 换 k256 0.14 或钱包签名路径换库（用户裁定押后类变更）」的处理，不声称唯一路径；`.cargo/audit.toml` 的 ignore 注释已按锁图口径再修订（2026-11-06：撤除「reachable ONLY via」「无其他路径」绝对表述，补 alloy-primitives 锁图边与 cargo tree 证据缺口；原注释曾错误归因 rsa），根工作区 `cargo audit` 无未处置漏洞项；desktop/src-tauri 与 fuzz 工作区各自 `cargo audit` 仍如实命中该 ID（两工作区无本地 ignore 配置，与 VULN-PERSONA-002 同口径不粉饰）
- [ ] VULN-PERSONA-002 [BLOCKED·上游无修复·中危 5.9·RUSTSEC-2023-0071] rsa 0.9.10（desktop）与 0.10.0-rc.18（fuzz/desktop）：patched 为空，等上游发布或换库；不勾，验收：上游出 patched 或换库后 cargo audit 该 ID 清零

## 源码分层分析 2026-11-07

### 抽象层清单

安全核心层——派生/包裹主密钥与逐项密钥，执行凭据、钱包、passkey、SSH/TOTP 的本地加密签名（代表模块 `core/src/service.rs:116`）。
授权与会话层——统一主体/资源/动作裁决，维护本地会话、自动锁、敏感重认证与 Connect/Agent 能力边界（代表模块 `core/src/authz.rs:141`）。
持久化层——以 SQLite 保存 vault、审计、同步、连接令牌、favicon，以 OS keyring 保护设备/账号/生物识别凭据（代表模块 `core/src/storage/database.rs:8`）。
同步与中继层——生成/消费 E2EE oplog 与快照，经 persona-server 密文中继完成推送、拉取、冲突与密钥轮换（代表模块 `core/src/sync/runtime.rs:29`）。
服务通信层——宿主经 Tauri IPC、Native Messaging、本机 HTTP、远端 HTTP/中继把用户请求转接并加固（代表模块 `server/src/lib.rs:34`）。
应用宿主与界面层——CLI/桌面/浏览器/移动端承担路由、状态、审批与平台填充入口（代表模块 `desktop/src/App.tsx:1`）。
系统代理层——SSH agent 监听 socket/命名管道、读取库内密钥并按策略签名或审批（代表模块 `agents/ssh-agent/src/lib.rs:125`）。
平台适配层——封装 OS 生物识别、keyring、窗口、移动 JNI/C-ABI/NAPI 差异（代表模块 `desktop/src-tauri/src/types.rs:15`）。
可观测层——落库脱敏审计并通过内存队列/事件上报告远端（代表模块 `core/src/events/emitter.rs:47`）。
构建发布层——工作区、pnpm/CI/docker 打包仓库产物与站点（代表模块 `Cargo.toml:1`）。
体验内容层——维护官网、文档站与品牌资产（代表模块 `website/src/pages/download.tsx:36`）。

### 超大文件候选（>1000 行）

- [ ] LAY-001 [P1] 拆分 `desktop/src-tauri/src/command_layer_tests.rs`（11855 行）——mock runtime 加固与按命令族的集成测试可独立拆分（`desktop/src-tauri/src/command_layer_tests.rs:13`）
- [ ] LAY-002 [P1] 拆分 `cli/src/commands/bridge.rs`（9375 行）——协议帧、配对、凭据、passkey、账号与同步处理器混在一个命令文件（`cli/src/commands/bridge.rs:459`）
- [ ] LAY-003 [P1] 拆分 `core/src/service.rs`（9347 行）——认证、凭据、passkey、附件、connect、旅行与历史职责都汇入单一服务（`core/src/service.rs:67`）
- [ ] LAY-004 [P1] 拆分 `desktop/src-tauri/src/commands.rs`（9232 行）——Tauri 命令面同时编排生命周期、同步、账号、SSH、passkey、钱包与附件（`desktop/src-tauri/src/commands.rs:218`）
- [ ] LAY-005 [P1] 拆分 `cli/src/commands/wallet.rs`（4440 行）——CLI 参数、钱包/地址流程、交易、导入导出和展示聚合（`cli/src/commands/wallet.rs:432`）
- [ ] LAY-006 [P1] 拆分 `cli/src/commands/ssh.rs`（4203 行）——SSH 命令、agent 启停、导入授权和集成检查混杂（`cli/src/commands/ssh.rs:180`）
- [ ] LAY-007 [P1] 拆分 `server/src/api/sync.rs`（3223 行）——设备登记、信封、oplog、快照与限流逻辑集中在一个处理器（`server/src/api/sync.rs:201`）
- [ ] LAY-008 [P1] 拆分 `cli/src/commands/totp.rs`（2795 行）——TOTP 参数解析、导入/截图流程与输出耦合（`cli/src/commands/totp.rs:166`）
- [ ] LAY-009 [P1] 拆分 `cli/src/commands/credential.rs`（2645 行）——凭据 CRUD、附件、历史、自定义字段和展示聚合（`cli/src/commands/credential.rs:291`）
- [ ] LAY-010 [P1] 拆分 `agents/ssh-agent/src/lib.rs`（2511 行）——协议处理、密钥装载、策略/审批审计与算法签名共存（`agents/ssh-agent/src/lib.rs:123`）
- [ ] LAY-011 [P1] 拆分 `server/src/api/accounts.rs`（2457 行）——账号、passkey、SRP、恢复码、设备与会话端点聚合（`server/src/api/accounts.rs:270`）
- [ ] LAY-012 [P1] 拆分 `core/src/crypto/transaction_signing.rs`（2385 行）——多链交易构建、签名、验证与编码共用一个模块（`core/src/crypto/transaction_signing.rs:44`）
- [ ] LAY-013 [P1] 拆分 `browser/chromium-extension/src/content.ts`（2294 行）——表单识别、填充、快捷 UI、保存栏与 passkey 页面协议混在 content script（`browser/chromium-extension/src/content.ts:88`）
- [ ] LAY-014 [P1] 拆分 `connect-server/src/lib.rs`（2071 行）——路由、防线、数据端点与大量内嵌测试未分离（`connect-server/src/lib.rs:90`）
- [ ] LAY-015 [P1] 拆分 `core/src/crypto/passkey.rs`（1968 行）——WebAuthn options、注册、断言、COSE 序列化与验证聚合（`core/src/crypto/passkey.rs:62`）
- [ ] LAY-016 [P1] 拆分 `desktop/src-tauri/src/desktop_fill.rs`（1905 行）——平台注入、字段分类、目标快照与跨进程契约合用一个文件（`desktop/src-tauri/src/desktop_fill.rs:123`）
- [ ] LAY-017 [P1] 拆分 `core/src/storage/repository.rs`（1863 行）——identity、credential、workspace、audit 及查询/统计仓储合并（`core/src/storage/repository.rs:24`）
- [ ] LAY-018 [P1] 拆分 `core/src/crypto/wallet_import_export.rs`（1737 行）——WIF/Keystore/JSON 导入导出格式与校验集中（`core/src/crypto/wallet_import_export.rs:57`）
- [ ] LAY-019 [P1] 拆分 `desktop/src/components/SettingsModal.tsx`（1709 行）——功能开关、同步、备份、生物识别、快捷键等设置面板聚合（`desktop/src/components/SettingsModal.tsx:1709`）
- [ ] LAY-020 [P1] 拆分 `desktop/src-tauri/src/types.rs`（1696 行）——AppState 与横跨命令、同步、账号、审批的 wire 类型混杂（`desktop/src-tauri/src/types.rs:15`）
- [ ] LAY-021 [P1] 拆分 `core/src/sync/runtime.rs`（1665 行）——会话装配、backfill、捕获、密钥轮换、冲突处理共用（`core/src/sync/runtime.rs:29`）
- [ ] LAY-022 [P1] 拆分 `core/src/storage/wallet_repository.rs`（1616 行）——钱包、地址、交易、统计仓储集中（`core/src/storage/wallet_repository.rs:20`）
- [ ] LAY-023 [P1] 拆分 `core/src/travel.rs`（1614 行）——sidecar 加密封装、入退模式、文件保护与跨库重建聚合（`core/src/travel.rs:73`）
- [ ] LAY-024 [P1] 拆分 `cli/src/commands/export.rs`（1610 行）——多格式导出计划、确认、文件加密与展示耦合（`cli/src/commands/export.rs:646`）
- [ ] LAY-025 [P1] 拆分 `core/src/auth/auto_lock.rs`（1579 行）——策略持久化、运行时、事件、审计和面板流转集中（`core/src/auth/auto_lock.rs:1`）
- [ ] LAY-026 [P1] 拆分 `core/src/import_1pux.rs`（1495 行）——1Password 解包、模型转换与导入校验合并（`core/src/import_1pux.rs:1`）
- [ ] LAY-027 [P1] 拆分 `cli/src/commands/import.rs`（1495 行）——交互流程、格式识别、进度与结果输出耦合（`cli/src/commands/import.rs:694`）
- [ ] LAY-028 [P1] 拆分 `cli/src/commands/edit.rs`（1469 行）——编辑解析、确认、核心调用与展示混杂（`cli/src/commands/edit.rs:662`）
- [ ] LAY-029 [P1] 拆分 `core/src/models/credential.rs`（1434 行）——枚举解析、主实体、多种凭据 payload 与校验同文件（`core/src/models/credential.rs:121`）
- [ ] LAY-030 [P1] 拆分 `desktop/src/components/CreateCredentialModal.tsx`（1423 行）——动态表单、TOTP/SSH/钱包字段、提交与 UI 状态聚合（`desktop/src/components/CreateCredentialModal.tsx:1423`）
- [ ] LAY-031 [P1] 拆分 `core/src/models/wallet.rs`（1389 行）——钱包实体、链枚举、地址、交易与安全设置集中（`core/src/models/wallet.rs:8`）
- [ ] LAY-032 [P1] 拆分 `cli/src/commands/auto_lock.rs`（1379 行）——策略 CRUD、看板、清理与展示耦合（`cli/src/commands/auto_lock.rs:760`）
- [ ] LAY-033 [P1] 拆分 `desktop/src/i18n/locales/en.ts`（1326 行）——大型扁平语言包可按域拆分（`desktop/src/i18n/locales/en.ts:5`）
- [ ] LAY-034 [P1] 拆分 `core/src/sync/pairing.rs`（1323 行）——邀请、SRP/PAKE、组密钥递交与中继客户端合并（`core/src/sync/pairing.rs:1`）
- [ ] LAY-035 [P1] 拆分 `core/src/sync/remote.rs`（1312 行）——wire 类型、HTTP 客户端、管理接口和快照传输集中（`core/src/sync/remote.rs:1`）
- [ ] LAY-036 [P1] 拆分 `agents/ssh-agent/src/policy.rs`（1311 行）——策略模型、文件/环境加载、频率与 known-host 检查聚合（`agents/ssh-agent/src/policy.rs:169`）
- [ ] LAY-037 [P1] 拆分 `desktop/src/i18n/locales/zh-CN.ts`（1299 行）——大型扁平语言包可按域拆分（`desktop/src/i18n/locales/zh-CN.ts:5`）
- [ ] LAY-038 [P1] 拆分 `core/src/auth/security_strategies.rs`（1290 行）——敏感操作门、策略校验、缓存与拦截器集中（`core/src/auth/security_strategies.rs:1`）
- [ ] LAY-039 [P1] 拆分 `core/src/auth/auto_lock_dashboard.rs`（1213 行）——看板模型、查询、事件流与测试并入同一模块（`core/src/auth/auto_lock_dashboard.rs:1`）
- [ ] LAY-040 [P1] 拆分 `desktop/src/hooks/usePersonaService.test.tsx`（1206 行）——服务 hook 覆盖面可按功能域拆分（`desktop/src/hooks/usePersonaService.test.tsx:1`）
- [ ] LAY-041 [P1] 拆分 `desktop/src/components/CredentialDetailPane.tsx`（1205 行）——详情展示、秘密揭示、TOTP、附件与钱包动作聚合（`desktop/src/components/CredentialDetailPane.tsx:1205`）
- [ ] LAY-042 [P1] 拆分 `core/src/crypto/wallet_encryption.rs`（1204 行）——钱包密钥封装、Keystore V3、scrypt 参数与迁移聚合（`core/src/crypto/wallet_encryption.rs:13`）
- [ ] LAY-043 [P1] 拆分 `desktop/src/types/index.ts`（1200 行）——桌面 API、命令、同步、账号、SSH、钱包类型单文件（`desktop/src/types/index.ts:19`）
- [ ] LAY-044 [P1] 拆分 `cli/src/commands/secrets.rs`（1169 行）——引用解析、env 注入、K8s/Terraform 协议与展示耦合（`cli/src/commands/secrets.rs:660`）
- [ ] LAY-045 [P1] 拆分 `core/src/sync/materialize.rs`（1165 行）——credential/passkey/identity 物化、信封重包与删除处理集中（`core/src/sync/materialize.rs:1`）
- [ ] LAY-046 [P1] 拆分 `cli/src/commands/backup.rs`（1165 行）——导出/恢复、远端上传下载、保留清理和输出耦合（`cli/src/commands/backup.rs:252`）
- [ ] LAY-047 [P1] 拆分 `desktop/src/utils/api.ts`（1163 行）——`PersonaAPI` 聚合几乎全部 Tauri 命令适配（`desktop/src/utils/api.ts:1163`）
- [ ] LAY-048 [P1] 拆分 `core/src/storage/blob.rs`（1147 行）——加密 blob 读写、附件校验与 attachment manager 合并（`core/src/storage/blob.rs:17`）
- [ ] LAY-049 [P1] 拆分 `core/src/auth/auto_lock_cached.rs`（1130 行）——缓存策略、失效、查询缓存与事件联动集中（`core/src/auth/auto_lock_cached.rs:1`）
- [ ] LAY-050 [P1] 拆分 `core/src/accounts/remote.rs`（1128 行）——账号、passkey、SRP、恢复码与设备授权 HTTP 客户端聚合（`core/src/accounts/remote.rs:26`）
- [ ] LAY-051 [P1] 拆分 `cli/src/commands/switch.rs`（1128 行）——身份切换、上下文建议、审计与备份回滚聚合（`cli/src/commands/switch.rs:510`）
- [ ] LAY-052 [P1] 拆分 `desktop/src/components/WalletPanel.tsx`（1116 行）——钱包列表、地址、交易确认、导入导出 UI 聚合（`desktop/src/components/WalletPanel.tsx:1116`）
- [ ] LAY-053 [P1] 拆分 `desktop/src/components/CreateCredentialModal.test.tsx`（1100 行）——动态表单测试可按凭据类型拆分（`desktop/src/components/CreateCredentialModal.test.tsx:1`）
- [ ] LAY-054 [P1] 拆分 `core/src/import_generic.rs`（1078 行）——CSV/Bitwarden/Chrome/Firefox/KeePass 解析与映射集中（`core/src/import_generic.rs:52`）
- [ ] LAY-055 [P1] 拆分 `desktop/src-tauri/src/ssh_integration.rs`（1058 行）——agent 路径、SSH config 块、include 分析与探测聚合（`desktop/src-tauri/src/ssh_integration.rs:95`）
- [ ] LAY-056 [P1] 拆分 `cli/src/commands/tui.rs`（1044 行）——数据 provider、ratatui 状态、渲染与事件循环耦合（`cli/src/commands/tui.rs:95`）
- [ ] LAY-057 [P1] 拆分 `cli/src/commands/remove.rs`（1035 行）——删除确认、备份、级联和审计流程聚合（`cli/src/commands/remove.rs:31`）
- [ ] LAY-058 [P1] 拆分 `core/src/context.rs`（1019 行）——信号发现、git remote 解析、映射模型与建议评分集中（`core/src/context.rs:43`）

### 目录/分类不合理处

- 生成物混入源码：`browser/chromium-extension/dist/*.js` 及 source map 共 32 个构建产物被 Git 跟踪，而 `package.json` 同时提供 `clean`/`build`（`browser/chromium-extension/tsconfig.json:8`）。
- 构建包管理不一致：docs 使用 npm lockfile 且被 pnpm workspace 排除，根 `package.json` 却提供 npm prefix 脚本（`package.json:16`；`pnpm-workspace.yaml:1`）。
- 文档与审计记录混杂：`docs/review/evidence/**` 跟踪多轮运行日志、`.done` 标记与测试证据，归档审计更宜独立目录（`docs/review/evidence/openclaw-2026-11-06-desktop-fill/filltest-lib.log:1`）。
- 根目录历史报告与现行事实并存：`CORE_ANALYSIS_REPORT.md` 自标 2025-01-14 历史快照，`FINAL_SUMMARY.md` 标注 2026-09-27 交付，仍在根级承担当前说明职责（`CORE_ANALYSIS_REPORT.md:3`；`FINAL_SUMMARY.md:3`）。
- 大型集成测试占据生产模块目录：`desktop/src-tauri/src/command_layer_tests.rs` 属于测试但位于 `src`，且直接引用 crate 私有装配（`desktop/src-tauri/src/command_layer_tests.rs:1`）。
- 平台 stub 位置不齐：鸿蒙 napi 包装占位放在 UI 工程源码目录，而 Rust 侧 napi 导出尚未存在（`mobile/harmony/entry/src/main/ets/persona/PersonaBridge.ets:6`）。
- 产品站点内容与真实状态脱节：`download.tsx` 声明平台文件与尺寸但按钮没有 href，扩展页面仍写“开发中/下一版本”（`website/src/pages/download.tsx:36`；`website/src/pages/docs.tsx:28`）。
- Safari 扩展只有壳宿主：manifest 引用的 background/content JS 无源码，Swift handler 只回显消息，与 Chromium 源码成熟度不一致（`browser/safari-extension/Shared/manifest.json:1`；`browser/safari-extension/Sources/PersonaSafariExtensionExtension/SafariWebExtensionHandler.swift:6`）。
