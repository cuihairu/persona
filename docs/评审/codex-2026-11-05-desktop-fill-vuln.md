# dd4adeb 桌面填充与依赖升级独立复核

审计基线：dd4adeb 及其前 4 笔提交（bb9de0f..dd4adeb）；前端依赖提交 4e89fbe 紧邻其前，也一并核对。当前检出 f94b55c，较基线仅有 gap 文档格式化；代码和锁文件与 dd4adeb 相同。结论：**FAIL，需要返工**。凭据可能写入错误窗口或普通明文输入框；产品宣称的剪贴板备选也没有接入。未取得原始 Windows/fuzz 运行日志，不能把席位自报转换成独立验收。

## 逐项结论

1. **依赖升级：FAIL（部分成立）**。desktop 和 fuzz 的锁文件分别在 `desktop/src-tauri/Cargo.lock:1766`、`fuzz/Cargo.lock:1258` 锁定 crypto-bigint 0.7.10，满足所给 ≥0.7.6 阈值；但两处也分别在 `desktop/src-tauri/Cargo.lock:1754`、`fuzz/Cargo.lock:1246` 保留 0.5.5，不能称漏洞依赖已清零。锁图确有 alloy-consensus 2.5.0 → k256 0.13.4 → ecdsa 0.16.9 → elliptic-curve 0.13.8 → crypto-bigint 0.5.5（`desktop/src-tauri/Cargo.lock:79,95,3986,3992,2350,2357,2423,2429`）；k256 还直接依赖同一 elliptic-curve（`desktop/src-tauri/Cargo.lock:3993`）。但 alloy-primitives 1.7.3 也有指向旧 k256 的锁图边（`desktop/src-tauri/Cargo.lock:194,209`），且 core 直接依赖该库（`core/Cargo.toml:48`）；“ONLY via alloy-consensus”和“无其他路径”的绝对表述不成立。锁文件包括可选依赖，不等于默认构建实际启用：本机 `cargo tree --offline --locked --target all -i crypto-bigint@0.5.5` 在 desktop 工作区输出 nothing to print，因此不能仅凭锁图认定默认产物存在此链，也不能据此证明没有其他清零方案。是否所有上游版本均不能替换、是否可调整 feature/依赖以清零，未得到可核验的完整证据。

   跨版本调用静态抽查：Taproot `PrimeField::from_repr` 对非规范 scalar 拒绝（`core/src/crypto/address_generator.rs:134`）；P-256 生成/签名/验证（`core/src/crypto/passkey.rs:176,419,456`）、持久密钥恢复（`core/src/service.rs:1632`）、SEC1 导入及 SSH 密钥转换（`core/src/crypto/ssh_import_pem.rs:162,185,195`）、SSH 签名（`agents/ssh-agent/src/lib.rs:606,679`）未见明显 API 语义错误；这不是运行时互操作证明，也不能声称所有调用点均已动态验证。前端 override 和锁文件均指向 decode-uri-component 0.5.1（`package.json:79`、`pnpm-lock.yaml:61,3857`），安装与前端测试自报未独立重跑。

2. **注入安全：FAIL**。本进程 PID 和死句柄有显式拒绝（`desktop/src-tauri/src/desktop_fill.rs:190,229,235,275`），但不构成窗口身份或字段归属的完整保证；见下列 P1。快照在显示浮窗之前捕获（`desktop/src-tauri/src/quick_access.rs:477`），注入时重新检查（`desktop/src-tauri/src/desktop_fill.rs:98`），但两次之间、检查与实际写入之间都可发生变化。任何能成为前台的普通进程可制造登录外观和输入框，诱导用户选择凭据后获得密码；代码没有可执行文件、域名或凭据与目标的绑定，也没有注入前可信确认。需要用户执行选凭据/填充动作；没有证据证明前台进程可自行调用该动作或无需用户交互跨应用注入。

3. **测试诚实性：FAIL（证据不足）**。Windows 五例是 Windows 条件编译测试，代码中没有 `#[ignore]`（`desktop/src-tauri/src/desktop_fill.rs:569,581,603,616,632,678`）；真窗测试在测试进程创建控件并直接调用底层函数（`desktop/src-tauri/src/desktop_fill.rs:482,582,594`），没有验证跨进程、热键、命令、复用竞态或完整产品链。Linux 只编译两例纯函数/平台不支持测试（`desktop/src-tauri/src/desktop_fill.rs:737`），不是同一五例。此次尝试 `cargo test --offline --locked --lib desktop_fill`，从头编译耗时，未完成即中止，**没有独立绿结果**；席位 267+10 和 fuzz 四目标各 1000 次仅有自报（`todo.md:18,44`），无原始输出、退出码或种子/目标日志可供核验。四个 fuzz 入口存在（`fuzz/fuzz_targets/passkey_creation_options.rs:9`、`fuzz/fuzz_targets/context_map_toml.rs:9`、`fuzz/fuzz_targets/ssh_openssh_key.rs:8`、`fuzz/fuzz_targets/keystore_json.rs:10`），不证明确实运行。桌面 Windows Hello 测试有明确 ignore（`desktop/src-tauri/src/biometric/windows_tpm.rs:590`），属于硬件前置条件，不能笼统声称完全无跳过；未发现本批 desktop_fill 五例有为绿而 ignore 的证据。仓库内未找到所述 249/6 失败明细及原始堆栈，`cli/src/commands/backup.rs:333` 的另一处 Access denied 注释不能证明那六例原因；Windows error 5 表示拒绝访问，单凭错误码无法区分环境权限、文件占用或产品缺陷，归因环境 **未证实**。

4. **交叉口径：FAIL**。#12 表格称已完成 Windows 填充（`docs/FEATURE_GAP_ANALYSIS.md:26`），但同文仍称 #12 未完成、仅浏览器桥（`docs/FEATURE_GAP_ANALYSIS.md:49,65`）；#22 称浮窗只负责取件（`docs/FEATURE_GAP_ANALYSIS.md:71`），而 Ctrl+F 已直接调用注入（`desktop/src/components/QuickAccessPanel.tsx:260,333`）。浏览器仍走扩展的目标可以与桌面填充共存，但“浮窗只取件”必须修订；中文版亦需同步（`docs/FEATURE_GAP_ANALYSIS.zh.md:27,50,66,72`）。

## 缺陷清单

### P1

- **窗口与子控件身份可在校验后被替换**：`desktop/src-tauri/src/desktop_fill.rs:98,101,116,120,229,239,275`。同 PID 重建同标题或以前缀开头的窗口可通过；空标题时 `starts_with("")` 恒真。即使顶层检查通过，枚举后子 HWND 可销毁并复用，写入前仅 `IsWindow`，不核验 PID、根窗口、控件类及所属关系。用户名和密码两次同步消息之间也有窗口变化。测试只检查死句柄和不同标题，没有真正复用（`desktop/src-tauri/src/desktop_fill.rs:629`）。应设计可验证的目标身份、尽可能缩短竞态并对每个子控件在写入前核验；Win32 非原子检查仍需明确剩余风险和用户确认。
- **密码可能写入可见普通字段或攻击者控件**：`desktop/src-tauri/src/desktop_fill.rs:64,68,243,260`。没有密码样式时直接把第二个普通 Edit 当密码框，未校验可见性、启用状态、只读状态或语义；任意前台进程也可以布置两个 Edit，并以标题伪装目标。用户按填充后明文进入普通框或攻击者进程。即便带 ES_PASSWORD，目标进程本就能读取输入；应取消不安全猜测、限制目标并提供可信目标确认，不能将本进程排除误称为授权校验。

### P2

- **剪贴板备选不可用，且辅助函数不具备保密保证**：生产入口只走 `execute_fill` 的 SetText；无控件直接报错（`desktop/src-tauri/src/desktop_fill.rs:101`），`with_clipboard_paste` 和 `paste_into_focused` 无生产调用，却被文档称已实现 fallback（`docs/src/design/desktop-fill.md:23`）。函数的 `value` 是直接写入剪贴板的明文，不是密文（`desktop/src-tauri/src/desktop_fill.rs:324,360,391,400`）；其他应用可在闭包期间读取或记录，恢复失败可留下明文（`desktop/src-tauri/src/desktop_fill.rs:364,414`），闭包 panic 也绕过恢复。文本备份以固定 1M 长度创建 slice，未按 `GlobalSize` 验证分配边界（`desktop/src-tauri/src/desktop_fill.rs:344`），存在未定义行为风险。当前产品路径不调用它，不能说当前 SetText 已泄漏到剪贴板；如要启用需先修复，并准确披露系统剪贴板不可防其他进程读取。
- **就绪状态与真实状态不一致**：`desktop/src-tauri/src/commands.rs:1175` 仅检查槽位非空，没有验证窗口，已销毁目标仍显示 ready；隐藏浮窗时也不清空（`desktop/src-tauri/src/quick_access.rs:472`）。最终注入虽会校验，但 UI 状态可误导。
- **依赖说明及验收记录过度断言**：`.cargo/audit.toml:6` 和 `todo.md:44` 遗漏 alloy-primitives 锁图边，且将锁图等同运行依赖；`todo.md:18,44` 的测试结果缺独立日志支持。修订为区分锁图、启用 feature、实际运行结果，附可复现命令和原始结果。
- **功能和文档口径漂移**：`docs/FEATURE_GAP_ANALYSIS.md:49,65,71` 与实现及 #12 表格矛盾；`docs/src/design/desktop-fill.md:23` 把未接入的辅助函数称为 fallback。同步中英文、设置文案及验收范围。

P0：未发现有证据支持的 P0。上述安全问题应修复并以独立跨进程 Windows 测试覆盖正常填充、恶意目标、窗口/子控件销毁重建、空标题、普通输入框与失败路径；补齐 Linux、Windows 全套及 fuzz 的原始日志后再作验收。
