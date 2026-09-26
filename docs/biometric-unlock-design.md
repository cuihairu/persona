# 生物识别解锁设计（调用系统功能解锁 vault）

状态：2026-09-26 设计定稿 + 架构落地；macOS 硬件绑定路线**待真机 spike**（§5.2）。
本文是 `docs/THREAT_MODEL.md`「Biometric Unlock」章的展开设计稿。

## 0. 需求原点

用户原话："调用系统功能解锁"、"macOS 也应该支持"、"Linux / Android / iOS 是否都支持"。

Persona 已有一层生物识别（2026-09-21 落地，三桌面平台）：**主密码托管进
OS keyring + OS 认证弹框做门禁**。本设计是它的升级：把"弹框通过就取回
密码"升级为"**密钥被硬件包住，解密那一刻才弹生物识别**"，并补齐移动端
路线图。

## 1. 平台支持矩阵

| 平台    | API                                                                                                                    | 绑定强度               | 本轮状态                                    |
| ------- | ---------------------------------------------------------------------------------------------------------------------- | ---------------------- | ------------------------------------------- |
| iOS     | LocalAuthentication (LAContext) + Secure Enclave (CryptoKit `dataRepresentation`)                                      | 硬件绑定               | 未接（无 Flutter 宿主，§7.2）               |
| Android | androidx BiometricPrompt + Android Keystore（`setUserAuthenticationRequired` + `setInvalidatedByBiometricEnrollment`） | 硬件绑定               | 未接（同上）                                |
| macOS   | Secure Enclave P-256 + ECIES（路线 B'，§5.2）                                                                          | 硬件绑定               | **spike 工具已备，待真机**；当前保持门禁层  |
| Windows | 首选 NCrypt/TPM "Passport 密钥"；次选 WebAuthn 平台认证器复用 `core/src/crypto/passkey.rs` ES256 原语                  | 硬件绑定（TPM）        | 规划中（§6）；当前保持 Windows Hello 门禁层 |
| Linux   | polkit `auth_self`（现状）或 fprintd D-Bus 直调                                                                        | **仅门禁，无硬件封装** | 现状保持（§7.1 诚实局限）                   |

绑定强度三档（`BiometricWrapCapability`，core 定义、三端共用）：

1. **HardwareBound**：包裹密钥的私钥不可导出（SE / TPM / Keystore），
   解密操作由硬件强制要求用户认证（生物识别 + 系统密码回退）。
   换指纹/生物注册集变化 → 密钥自动失效。
2. **OsGateOnly**：秘密存 OS keyring，OS 认证弹框是门禁——门禁由系统
   执行（非应用层自检），但 keyring 本身可能被同用户进程读取
   （THREAT_MODEL 已登记 Windows Credential Manager 无 ACL）。
3. **Unsupported**：无生物硬件/无系统认证栈，功能整体隐藏（前端不渲染
   入口，而非报错）。

## 2. 信任模型

### 2.1 防什么

- **T1 同用户恶意进程读秘密**：门禁层（现状）下，读到 keyring 条目 =
  拿到主密码，绕过生物识别。硬件绑定层下，进程只能拿到**包裹 blob**
  （密文），没有硬件认证拿不到明文密钥。
- **T2 生物注册集漂移**：新指纹不应解锁旧包裹。用平台
  `biometryCurrentSet` / `setInvalidatedByBiometricEnrollment` 语义 +
  core 包裹信封里的 enrollment 指纹双保险（§3.2）。
- **T3 暴力试探**：失败计数/锁户在 core `UserAuth` 层，硬件绑定路径
  **不绕过锁户**（见 §3.4）。

### 2.2 不防什么（诚实边界）

- **不替代主密码**：生物识别是解锁因子，主密码始终是恢复因子。
  硬件损坏/重装系统/生物注册重置后，主密码是唯一出路。
- **不存储任何生物模板**：模板永远在系统侧（SE / TEE / StrongBox），
  应用只拿"解密成功"这个布尔结果或解密能力本身。
- **不防被胁迫**：硬件认证通过即解密，与 1Password 同暴露级。
- **不防系统层攻击者**（恶意登录会话内运行的用户态 rootkit、内核级
  键盘记录）：任何本地应用模型都防不了。

## 3. 密钥流

### 3.1 现状（门禁层，三桌面平台已上线）

```
enable:  验主密码 → OS 弹框 → 主密码 → keyring[persona-biometric]
unlock:  keyring 取回主密码 → OS 弹框门禁 → authenticate_user(密码)
```

弱点：T1——OS 弹框只是门禁，keyring 条目是真值。

### 3.2 目标（硬件绑定层）

```
enable（已解锁会话内）:
  master_key = PBKDF2(主密码, salt)          ← 已在内存（会话已解锁）
  wrap_blob  = SE/TPM/Keystore 包裹 master_key   ← 硬件在"包裹"时不弹框
  keyring[persona-biometric-wrap] = wrap_blob     ← 只存密文，不存密码

unlock（锁定态）:
  wrap_blob ← keyring
  master_key = 硬件解开 wrap_blob            ← 硬件在"解密那一刻"弹生物识别
  service.authenticate_with_master_key(master_key)
```

关键差异：秘密的真值从"keyring 里的密码"变成"硬件里的私钥"；
keyring 里只剩打不开的密文。

### 3.3 包裹信封格式（core 定义，`core/src/auth/biometric_wrap.rs`）

```
BIOWRAP1 | u8 platform_tag | 32B enrollment_fp | u32le payload_len | payload
```

- `platform_tag`：1 = macOS SecureEnclave，2 = Windows TPM/Passport，
  3 = Linux（保留），0 = 测试 mock。解包时 tag 不匹配 → `WrapInvalid`。
- `enrollment_fp`：启用时刻的生物注册集指纹（平台提供；硬件已强制
  biometryCurrentSet 的平台可存常量占位）。解包时 core 再比对一次，
  不匹配 → `EnrollmentChanged`——即使平台层漏拦（纵深防御第二道）。
- `payload`：平台私有密文。core 不解释 payload，密钥流只经过
  `wrap_payload`/`unwrap_payload` 两个 trait 方法，中间值用 `Zeroizing` 包裹。

### 3.4 回退链（不可死锁）

```
生物识别 → 系统密码/PIN（平台弹框内置回退，如 LAPolicy.DeviceOwnerAuthentication）
        → 主密码（应用层永远保留的入口）
```

core 侧的失效自动降级：

| 解包错误                                         | 桌面行为                                                                                               |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| `UserCancelled`                                  | 静默回到解锁屏，指纹按钮保留                                                                           |
| `EnrollmentChanged` / `WrapInvalid` / `Platform` | **自动删除包裹 blob** + 返回 `BIOMETRIC_RESET` 码 → 前端提示"生物解锁已重置，请用主密码解锁后重新启用" |
| 锁户（5 次失败）                                 | 与密码路径同语义：`AccountLocked`，生物识别也不放行                                                    |

`authenticate_with_master_key` 与 `authenticate_user` 的语义对齐：
失败计数复位、session 创建、`touch_sensitive`、审计 Login——只有
密码验证这一步被"硬件已认证"替代；`password_change_required`
强制改密旗标**仍然生效**（生物解锁也会被引导进改密流程）。

## 4. 集成架构

```
core（平台无关）
  auth/biometric_wrap.rs
    BiometricWrapCapability / BiometricWrapError
    trait BiometricKeyWrapper { capability / is_available / enrollment_fingerprint
                                / wrap_payload / unwrap_payload / delete_wrap_payload }
    包裹信封编解码 + MockKeyWrapper（测试与 CI 用）
  service.rs::authenticate_with_master_key()   ← 密钥解锁原语（锁户/会话/审计对齐）

desktop（宿主装配）
  biometric.rs           既有 OsBiometricProvider（门禁层，SSH agent 共用）
  biometric/macos_se.rs  Secure Enclave 路线 B' 实现（cfg macos；spike 门控）
  commands.rs            biometric_enable/_unlock 按capability 分流；
                         wrap blob 走 keyring[persona-biometric-wrap]；
                         biometric_wrap_spike 开发命令（真机跑探针）
```

选择规则（`biometric_enable`）：provider `capability()` 为
`HardwareBound` 且 `is_available()` → 硬件包裹；否则 → 门禁层
（现状密码托管，行为不变）。`biometric_unlock` 按 keyring 里
**哪类条目存在**决定走哪条链——两类互斥，禁用命令双删。

## 5. macOS：路线选择与 spike（先验证再实现）

### 5.1 签名坑（为什么不能直接写）

data protection keychain 里任何带 `SecAccessControl` 的条目，在
ad-hoc 签名（Tauri dev/未配证书的 build）下创建/读取会失败
`errSecMissingEntitlement (-34018)`。1Password/Bitwarden 是 Developer ID
签名 + entitlement，我们没有证书。

### 5.2 三条候选路线

| 路线 | 机制                                                                                                                 | 持久性                          | 证书需求                   | 风险                           |
| ---- | -------------------------------------------------------------------------------------------------------------------- | ------------------------------- | -------------------------- | ------------------------------ |
| A    | DP keychain 通用密码 + SecAccessControl(biometryCurrentSet)                                                          | 重启存活                        | Developer ID + entitlement | ad-hoc 下 -34018（已知）       |
| B    | **非永久** SE 密钥（`SecKeyCreateRandomKey` + `kSecAttrTokenIDSecureEnclave` + `kSecAttrIsPermanent: false`）+ ECIES | ⚠️ 进程退出私钥即销毁           | 无                         | 密钥不可重建，重启后 blob 变砖 |
| B'   | **永久** SE 密钥（同上但 `IsPermanent: true` + AccessControl）                                                       | 重启存活（keychain 存 SE 引用） | 待 spike                   | 创建是否也吃 -34018 未知       |

**调研结论（2026-09-26，本地无 Mac 无法实机验证）**：路线 B 字面
方案（非永久密钥）的私钥**不随进程存活**——SE 的持久化只在
`kSecAttrIsPermanent: true` 时发生；CryptoKit 的
`SecureEnclave.P256.PrivateKey.dataRepresentation`（age-plugin-se 等
用的形态）能导出"只有本机 SE 能解开的密钥 blob"从而绕开 keychain，
但该导出是 Swift CryptoKit 专属 API，Security.framework C 接口
（Rust objc2-security 可达范围）**拿不到等价物**。

**spike 目标**（真机 macOS，`PERSONA_BIOMETRIC_SE_SPIKE=1` 启动后调
`biometric_wrap_spike` 命令，逐项回报 OSStatus）。探针与设计条目的
对应关系（探针名即命令返回的 `name`）：

| 设计条目              | 探针名                                                            | 说明                                                                                                                                                                                                                         |
| --------------------- | ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. B' 密钥创建        | `1. SecKeyCreateRandomKey (SE, permanent, biometryCurrentSet)`    | 永久 SE 密钥 + `.privateKeyUsage \| .biometryCurrentSet` AccessControl → 记录 OSStatus（若 -34018 则 B' 也被签名挡住）                                                                                                       |
| 1b. 创建后可查        | `1b. find_key after create`                                       | 同进程内 keychain 引用立即可见                                                                                                                                                                                               |
| 2. ECIES roundtrip    | `2a. SecKeyCreateEncryptedData` / `2b. SecKeyCreateDecryptedData` | B'/B：公钥包裹（无提示）→ 私钥解裹（弹生物识别）；算法为 `kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM`（objc2-security 0.3 仅导出 AESGCM 一族，早年 `...AEAD` 已不导出——同为 SE 内 ECDH+HKDF+AES-GCM） |
| 3. 持久性             | `3. find_key (persistence probe)`                                 | **重启进程后再跑一次 spike**，本步仍 found = keychain 引用跨重启存活                                                                                                                                                         |
| 4. 删指纹对照（手动） | （无自动探针）                                                    | 跑一次 spike → 在系统设置删一条指纹 → 再跑一次：第 2b 步必须失败才算 `biometryCurrentSet` 生效                                                                                                                               |
| 5. 基线               | `4. access control create (baseline, no keychain write)`          | 仅构造 AccessControl（构造本身不吃 entitlement；真正的 -34018 若存在，出现在第 1 步的 key 创建）                                                                                                                             |
| 6. 删除幂等           | `5. SecItemDelete (wrap key, idempotent)`                         | 禁用/失效自愈共用的删除路径（含 `errSecItemNotFound` 幂等）                                                                                                                                                                  |

对照组 A（DP keychain 通用密码 + SecAccessControl）未做自动探针：
ad-hoc 下 -34018 是已知基线（§5.1），且本设计不走路线 A（无证书）。

spike 通过（期望路线 B'）→ 把 macos_se.rs 的 capability 翻成
HardwareBound，enable 默认走硬件包裹；失败 → 文档贴真实错误码，
macOS 保持门禁层，路线 A 留给"有 Developer ID 证书时"再评。

### 5.3 当前 macOS 行为与验证状态（诚实记录）

不变（门禁层）：LAContext `DeviceOwnerAuthentication`（生物识别 + 系统
密码回退）+ keyring 主密码托管。macos_se.rs 已入库，
生产路径未被默认启用——不留半成品在 unlock 主链路上。

编译验证：macos_se.rs 是 `cfg(target_os = "macos")` 代码，Linux CI
（`ci.yml` 的 desktop job，ubuntu-latest）根本不编译它；`objc2`
crate 在非 Apple **host** target 上连 `cargo check` 都直接拒绝。
但交叉 check 可以：`cargo check --target aarch64-apple-darwin --lib`
在 Linux 上可用——`cargo check` 不链接，把 cc-rs 要编译的
ObjC 异常辅助文件用退出 0 的空编译器桩掉
（`CC_aarch64_apple_darwin=true cargo check --target …`）即可让
rustc 全量 type-check 本模块。**2026-09-26 该验证已跑通（check +
clippy `-D warnings` 双绿）**，并当场抓出三处真实错误修复：
CF 类型须走直接依赖 `objc2-core-foundation`（objc2-foundation 不在
根上重导出）、`kSec…` extern static 读取需逐处 `unsafe`、
`SecItemCopyMatching` out 参数是 `*mut *const CFType`。
最终链接与运行时行为仍只在 `desktop-build` 的 macOS job
（macos-latest runner 上 `tauri build`）与真机 spike 上验证。

## 6. Windows（规划，下一期）

- 首选：NCrypt `Microsoft Passport Key Storage Provider`（TPM 保护、
  按 Hello 策略强制认证）——真硬件绑定，等价 macOS 路线 B'。
- 次选：WebAuthn 平台认证器（Windows Hello）+ `core/src/crypto/passkey.rs`
  ES256 原语：make credential（UV required）→ 解锁时 get assertion
  （硬件弹 Hello）→ 以 credential 绑定性门禁 DPAPI 包裹层。
  弱于 Passport Key：assertion 只证明"持证 + 用户在场"，包裹密钥本体
  仍要 DPAPI/TPM 另外保一层。
- `UserConsentVerifier`（布尔确认）只配当**门禁层**现状使用。
- **明确非目标**：不能也不应替代 Windows 登录验证——凭据提供程序是
  LogonUI 加载的 COM 组件，第三方无法顶替；我们做的是"解锁 Persona
  vault"，不是"登录 Windows"。

## 7. Linux / 移动端

### 7.1 Linux 现状（诚实局限）

polkit `auth_self` 门禁（手写 CheckAuthorization，规避 CVE-2026-78422）。
**无硬件密钥封装**：无 SE/StrongBox/TPM 的统一应用层 API；TPM2.0 直驱
（tss-esapi）在桌面发行版碎片化严重，不做默认依赖。keyring 为
secret service（GNOME Keyring/KWallet），条目可被同会话进程读取。
结论：Linux 定格在 OsGateOnly 档，文档不宣称硬件绑定。
fprintd D-Bus（net.reactivated.Fprint）直调是 polkit 的备选（少一层
策略依赖），收益只是少装 polkit，暂不做。

### 7.2 iOS / Android（路线图，等 Flutter 宿主）

- iOS：CryptoKit `SecureEnclave.P256` + `.biometryCurrentSet` AccessControl，
  `dataRepresentation` 落 app 自管文件（不经 keychain，避开 entitlement），
  LAContext 只做 UI 提示。persona-mobile 已有 FFI 包络，宿主落地后
  按本设计的 trait 直接实现第四个后端。
- Android：Keystore `setUserAuthenticationRequired(true)` +
  `setInvalidatedByBiometricEnrollment(true)`（API 24/28 语义），
  BiometricPrompt 触发 gate；包裹 blob 走 FFI 传回 Rust 侧存 keyring。
- 两端的 FFI 包络（`{"ok":…,"data"|"error":…}`）已在
  persona-mobile 就绪，缺口只有 Flutter 宿主工程本身。

## 8. 本轮落地清单（2026-09-26）

- [x] 设计文档（本文）
- [x] core：`BiometricKeyWrapper` trait + 信封编解码 + `MockKeyWrapper`
      （行/分支 100%，`cargo llvm-cov` 实测；另 6 个服务层用例覆盖
      包裹→解锁端到端与三道门禁）
- [x] core：`authenticate_with_master_key`（锁户/失败计数/会话/审计/
      强制改密旗标与密码路径对齐）+ `derive_master_key_for_wrap` +
      `unlock_with_master_key`
- [x] desktop：capability 分流的 enable/unlock/disable/status +
      wrap blob keyring 隔离（`persona-biometric-wrap`）+ 改密联动删 blob + 命令层 7 用例（enable 落密文/blob 互斥/unlock 闭环/注册集漂移/
      用户取消/blob 损坏/改密失效/spike 非 macOS 报 Unsupported）
- [x] desktop：macos_se.rs（路线 B'，spike 门控；**编译验证已过**——
      Linux 交叉 check/clippy，见 §5.3）+ `biometric_wrap_spike` 命令
- [x] desktop：状态面暴露 wrap 档位（hardware-bound / os-gate），
      EnrollmentChanged 自动降级 + `BIOMETRIC_RESET` / `BIOMETRIC_CANCELLED`
      前端分流（解锁屏 RESET 隐藏按钮、CANCEL 静默保留；设置页档位行）
- [ ] macOS 真机 spike（§5.2 探针 1/1b/2a/2b/3/4/5 + 手动删指纹对照）
      → 结论回填本文 §5.2 与 THREAT_MODEL
- [ ] Windows Passport Key / WebAuthn 实现（§6）
- [ ] iOS/Android：等 Flutter 宿主（§7.2）
