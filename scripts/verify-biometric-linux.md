# Linux biometric unlock 实机验证脚本

前置：桌面开发环境已就绪（`pnpm i`、Rust toolchain）；有 secret service
实现（GNOME Keyring / KWallet）在运行；polkit agent 在运行（桌面会话默认有）。

## 0. 安装 polkit action（dev 构建不带）

```bash
cd desktop/src-tauri
sudo install -Dm644 polkit/com.persona.desktop.biometric-unlock.policy \
  /usr/share/polkit-1/actions/
```

验证安装与授权路径（`auth_self`：会弹本用户密码/指纹框，认证即返回 0）：

```bash
pkcheck --action-id com.persona.desktop.biometric-unlock --process $$; echo "exit=$?"
```

期望：弹框，通过后 `exit=0`；取消则 `exit=2`（授权被拒）。

## 1. 正路径：enable → 指纹解锁

```bash
cd desktop && pnpm tauri dev
```

1. 主密码解锁进入应用。
2. 设置 → 安全 → 「指纹解锁」开 → ReauthModal 输主密码 → 确认 → 系统
   polkit 弹框（无指纹硬件时输本用户密码）→ 开关变绿 + toast「指纹解锁已开启」。
3. 锁定（⌘L / 锁定按钮）→ 解锁屏出现「使用指纹解锁」按钮。
4. 点按钮 → 系统弹框通过 → 直接进入应用（不输主密码）。

keyring 侧核对（条目 = 主密码托管）：

```bash
secret-tool search service persona-biometric   # 应有一条，attribute 含 db 路径
```

## 2. 负路径

- **改密联动**：设置内改主密码 → 锁定 → 指纹按钮仍可用且以新密码解锁。
- **陈旧条目自删**：`secret-tool clear service persona-biometric`（或 CLI 侧
  改密制造陈旧）→ 锁定 → 刷新出的解锁屏**不再渲染指纹按钮**（status 活查）；
  若在条目被删前已渲染，点击后应提示失效并隐藏按钮（`BIOMETRIC_RESET`）。
- **disable**：设置里关指纹解锁 → keyring 条目消失 → 解锁屏无按钮。
- **未装 action 文件**（先 `sudo rm
  /usr/share/polkit-1/actions/com.persona.desktop.biometric-unlock.policy`）：
  设置页开关禁用、提示「当前系统不支持或未配置生物识别」；解锁屏无按钮
  （fail-closed）。
- **错误密码 enable**：ReauthModal 输错主密码 → 错误留在弹窗内可重试，
  keyring 零写入（`secret-tool search` 无新条目）。

## 3. deb 打包核对

```bash
cd desktop && pnpm tauri build --bundles deb
dpkg-deb -c src-tauri/target/release/bundle/deb/Persona_0.1.0_amd64.deb | grep polkit
```

期望行：

```
./usr/share/polkit-1/actions/com.persona.desktop.biometric-unlock.policy
```
