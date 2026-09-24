# 可复现构建（Reproducible Builds）

状态：**deb 产物同机逐字节可复现**（2026-09-24 基线实测）；跨机器复现
有已知差距（见下文「剩余差距」）。本文记录测量方法、实测数据与复验命令。

## 范围

- 对象：`tauri build --bundles deb` 产出的 `desktop/src-tauri/target/release/bundle/deb/Persona_0.1.0_amd64.deb`（内嵌 46MB 主程序 + 桌面/图标/polkit 资源）。
- 口径：**同机复现**（同一台机器、同一工具链、同一源码树，仅时间不同）。跨机器/跨环境复现为差距项，不是本基线的验收标准。
- AppImage / rpm / dmg / Windows 安装器不在本基线内（bundler 各格式归一化程度未测）。

## 实测基线（2026-09-24）

方法：同一源码树连续两次 `tauri build --bundles deb`（第二次前 `touch src-tauri/src/main.rs` 强制重编主 crate + 重链），逐层对比产物。

| 层 | 结果 |
| --- | --- |
| 前端 `dist/`（tsc + vite build） | 两次**逐字节一致**（4 个文件，内容哈希命名，无时间戳） |
| 二进制 `target/release/persona-desktop` | 两次**逐字节一致**（46,447,992 字节；由归一化 deb 哈希一致传递证明，见下） |
| deb 内 `debian-binary` ar 成员 | 两次一致（固定 `2.0`） |
| deb 内 `control.tar.gz` / `data.tar.gz` | 两次**不一致**——差异仅两项：tar 条目 **mtime = 构建时刻**、tar 条目**属主 = 构建用户**；条目顺序、路径、大小、权限位全部一致 |
| gzip 头（两层 tar.gz） | 两次一致：bundler 已把 gzip mtime 置 0、OS 字节 0xff（tauri-bundler 2.x 用 flate2，无时间痕迹） |
| raw deb 整包 | `d777883b…` vs `3fd1d15f…`（**不可复现**，唯一来源即上两行 tar 层差异） |

结论：不可复现性**全部集中在 deb 打包层的 tar mtime 与属主**，编译与前端产物本身已确定。

## 规范化：`scripts/normalize-deb.sh`

后处理脚本把 tar 层差异归零，使两次构建产出逐字节相同的 deb：

```bash
tauri build --bundles deb
scripts/normalize-deb.sh \
  desktop/src-tauri/target/release/bundle/deb/Persona_0.1.0_amd64.deb \
  Persona_0.1.0_amd64.deb   # 规范化产物
```

三层处理：

1. **ar 成员头**：`ar -rD` 显式确定性模式（成员时间戳/uid/gid 归零）。
2. **tar 内容**：条目按名排序、mtime 统一 `SOURCE_DATE_EPOCH`（缺省 0）、属主统一 `root:0`；权限位经 `tar -p` 原样保留（`/usr/bin/persona-desktop` 的 755 不能丢）。
3. **gzip 头**：`gzip -n`（不写 mtime 与原始文件名；原产物此处已干净，脚本保证不受上游变化影响）。

实测：两次 raw 不同的 deb 经规范化后同为
`29a0c8490a831b2c4b6b3222df7deb806956a8365123488a23d706fdc7f47797`；
`dpkg-deb --info` 结构校验通过（control/md5sums 完整）。

### 复验命令

```bash
# 两次构建（第二次前 touch 主入口强制重链），分别留档 raw deb
sha256sum <deb1> <deb2>                      # raw：预期不同
scripts/normalize-deb.sh <deb1> /tmp/n1.deb
scripts/normalize-deb.sh <deb2> /tmp/n2.deb
sha256sum /tmp/n1.deb /tmp/n2.deb            # 规范化后：预期相同
```

## 剩余差距（写实）

1. **跨机器路径嵌入**：二进制内嵌构建环境绝对路径——`/home/<user>` ×1006、
   `~/.cargo/registry` 绝对路径 ×916（`strings` 实测）。来源是 panic location
   / 调试路径：本仓库 panic 路径为相对形式（`src/...`），**registry 依赖
   crate 的 panic 路径是绝对路径**，随构建机 `$HOME` 变化。缓解：构建时设
   `RUSTFLAGS="--remap-path-prefix=$HOME=/repro-home"`（属构建环境决策，
   未入仓——入仓需评估对所有开发者/CI 构建行为的影响）。
2. **工具链未固定**：本机 rustc 1.97.0，CI 全部 `dtolnay/rust-toolchain@stable`
   漂浮。锁定需加 `rust-toolchain.toml`（根 + desktop/src-tauri 双 workspace
   各一），会改变所有开发者与 CI 的工具链选择、影响 rust-cache 键——单独立项。
3. **上游 bundler 不归一**：tar mtime/属主由 tauri-bundler 写入，仓库侧以
   `normalize-deb.sh` 后处理兜底；上游若提供 `SOURCE_DATE_EPOCH` 支持，脚本
   可退化为校验器。
4. **其他打包格式未测**：AppImage/rpm/dmg 的归一化程度未知，需要时按同
   方法（两次构建 + 逐层解包对比）另测。

## 依赖输入固定现状

- `Cargo.lock` ×2（根 workspace + desktop/src-tauri）已入库；
- `pnpm-lock.yaml` 已入库；tauri-cli 2.11.4 / vite 8.3.0 由锁文件固定；
- 图标、polkit policy 等静态资源入库（无生成物）。
