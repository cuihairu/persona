# 可复现构建（Reproducible Builds）

状态：**deb 产物同机逐字节可复现**（2026-09-24 基线实测）；工具链已钉版
（1.97.0）、构建机路径已重映射（`scripts/build-repro.sh`），跨机器产物
应当一致但**真跨机复验未做**（见「剩余差距」）。本文记录测量方法、实测
数据与复验命令。

## 范围

- 对象：`tauri build --bundles deb` 产出的 `desktop/src-tauri/target/release/bundle/deb/Persona_0.1.0_amd64.deb`（内嵌 46MB 主程序 + 桌面/图标/polkit 资源）。
- 口径：**同机复现**（同一台机器、同一工具链、同一源码树，仅时间不同）实测通过；跨机器一致性有证据（路径重映射 + 钉版）但未跨机实测。
- AppImage / rpm 已实测（内容可复现、字节级不可复现，见「剩余差距」4）；
  dmg 在 Linux 上无法构建（macOS 专属工具链）、Windows NSIS 安装器未测。

## 实测基线（2026-09-24）

方法：同一源码树连续两次 `tauri build --bundles deb`（第二次前 `touch src-tauri/src/main.rs` 强制重编主 crate + 重链），逐层对比产物。

| 层                                      | 结果                                                                                                                         |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| 前端 `dist/`（tsc + vite build）        | 两次**逐字节一致**（4 个文件，内容哈希命名，无时间戳）                                                                       |
| 二进制 `target/release/persona-desktop` | 两次**逐字节一致**（46,447,992 字节；由归一化 deb 哈希一致传递证明，见下）                                                   |
| deb 内 `debian-binary` ar 成员          | 两次一致（固定 `2.0`）                                                                                                       |
| deb 内 `control.tar.gz` / `data.tar.gz` | 两次**不一致**——差异仅两项：tar 条目 **mtime = 构建时刻**、tar 条目**属主 = 构建用户**；条目顺序、路径、大小、权限位全部一致 |
| gzip 头（两层 tar.gz）                  | 两次一致：bundler 已把 gzip mtime 置 0、OS 字节 0xff（tauri-bundler 2.x 用 flate2，无时间痕迹）                              |
| raw deb 整包                            | `d777883b…` vs `3fd1d15f…`（**不可复现**，唯一来源即上两行 tar 层差异）                                                      |

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

## 一键可复现构建：`scripts/build-repro.sh`

把上述两步（重映射 + 构建 + 归一）收敛成一条命令：

```bash
scripts/build-repro.sh [输出.deb]   # 缺省仓库根 Persona_0.1.0_amd64.deb
```

- `RUSTFLAGS="--remap-path-prefix=$HOME=/repro-home"`：panic location 等
  不再携带真实用户路径（实测 `/home/<user>` ×1006 → **0**，registry 绝对
  路径 ×916 全部变为 `/repro-home` 前缀）——同工具链下跨机器编译产物趋
  于一致。opt-in：只作用于本脚本进程，日常 `cargo build` 不受影响。
- `SOURCE_DATE_EPOCH` 锚定当前 HEAD 提交时刻（非 git 环境退化 0）。
- 内部调用 `normalize-deb.sh` 归一 tar 层。

实测（2026-09-24，钉版工具链 1.97.0）：首轮与强制重编重链轮相隔约
10 分钟，归一 deb 哈希同为
`2cf482056afe1de58c89b96261b0c0f1dfd8e0708e8141f29658bc8fa347f7b9`。

## 构建容器：`docker/Dockerfile.repro` + `--docker` 模式（2026-09-24）

跨机可复现的正式口径：不同宿主机器（glibc/链接器/系统库不同——本基线
宿主 Ubuntu 26.04 即实例）在**同一容器内**执行构建。容器内 `$HOME` 恒为
`/root`，`RUSTFLAGS` 重映射目标随之跨宿主恒定。

```bash
scripts/build-repro.sh --docker                       # 产物写仓库根
PERSONA_REPRO_RUNTIME=podman scripts/build-repro.sh --docker   # podman 亦可
```

- 容器内容：`debian:bookworm-slim`（digest 钉死，与 Dockerfile.server 同
  基座）+ tauri v2 官方 Linux 依赖 + node 24（`COPY --from` 官方镜像，与
  CI setup-node 同大版本）+ corepack 固定 pnpm 10.22.0（`COREPACK_HOME`
  在镜像层内，容器 run 离线可用）+ rustup 1.97.0（与 `rust-toolchain.toml`
  同版，升级 = 改 toolchain file + 重建镜像）。
- **独立 `CARGO_TARGET_DIR=/tmp/repro-target` 是正确性前提**：容器与宿主
  glibc 不同而 cargo 增量指纹不区分工具链环境，误复用宿主 `target/` 会把
  异构缓存编进产物。容器构建因此总是全量（首编译约 15–25 分钟）。
- 依赖安装：容器内 `pnpm install --frozen-lockfile`（宿主已装的
  `node_modules` 挂载复用——同为 linux-x64，二进制兼容；纯净环境全量装）。
- 镜像重建：`docker build -f docker/Dockerfile.repro -t persona-repro .`；
  基础镜像升级同「容器钉死」节的 digest 查询方法。

### 容器内实测（2026-09-24）

三轮全量构建（`--docker` 模式，容器内 cargo 全量 9m40s–12m12s/轮）：

| 轮次       | 配置                        | 归一产物 sha256（前 8 位）          |
| ---------- | --------------------------- | ----------------------------------- |
| R1         | 镜像初版（无 git）          | `211cc36a…`                         |
| R2         | 镜像 + git（终验）          | `000a5265…`                         |
| R3         | 同 R2（复验，独立 cargo 缓存） | `000a5265…`（**与 R2 逐字节一致**） |

- R1 暴露的缺陷与修复：debian slim 无 git，`build-repro.sh` 的
  `SOURCE_DATE_EPOCH` HEAD 锚定静默退化为 0——git 已加入镜像必装清单
  （锚定恢复后哈希从 `211cc36a…` 变为 `000a5265…`，属预期：tar mtime
  锚点不同）。
- R2 == R3：同一容器定义、相隔约 30 分钟的两次独立全量构建（容器
  `--rm` 每次 cargo 缓存清零）逐字节同哈希——**容器内同机复现通过**。
- 与宿主路径产物（`2cf48205…`，SOURCE_DATE_EPOCH 同为 HEAD 但构建环境
  不同）哈希不同，符合预期——**跨机可比对的口径 = 容器内构建**。
- 剩余半步：「不同物理机 × 同一容器」复验（两台机器各跑一次
  `--docker`，`sha256sum` 对比应为 `000a5265…` 口径——同 HEAD 前提下
  epoch 相同、产物应一致），需第二台机器执行。

## 剩余差距（写实）

1. ~~跨机器路径嵌入~~ **已收口**（2026-09-24）：`scripts/build-repro.sh`
   以 `--remap-path-prefix` 重映射 `$HOME`，实测二进制内 `/home/<user>`
   计数 1006 → 0、registry 路径全部变为常量前缀。
2. ~~工具链未固定~~ **已收口**（2026-09-24）：根仓 `rust-toolchain.toml`
   钉 1.97.0（rustup 向上查找，双 workspace 同受覆盖）+ CI 五处
   `dtolnay/rust-toolchain@1.97.0`（版本 ref 官方支持）；升级 = 两处
   一起改。
3. **上游 bundler 不归一**：tar mtime/属主由 tauri-bundler 写入，仓库侧以
   `normalize-deb.sh` 后处理兜底；上游若提供 `SOURCE_DATE_EPOCH` 支持，脚本
   可退化为校验器。
4. **AppImage：内容可复现、字节级不可复现**（2026-09-24 A/B 实测）：两次
   纯打包轮 `tauri build --bundles appimage`，unsquashfs 逐层解包对比——
   文件内容**逐字节一致**（含 linuxdeploy 部署进包的 GTK3/webkit2gtk 依赖
   库），差异仅 **846 条 inode mtime**（= 构建时刻）；并链式传导为整包
   差异：inode mtime → squashfs 字节不同 → 运行时 ELF 的 `.digest_md5`
   段（appimagetool 打包时算的 squashfs MD5，ELF 偏移 0xe3900 的 16 字节）
   随之不同。归一需 `mksquashfs -all-time/-mkfs-fixed-time` 重打包并重算
   digest 段，或上游 appimagetool 支持 `SOURCE_DATE_EPOCH`（AppImageKit
   长期未合）——**未做仓库侧 hack**，deb 仍是主交付可复现产物。

   **rpm：内容可复现、字节级不可复现**（2026-09-24 A/B 实测，方法同上）：
   两次纯打包轮 `tauri build --bundles rpm`，整包对比仅 **64 字节差异、
   全部集中在头部区**——

   | 差异源                       | 位置（tag）                  | 实测                                                          |
   | ---------------------------- | ---------------------------- | ------------------------------------------------------------- |
   | 签名 header 的 SHA256 hex 串 | sig tag 273（64 字符 ASCII） | 56/64 字符不同（哈希对象是主 header，随下列时间戳链式变化）   |
   | 主 header `BUILDTIME`        | tag 1006（INT32）            | 两轮相差 403s，2 字节不同                                     |
   | 主 header `FILEMTIMES`       | tag 1034（INT32×5）          | 前 2 条 = 打包时刻（随轮次变）；后 3 条 = 静态资源 mtime 不变 |

   **payload 逐字节一致**（除上述 64 字节外整包 cmp 相同）。与 AppImage
   同理：差异全部派生自构建时刻，归一需上游 rpm 写头尊重
   `SOURCE_DATE_EPOCH`；仓库侧未做 header 重写 hack。dmg 在 Linux 无法
   构建，未测。

5. **真跨机验证未做（仅剩此半步）**：重映射 + 钉版 + 构建容器已全部就位，
   **容器内同机复现已实测通过**（2026-09-24，R2/R3 两轮独立全量构建逐字
   节同哈希 `000a5265…`，见「容器内实测」）。收口动作 = 第二台机器各跑
   一次 `scripts/build-repro.sh --docker`，`sha256sum` 对比（同 HEAD 前提
   下应与 `000a5265…` 一致——SOURCE_DATE_EPOCH 由 git 锚定同一提交）。

## 依赖输入固定现状

- `Cargo.lock` ×2（根 workspace + desktop/src-tauri）已入库；
- `pnpm-lock.yaml` 已入库；tauri-cli 2.11.4 / vite 8.3.0 由锁文件固定；
- 图标、polkit policy 等静态资源入库（无生成物）；
- **容器钉死（2026-09-24）**：`docker/Dockerfile.server` 两个 FROM 按
  digest 钉死（CI 发布面浮动收口）——
  - `rust:1-bookworm@sha256:93ce27a8…`
  - `debian:bookworm-slim@sha256:3783cc01…`

  钉的是**系统层**（glibc/链接器/预装工具随上游重建漂移的部分）；cargo
  实际版本不受影响——builder 里 rustup 读仓库内 `rust-toolchain.toml`
  （钉 1.97.0），工具链升级与容器 digest 解耦。注意 digest 钉死后
  runtime 层的 apt 包同样冻结在镜像时点，安全补丁随 digest 升级进入。

  升级方法（重新查 multi-arch index digest，改 Dockerfile 后 CI Docker
  job 即验证）：

  ```bash
  # 以 rust:1-bookworm 为例；debian 换 scope 与 tag 即可
  token=$(curl -s 'https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/rust:pull' | jq -r .token)
  curl -sI -H "Authorization: Bearer $token" \
    -H "Accept: application/vnd.oci.image.index.v1+json" \
    https://registry-1.docker.io/v2/library/rust/manifests/1-bookworm |
    grep -i docker-content-digest
  ```
