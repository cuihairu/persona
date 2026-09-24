# 环境搭建

从源码构建 Persona（CLI + SSH Agent + 桌面应用）所需的工具链与步骤。
版本以仓库钉定为准，不按通用建议猜。

## 前置依赖

| 工具            | 版本                             | 说明                                                        |
| --------------- | -------------------------------- | ----------------------------------------------------------- |
| Rust            | **1.97.0**（仓库钉定）           | 装 [rustup](https://rustup.rs) 即可，进入仓库目录自动切版本 |
| Node.js         | 24（与 CI 同大版本）             | 前端构建与脚本                                              |
| pnpm            | 10.22.0（`packageManager` 钉定） | `corepack enable pnpm` 后自动对齐                           |
| Tauri 系统依赖  | webkit2gtk / gtk3 等             | 仅桌面应用；Linux 见下方 apt 清单                           |
| docker / podman | 任意近期版                       | 可选，服务器镜像与可复现构建容器                            |

Linux 桌面构建依赖（Debian/Ubuntu 系）：

```bash
sudo apt install build-essential libwebkit2gtk-4.1-dev libgtk-3-dev \
  libayatana-appindicator3-dev librsvg2-dev libxdo-dev libssl-dev
```

## 克隆与构建

```bash
git clone git@github.com:cuihairu/persona.git
cd persona

# Rust 侧：CLI + server + SSH agent（rustup 按 rust-toolchain.toml 自动用 1.97.0）
cargo build --workspace

# JS 侧：桌面应用 + 浏览器扩展
corepack enable pnpm
pnpm install
```

## 跑起来

```bash
# CLI：初始化一个加密工作区
cargo run -p persona-cli -- init --path ~/Persona --yes --encrypted \
  --master-password "你的主密码"

# 桌面应用 dev 模式
pnpm --filter desktop run dev
```

CLI 与桌面应用共用同一套密码库格式，可混用（见[快速开始](/user/quick-start)）。

## 质量门（与 CI 同口径）

```bash
make ci                        # 全套：安装 + lint + test + 漏洞扫描

# 格式：双口径（desktop 是独立 workspace，两个都要跑）
cargo fmt --all
cargo fmt                      # 在 desktop/src-tauri/ 下再跑一次

# Clippy：拒绝 warning
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --all-targets -- -D warnings   # 在 desktop/src-tauri/ 下再跑一次
```

> Rust 全量测试约 12–16 分钟（Argon2 密钥派生密集），改 CI 前先
> `cargo test -p <crate>` 单跑相关 crate 省时间。

## 产物构建

- **可复现 deb**：`scripts/build-repro.sh`（或加 `--docker` 进标准容器构建），
  细节见
  [REPRODUCIBLE_BUILDS.md](https://github.com/cuihairu/persona/blob/main/docs/REPRODUCIBLE_BUILDS.md)。
- **server 镜像**：`docker build -f docker/Dockerfile.server .`

## 下一步

- [项目结构](/development/structure)——monorepo 布局与 crate 职责
- [工程文档](https://github.com/cuihairu/persona/tree/main/docs)——设计文档全集
