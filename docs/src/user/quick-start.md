# 快速开始

Persona 是本地优先的身份材料管理器：密码库是**你设备上的一个加密 SQLite
文件**，联网能力（同步、审计副本）全部是可选附件。本页带你从零跑起来。

## 两条使用路径

| 路径                 | 适合                                     | 上手方式                       |
| -------------------- | ---------------------------------------- | ------------------------------ |
| **桌面应用**（主推） | 日常管理凭据，图形界面 + 浏览器扩展 + SSH Agent | 源码构建 deb 安装，或 dev 模式 |
| **CLI**              | 脚本化、服务器环境、喜欢终端             | `cargo build --workspace`      |

两者共用同一套本地密码库格式与加密体系，可混用。

## 桌面应用

### 构建与安装

```bash
git clone git@github.com:cuihairu/persona.git
cd persona
pnpm install

# 可复现构建 deb（约 15–25 分钟，产物在仓库根）
scripts/build-repro.sh
sudo dpkg -i Persona_0.1.0_amd64.deb
```

开发调试可直接跑 dev 模式：

```bash
pnpm --filter desktop run dev
```

> 构建细节与逐字节可复现口径见
> [REPRODUCIBLE_BUILDS.md](https://github.com/cuihairu/persona/blob/main/docs/REPRODUCIBLE_BUILDS.md)。

### 首次使用

1. 启动 Persona，**创建密码库**并设置主密码——主密码派生加密密钥，
   库文件全程加密落盘。**主密码丢失无法找回**（没有后门），请牢记。
2. 在主界面添加凭据（密码、API key、TOTP 等），敏感字段默认掩显。
3. 锁定即断密钥：锁屏后主密钥不驻留内存，解锁需重新输入主密码。

## CLI

```bash
# 构建 CLI 与 SSH agent
cargo build --workspace

# 初始化加密工作区
persona init --path ~/Persona --yes --encrypted --master-password "你的主密码"

# 身份与凭据
persona add                      # 新增身份
persona list                     # 列出身份
persona switch <name>            # 切换活跃身份
persona credential add --identity alice --name "GitHub" \
  --credential-type password --prompt-secret
persona credential list --identity alice --format table
persona credential show --id <UUID> --reveal
```

条目历史（1Password 风格）：每次增删改都带时间戳记录，可回溯。

## 备份（建议立刻做）

主库之外只有**加密导出文件**是补救手段——主密码丢失、库文件损坏均无其他
恢复途径。备份口令独立于主密码：

```bash
persona export --encrypt --out vault-backup.persenc   # 加密导出
persona import vault-backup.persenc --decrypt --mode merge --backup   # 恢复
```

自托管服务器用户还可用 `persona backup push` 把整库快照异地保管。
完整实操（含网盘冷备警告、恢复语义）见
[STORAGE_AND_SYNC.md 的备份章节](https://github.com/cuihairu/persona/blob/main/docs/STORAGE_AND_SYNC.md)。

## 可选：多设备端到端加密同步

默认**纯本地、零联网**。要在多台设备间同步凭据：

1. 自托管一台 Persona Server（Docker 镜像，服务器只见密文）；
2. 桌面端「设置 → 同步设备」加入并逐台授权。

离线并发修改同一凭据不会丢数据（双版本保留，由你裁决）。部署步骤、
诚实边界与冲突裁决详见
[STORAGE_AND_SYNC.md](https://github.com/cuihairu/persona/blob/main/docs/STORAGE_AND_SYNC.md)。

## 下一步

- [项目简介](/overview/introduction)——问题边界与设计理念
- [安全特性](/overview/security)——密钥层级与加密体系
- [工程文档](https://github.com/cuihairu/persona/tree/main/docs)——威胁模型、E2EE 同步设计等深度材料
