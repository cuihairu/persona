# 供应链安全检查指南

本项目实施全面的供应链安全检查,确保所有依赖项的安全性、许可证合规性和来源可信度。

## 工具链

### Rust 生态系统

#### 1. cargo-deny

[cargo-deny](https://github.com/EmbarkStudios/cargo-deny) 是一个全面的 Cargo 依赖检查工具。

**安装:**

```bash
cargo install cargo-deny
```

**功能:**

- ✅ 安全漏洞检查 (基于 RustSec Advisory Database)
- ✅ 许可证合规性验证
- ✅ 依赖来源验证
- ✅ 重复依赖检测
- ✅ 禁用依赖管理

**配置文件:** `deny.toml`

**运行检查:**

```bash
# 完整检查
cargo deny check

# 单项检查
cargo deny check advisories  # 仅漏洞检查
cargo deny check licenses    # 仅许可证检查
cargo deny check bans        # 仅禁用依赖检查
cargo deny check sources     # 仅来源检查
```

#### 2. cargo-audit

[cargo-audit](https://github.com/RustSec/rustsec/tree/main/cargo-audit) 专注于已知漏洞扫描。

**安装:**

```bash
cargo install cargo-audit
```

**运行检查:**

```bash
cargo audit
```

### JavaScript/TypeScript 生态系统

#### npm audit

Node.js 内置的安全审计工具。

**运行检查:**

```bash
cd desktop
npm audit

# 仅显示中等及以上级别的漏洞
npm audit --audit-level=moderate

# 自动修复（谨慎使用）
npm audit fix
```

## 许可证策略

### 允许的许可证

项目允许以下开源许可证:

- **MIT** - 最宽松的许可证
- **Apache-2.0** - 商业友好的许可证
- **BSD-2-Clause / BSD-3-Clause** - 简洁的许可证
- **ISC** - 与 MIT 类似
- **MPL-2.0** - Mozilla Public License
- **CC0-1.0** - 公共领域声明
- **0BSD** - 零条款 BSD

### 禁止的许可证

以下许可证因其 copyleft 性质被禁止:

- **GPL-2.0 / GPL-3.0** - 强 copyleft
- **AGPL-3.0** - 网络 copyleft
- **LGPL** - 较弱的 copyleft (警告级别)

### 处理许可证问题

如果检测到不兼容的许可证:

1. **评估依赖:** 确认是否真正需要该依赖
2. **寻找替代:** 查找具有兼容许可证的替代库
3. **联系上游:** 与库维护者沟通许可证变更可能性
4. **例外申请:** 记录在 `deny.toml` 中 (需团队审批)

## 安全漏洞处理流程

### 1. 检测阶段

CI/CD 流水线自动运行安全检查:

```yaml
# .github/workflows/ci.yml
- name: Security Audit
  run: cargo deny check && cargo audit
```

### 2. 漏洞分析

当检测到漏洞时:

1. **查看详情:** 访问 [RustSec Advisory Database](https://rustsec.org/)
2. **评估影响:** 确定漏洞是否影响项目的使用场景
3. **检查补丁:** 查看是否有修复版本

### 3. 修复步骤

#### 立即修复 (高危/严重)

```bash
# 更新到修复版本
cargo update -p <crate-name>

# 验证修复
cargo deny check advisories
cargo audit
```

#### 计划修复 (中危/低危)

1. 在 GitHub Issues 创建跟踪任务
2. 评估升级影响
3. 在下个 sprint 中修复

#### 临时忽略 (误报/不适用)

```toml
# deny.toml
[advisories]
ignore = [
    "RUSTSEC-YYYY-XXXX",  # 原因: 不影响我们的使用场景
]
```

**注意:** 必须在 PR 中说明忽略原因!

### 已知未修复依赖登记（2026-09 复审）

下列 Dependabot 告警上游**无补丁版本**或修复被宿主框架锁定，记录风险面与解除路径。每月复审时核对上游是否已发修复。

| 告警                         | 依赖           | 引入链                                                          | 风险面评估                                                                                    | 解除路径                                                |
| ---------------------------- | -------------- | --------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| GHSA-wrw7-89jp-8q8g (medium) | glib 0.18.5    | Tauri 1.x → gtk-rs（仅 Linux 桌面）                             | `VariantStrIter` 迭代器 soundness 缺陷；Persona 桌面端不直接以该迭代器遍历不可信 Variant 数据 | Tauri 2.x 升级批次（独立工程）                          |
| GHSA-848j-6mx2-7j84 (low)    | elliptic 6.6.1 | website (umi) → webpack → node-libs-browser → crypto-browserify | 构建链 polyfill 聚合；website 是展示站，产物不调用 node crypto polyfill；上游无补丁版本       | umi/webpack 构建链演进后依赖消失，或迁出 webpack 系构建 |

已修复（同批复核）：workspace `lru` 0.12.5→0.18.4（ratatui 0.26→0.30 + rqrr 0.7→0.11）；`desktop/src-tauri` `rand` 0.8.5→0.8.7；docs `vite` 5.4.21→6.4.3 + `esbuild` 0.21.5→0.25.12（npm overrides，vitepress 1.6.4 构建验证通过）；`image-size`（GHSA-5p2g-fcmc-qvqq / GHSA-w3rx-r6r6-pgpr，high）pnpm override `less@<4.9.1`→4.9.1 后整链消失——less 4.9.1 已移除 image-size 依赖，另留 `image-size@<2.0.4`→2.0.4 防御性 pin（OSV 确认 2.0.4 无已知漏洞；Dependabot 告警元数据滞后仍标"无补丁"）。

## Makefile 命令

项目提供了便捷的 Makefile 命令:

```bash
# 完整安全检查 (推荐)
make security-check

# 仅漏洞扫描
make security-advisories

# 仅许可证检查
make security-licenses

# 仅依赖禁用检查
make security-bans

# 仅来源检查
make security-sources

# 传统 audit (仅漏洞)
make security-audit
```

## CI/CD 集成

### GitHub Actions

安全检查已集成到 CI 流水线:

**触发条件:**

- 每次 `push` 到 `main` 分支
- 每个 `pull_request`

**检查项目:**

1. Rust 依赖安全
2. JavaScript/TypeScript 依赖安全
3. 许可证合规性
4. 依赖来源验证

**失败策略:**

- ❌ 高危/严重漏洞 → CI 失败
- ⚠️ 中危/低危漏洞 → 警告 (不阻塞)
- ❌ 许可证违规 → CI 失败
- ❌ 未知依赖来源 → 警告

## 定期维护

### 每周任务

```bash
# 更新漏洞数据库
cargo deny fetch

# 检查依赖更新
cargo outdated
cd desktop && npm outdated
```

### 每月任务

```bash
# 完整安全审计
make security-check

# 更新依赖到最新安全版本
cargo update
cd desktop && npm update
```

### 季度审查

1. 审查所有安全忽略项
2. 评估依赖项健康度 (维护状态、社区活跃度)
3. 清理未使用的依赖
4. 更新安全策略

## 最佳实践

### 1. 最小化依赖

- ❌ 不添加不必要的依赖
- ✅ 优先使用标准库
- ✅ 评估依赖的传递依赖树大小

### 2. 固定版本

```toml
# Cargo.toml - 使用精确版本
[dependencies]
serde = "1.0.197"  # 好
# serde = "*"      # 坏
```

### 3. 审查新依赖

添加新依赖前检查:

- ✅ 许可证是否兼容
- ✅ 维护活跃度 (最近提交时间)
- ✅ 社区信任度 (stars, downloads, contributors)
- ✅ 安全历史 (是否有漏洞记录)
- ✅ 代码质量 (测试覆盖率, CI状态)

### 4. 依赖锁定

- ✅ 提交 `Cargo.lock` 到版本控制
- ✅ 提交 `package-lock.json` 到版本控制
- ❌ 不提交 `node_modules/` 或 `target/`

### 5. 安全更新优先

- 高危/严重漏洞: 24小时内修复
- 中危漏洞: 1周内修复
- 低危漏洞: 1个月内修复

## 故障排除

### cargo-deny 检查失败

**症状:** `cargo deny check` 返回错误

**解决步骤:**

1. 查看详细输出:

   ```bash
   cargo deny check -vv
   ```

2. 针对性修复:

   ```bash
   # 漏洞问题
   cargo update -p <vulnerable-crate>

   # 许可证问题
   # 评估并更新 deny.toml 或移除依赖

   # 来源问题
   # 检查是否使用了非 crates.io 源
   ```

### cargo-audit 误报

**症状:** 报告的漏洞不影响项目

**解决步骤:**

1. 仔细阅读漏洞详情
2. 确认不影响项目使用场景
3. 在 `deny.toml` 中添加忽略项并说明原因

### npm audit 大量警告

**症状:** `npm audit` 显示数十个漏洞

**解决步骤:**

1. 检查是否为开发依赖:

   ```bash
   npm audit --production
   ```

2. 尝试自动修复:

   ```bash
   npm audit fix
   ```

3. 手动升级主要依赖:
   ```bash
   npm update <package-name>
   ```

## 参考资源

### 官方文档

- [RustSec Advisory Database](https://rustsec.org/)
- [cargo-deny 文档](https://embarkstudios.github.io/cargo-deny/)
- [cargo-audit 文档](https://github.com/RustSec/rustsec/tree/main/cargo-audit)
- [npm audit 文档](https://docs.npmjs.com/cli/v8/commands/npm-audit)

### 安全公告订阅

- [RustSec Advisories RSS](https://rustsec.org/feed.xml)
- [GitHub Security Advisories](https://github.com/advisories)
- [npm Security Advisories](https://github.com/advisories?query=ecosystem%3Anpm)

### 社区资源

- [Rust Security Working Group](https://www.rust-lang.org/governance/wgs/wg-security-response)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)

---

**维护者:** Persona Security Team
**最后更新:** 2025-01-24
**审阅周期:** 季度
