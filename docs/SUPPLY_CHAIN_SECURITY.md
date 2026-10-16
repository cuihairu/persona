# Supply Chain Security Check Guide

> [English](SUPPLY_CHAIN_SECURITY.md) | [中文](SUPPLY_CHAIN_SECURITY.zh.md)

This project runs comprehensive supply chain security checks to ensure the security, license compliance, and source trustworthiness of every dependency.

## Toolchains

### Rust Ecosystem

#### 1. cargo-deny

[cargo-deny](https://github.com/EmbarkStudios/cargo-deny) is a comprehensive Cargo dependency checking tool.

**Install:**

```bash
cargo install cargo-deny
```

**Features:**

- Security vulnerability checks (based on the RustSec Advisory Database)
- License compliance verification
- Dependency source verification
- Duplicate dependency detection
- Banned dependency management

**Configuration file:** `deny.toml`

**Run checks:**

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

[cargo-audit](https://github.com/RustSec/rustsec/tree/main/cargo-audit) focuses on scanning for known vulnerabilities.

**Install:**

```bash
cargo install cargo-audit
```

**Run checks:**

```bash
cargo audit
```

### JavaScript/TypeScript Ecosystem

#### pnpm audit

Node.js's built-in security audit tool (the desktop side of this repo uses the pnpm workspace).

**Run checks:**

```bash
pnpm --filter persona-desktop audit

# 仅显示中等及以上级别的漏洞
pnpm --filter persona-desktop audit --audit-level=moderate

# 自动修复（谨慎使用）
pnpm --filter persona-desktop audit fix
```

## License Policy

### Allowed Licenses

The allowlist in `deny.toml` (anything not listed is rejected — the mechanism is an allowlist, not tiered warnings):

- **MIT** - the most permissive license
- **Apache-2.0** (including `Apache-2.0 WITH LLVM-exception`) - a business-friendly license
- **BSD-2-Clause / BSD-3-Clause** - concise licenses
- **ISC** - similar to MIT
- **Unicode-3.0 / Zlib / MITNFA / CDLA-Permissive-2.0 / BSL-1.0** - common permissive licenses
- **MPL-2.0** - Mozilla Public License
- **CC0-1.0** - public domain dedication
- **0BSD** - zero-clause BSD

### Prohibited Licenses

The following licenses are prohibited due to their copyleft nature (everything outside the allowlist is rejected):

- **GPL-2.0 / GPL-3.0** - strong copyleft
- **AGPL-3.0** - network copyleft
- **LGPL** - weaker copyleft

### Handling License Issues

If an incompatible license is detected:

1. **Evaluate the dependency:** confirm whether it is truly needed
2. **Look for alternatives:** find a substitute library with a compatible license
3. **Contact upstream:** discuss with the library maintainers whether a license change is possible
4. **Exception request:** record it in `deny.toml` (requires team approval)

## Security Vulnerability Handling Process

### 1. Detection Phase

The CI/CD pipeline runs the security checks automatically:

```yaml
# .github/workflows/ci.yml — Security Audit job（两个独立 step）
- run: cargo deny check
- run: cargo audit
  continue-on-error: true # Don't fail CI on advisories, just warn
```

### 2. Vulnerability Analysis

When a vulnerability is detected:

1. **View the details:** visit the [RustSec Advisory Database](https://rustsec.org/)
2. **Assess the impact:** determine whether the vulnerability affects this project's usage scenarios
3. **Check for patches:** see whether a fixed version exists

### 3. Remediation Steps

#### Immediate Fix (High/Critical)

```bash
# 更新到修复版本
cargo update -p <crate-name>

# 验证修复
cargo deny check advisories
cargo audit
```

#### Planned Fix (Medium/Low)

1. Create a tracking task in GitHub Issues
2. Assess the upgrade impact
3. Fix it in the next sprint

#### Temporary Ignore (False Positive/Not Applicable)

```toml
# deny.toml
[advisories]
ignore = [
    "RUSTSEC-YYYY-XXXX",  # 原因: 不影响我们的使用场景
]
```

**Note:** the reason for the ignore must be explained in the PR!

### Known Unfixed Dependency Registry (2026-09 Review)

For the Dependabot alerts below, upstream has **no patched version** or the fix is locked by the host framework; the risk surface and the path to resolution are recorded here. At each monthly review, check whether upstream has shipped a fix.

| Alert                        | Dependency         | Introduction chain                                                  | Risk surface assessment                                                                                                                                                                                                                                                                                                                                                           | Resolution path                                                                                                      |
| ---------------------------- | ------------------ | ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| GHSA-wrw7-89jp-8q8g (medium) | glib 0.18.5        | Tauri (Linux GTK backend) → gtk-rs (Linux desktop only)             | `VariantStrIter` iterator soundness flaw; the Persona desktop side does not use that iterator directly to traverse untrusted Variant data                                                                                                                                                                                                                                         | Waiting on an upstream gtk-rs transitive dependency upgrade (glib 0.18.5 is still in `desktop/src-tauri/Cargo.lock`) |
| GHSA-848j-6mx2-7j84 (low)    | ~~elliptic 6.6.1~~ | ~~website (umi) → webpack → node-libs-browser → crypto-browserify~~ | **Broken (2026-10 review)**: the root `package.json` overrides point `crypto-browserify` at an in-house no-op stub (`vendor/crypto-browserify-stub`, pnpm `link:`), so the whole elliptic chain left the dependency tree; umi's node-libs-browser polyfill map still require.resolve's the package but never loads it, and the website build never calls the node crypto polyfill | Resolved (stub breaks the chain)                                                                                     |

Fixed (reviewed in the same batch): workspace `lru` 0.12.5→0.18.4 (ratatui 0.26→0.30 + rqrr 0.7→0.11); `desktop/src-tauri` `rand` 0.8.5→0.8.8; docs `vite` 5.4.21→6.4.3 + `esbuild` 0.21.5→0.25.12 (initially flattened with npm overrides, later resolved naturally to 0.25.12 via vite ^6.4.3 and the override removed; vitepress 1.6.4 build verified); `image-size` (GHSA-5p2g-fcmc-qvqq / GHSA-w3rx-r6r6-pgpr, high) — after the pnpm override `less@<4.9.1`→4.9.1 the whole chain disappeared, because less 4.9.1 dropped its image-size dependency; a defensive pin `image-size@<2.0.4`→2.0.4 remains (OSV confirms 2.0.4 has no known vulnerabilities; Dependabot's alert metadata lags and still marks it "no patch").

## Makefile Commands

The project provides convenient Makefile commands:

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

## CI/CD Integration

### GitHub Actions

The security checks are integrated into the CI pipeline:

**Triggers:**

- Every `push` to the `main` branch
- Every `pull_request`

**Checks:**

1. Rust dependency security
2. JavaScript/TypeScript dependency security
3. License compliance
4. Dependency source verification

**Failure policy:**

- Rust side (`cargo deny check advisories`, v2 advisories): any level of
  RustSec vulnerability fails CI ("Vulnerable" is denied by default; an exemption requires explicit registration);
- JS/TS side (pnpm audit): `--audit-level=moderate` with `continue-on-error`
  — vulnerabilities of high and above are reported but do not block merges;
- License violations → CI failure (allowlist mechanism)
- Unknown dependency sources → warning

## Scheduled Maintenance

### Weekly Tasks

```bash
# 更新漏洞数据库
cargo deny fetch

# 检查依赖更新
cargo outdated
pnpm --filter persona-desktop outdated
```

### Monthly Tasks

```bash
# 完整安全审计
make security-check

# 更新依赖到最新安全版本
cargo update
cd desktop && npm update
```

### Quarterly Review

1. Review all security ignores
2. Assess dependency health (maintenance status, community activity)
3. Clean up unused dependencies
4. Update the security policy

## Best Practices

### 1. Minimize Dependencies

- Do not add unnecessary dependencies
- Prefer the standard library
- Evaluate the size of the transitive dependency tree

### 2. Pin Versions

```toml
# Cargo.toml - 使用精确版本
[dependencies]
serde = "1.0.197"  # 好
# serde = "*"      # 坏
```

### 3. Review New Dependencies

Before adding a new dependency, check:

- Whether the license is compatible
- Maintenance activity (most recent commit time)
- Community trust (stars, downloads, contributors)
- Security history (any vulnerability records)
- Code quality (test coverage, CI status)

### 4. Dependency Locking

- Commit `Cargo.lock` to version control
- Commit `pnpm-lock.yaml` to version control (exception for the docs/ subsite: standalone npm + `docs/package-lock.json`)
- Do not commit `node_modules/` or `target/`

### 5. Prioritize Security Updates

- High/critical vulnerabilities: fix within 24 hours
- Medium vulnerabilities: fix within 1 week
- Low vulnerabilities: fix within 1 month

## Troubleshooting

### cargo-deny Check Failures

**Symptom:** `cargo deny check` returns an error

**Resolution steps:**

1. View the detailed output:

   ```bash
   cargo deny check -vv
   ```

2. Fix the specific problem:

   ```bash
   # 漏洞问题
   cargo update -p <vulnerable-crate>

   # 许可证问题
   # 评估并更新 deny.toml 或移除依赖

   # 来源问题
   # 检查是否使用了非 crates.io 源
   ```

### cargo-audit False Positives

**Symptom:** the reported vulnerabilities do not affect this project

**Resolution steps:**

1. Read the vulnerability details carefully
2. Confirm that it does not affect this project's usage scenarios
3. Add an ignore entry in `deny.toml` with a stated reason

### npm audit Flood of Warnings

**Symptom:** `npm audit` shows dozens of vulnerabilities

**Resolution steps:**

1. Check whether they are dev dependencies:

   ```bash
   npm audit --production
   ```

2. Try an automatic fix:

   ```bash
   npm audit fix
   ```

3. Upgrade the major dependencies by hand:
   ```bash
   npm update <package-name>
   ```

## Reference Resources

### Official Documentation

- [RustSec Advisory Database](https://rustsec.org/)
- [cargo-deny Documentation](https://embarkstudios.github.io/cargo-deny/)
- [cargo-audit Documentation](https://github.com/RustSec/rustsec/tree/main/cargo-audit)
- [npm audit Documentation](https://docs.npmjs.com/cli/v8/commands/npm-audit)

### Security Advisory Subscriptions

- [RustSec Advisories RSS](https://rustsec.org/feed.xml)
- [GitHub Security Advisories](https://github.com/advisories)
- [npm Security Advisories](https://github.com/advisories?query=ecosystem%3Anpm)

### Community Resources

- [Rust Security Working Group](https://www.rust-lang.org/governance/wgs/wg-security-response)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)

---

**Maintainer:** Persona Security Team
**Last updated:** 2026-10-05
**Review cycle:** Quarterly
