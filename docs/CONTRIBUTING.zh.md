> [English](CONTRIBUTING.md) | **中文**

# 贡献指南

感谢你帮助改进 Persona！本文档记录了我们期望贡献者遵循的约定，让评审保持快速且可预期。

## Conventional Commits

我们对每个 pull request 强制执行 Conventional Commit 标题。格式：

```
<type>(<optional scope>): <summary>
```

合法类型：`feat`、`fix`、`chore`、`docs`、`refactor`、`test`、`build`、`ci`、`perf`、`style`、`revert`。标题保持在 72 字符以内，使用祈使语气。

示例：

- `feat(cli): add credential list command`
- `fix(core): clamp TOTP skew to 30s`
- `chore: update CI cache keys`

## Pull Requests

- 使用 Conventional Commit 风格的 PR 标题；squash merge 会保留该标题作为最终 commit。
- 保持 PR 聚焦，并尽量关联 issue。
- 新增或完成路线图条目时更新 `TODO.md`。
- 为新逻辑添加测试，并在可行时本地运行 `make lint-all` / `make test-all`。

## Code Ownership

CODEOWNERS 将评审路由到合适的维护者。如果你创建了新的顶层目录，请相应扩展 `.github/CODEOWNERS`，让变更持续流向正确的人。
