# Contributing Guide

Thanks for helping improve Persona! This guide captures the conventions we expect contributors to follow so reviews stay fast and predictable.

## Conventional Commits

We enforce Conventional Commit titles on every pull request. Format:

```
<type>(<optional scope>): <summary>
```

Valid types: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `build`, `ci`, `perf`, `style`, `revert`. Keep subjects under ~72 characters and written in the imperative mood.

Examples:
- `feat(cli): add credential list command`
- `fix(core): clamp TOTP skew to 30s`
- `chore: update CI cache keys`

## Pull Requests

- Use a Conventional Commit–style PR title; squash merges will keep the title as the final commit.
- Keep PRs focused and linked to issues when possible.
- Update `TODO.md` when you add or complete roadmap items.
- Add tests for new logic and run `make lint-all` / `make test-all` locally when feasible.

## Code Ownership

CODEOWNERS routes reviews to the right maintainers. If you create new top-level areas, extend `.github/CODEOWNERS` accordingly so changes keep flowing to the right people.
