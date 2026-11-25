#!/usr/bin/env bash
# SSH agent real-host E2E harness: live acceptance test against github.com
# (the TODO "Full E2E test" item). Only two points need user cooperation:
# (1) paste the printed public key into GitHub; (2) confirm the signature in the TTY.
# Usage: PERSONA_E2E_IDENTITY=<identity name> scripts/e2e-ssh-github.sh
# Steps and expected output mirror the same todo.md entry; negative cases
# (decline confirmation / rate limiting / audit lines) are covered by TODO
# manual section 4 and are not automated in this script.
set -euo pipefail

IDENTITY=${PERSONA_E2E_IDENTITY:-default}
KEY_NAME=github-e2e

fail() { echo "✗ $*" >&2; exit 1; }

command -v persona >/dev/null || fail "未找到 persona CLI（先 cargo install --path cli 或用仓库内构建产物）"
command -v ssh >/dev/null || fail "未找到 ssh"

echo "── 0. 前置：解锁 vault（列出全部 SSH 密钥）"
persona ssh list-all || fail "list-all 失败：vault 未初始化或主密码不对"
echo "✓ vault 可用（身份：$IDENTITY）"

# list-all/agent-status output may carry ANSI color codes (colored is affected
# by CLICOLOR_FORCE and similar env vars), so strip them before parsing
plain() { sed 's/\x1b\[[0-9;]*m//g'; }

echo "── 1. 密钥：已有 $KEY_NAME 则复用，否则生成"
existing=$(persona ssh list-all | plain | grep -B1 "Name: $KEY_NAME" | grep -oP 'ID: \K[0-9a-f-]+' || true)
if [ -n "$existing" ]; then
  key_id=$existing
  echo "✓ 复用既有密钥 $key_id"
else
  persona ssh generate --identity "$IDENTITY" --name "$KEY_NAME"
  key_id=$(persona ssh list-all | plain | grep -B1 "Name: $KEY_NAME" | grep -oP 'ID: \K[0-9a-f-]+' || true)
  [ -n "$key_id" ] || fail "生成后未在 list-all 找到 $KEY_NAME"
  echo "✓ 已生成 $key_id"
fi

echo "── 2. 公钥上 GitHub（唯一的人工步骤）"
persona ssh export-pub --id "$key_id" | tee /tmp/persona-github-e2e.pub
echo "→ 把上面这行公钥添加到：https://github.com/settings/ssh/new"
read -r -p "添加完成后按回车继续…"

echo "── 3. 装载 agent"
persona ssh add-to-agent --identity "$IDENTITY"
# agent-status has no literal "running" marker: when running it prints
# Socket:/PID:/Agent keys, when stopped it prints "not running" — so the
# running criterion is "has a Socket line and no not running"
status_out=$(persona ssh agent-status | plain)
echo "$status_out"
echo "$status_out" | grep -q "not running" && fail "agent 未运行"
echo "$status_out" | grep -q "Socket:" || fail "agent 缺 Socket 行（未运行）"
echo "✓ agent 运行中"

echo "── 4. 正向：真连 github.com（TTY 确认时输 y）"
echo "   （GitHub 不提供 shell，ssh -T 以退出码 1 结束属正常，以输出判定）"
set +e
persona ssh run --host github.com -- ssh -o StrictHostKeyChecking=accept-new -T git@github.com \
  2>&1 | tee /tmp/persona-github-e2e.out
set -e

echo "── 5. 判定"
if grep -q "successfully authenticated" /tmp/persona-github-e2e.out; then
  echo "✓ E2E 通过：GitHub 已用 persona 提供的密钥认证"
else
  fail "未看到 successfully authenticated——检查 /tmp/persona-github-e2e.out 与公钥是否已上 GitHub"
fi
echo "负向用例（拒绝确认 / PERSONA_AGENT_REQUIRE_CONFIRM / 限速 / audit ssh_sign 行）按 todo.md 手册 ④ 手工过一遍"
