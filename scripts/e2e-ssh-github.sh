#!/usr/bin/env bash
# SSH agent 真机 E2E 引导：github.com 实连验收（TODO「Full E2E test」条目）。
# 需要用户配合的点只有两处：① 把打印出的公钥贴到 GitHub；② TTY 确认签名。
# 用法: PERSONA_E2E_IDENTITY=<身份名> scripts/e2e-ssh-github.sh
# 步骤与预期输出对照 TODO.md 同条目；负向用例（拒绝确认/限速/审计行）见
# TODO 手册 ④，不在本脚本内自动化。
set -euo pipefail

IDENTITY=${PERSONA_E2E_IDENTITY:-default}
KEY_NAME=github-e2e

fail() { echo "✗ $*" >&2; exit 1; }

command -v persona >/dev/null || fail "未找到 persona CLI（先 cargo install --path cli 或用仓库内构建产物）"
command -v ssh >/dev/null || fail "未找到 ssh"

echo "── 0. 前置：解锁 vault（列出全部 SSH 密钥）"
persona ssh list-all || fail "list-all 失败：vault 未初始化或主密码不对"
echo "✓ vault 可用（身份：$IDENTITY）"

# list-all/agent-status 的输出可能带 ANSI 色码（colored 受 CLICOLOR_FORCE
# 等环境影响），解析前统一剥离
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
# agent-status 没有 "running" 字样：运行中打 Socket:/PID:/Agent keys，
# 未运行打 "not running"——以「有 Socket 且无 not running」为运行判据
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
echo "负向用例（拒绝确认 / PERSONA_AGENT_REQUIRE_CONFIRM / 限速 / audit ssh_sign 行）按 TODO.md 手册 ④ 手工过一遍"
