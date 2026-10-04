#!/usr/bin/env bash
# 账号侧红线实机勾稽（M4 口径）：起真实 persona-server 进程，走 HTTP wire
# 断言账号域边界。与 lib 测试互补：这里验证的是进程/路由/中间件装配，
# 不是 SRP 数学（那在 core/src/accounts/login.rs 的真算 mock 里）。
#
# 断言清单（红线口径：服务端对凭证/会话/设备默认拒绝，放行必须持证）：
#   1. /health 存活
#   2. register 公开（注册入口不设 Bearer——否则无法开账号）
#   3. srp/register 无 Bearer → 401（写凭证 fail-closed）
#   4. srp/register 持静态令牌 → 2xx（bootstrap 链路）
#   5. recovery-codes 无 Bearer → 401；持证 → 出码
#   6. 恢复码一次性：验证成功一次后复用 → success=false
#   7. srp/challenge 公开且返回真实 server_public
#   8. srp/verify 伪证明 → 401
#   9. sessions 证据语义：零证据 → 422；双证据 → 422
#  10. devices/sessions 全家族无 Bearer → 401
#
# 用法：scripts/verify-account-redline.sh   （自建二进制，tmp 隔离，跑完自清理）
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d /tmp/persona-acct-verify.XXXXXX)"
DB="$TMP/verify.db"
PORT="${PERSONA_VERIFY_PORT:-18993}"
BASE="http://127.0.0.1:$PORT"
TOKEN="verify-static-token"
SRV_PID=""

cleanup() {
  [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

fail() { echo "✗ $1" >&2; exit 1; }
pass() { echo "✓ $1"; }

# ---- 0. 构建 server（debug，增量） ----
echo "== build persona-server =="
cargo build --manifest-path "$REPO/server/Cargo.toml" --quiet
BIN="$REPO/target/debug/persona-server"
[ -x "$BIN" ] || fail "server 二进制不存在: $BIN"

# b64 随机 salt/verifier（仅走 wire 装配；verify 步用伪证明，不依赖其可验证性）
SALT="$(head -c 32 /dev/urandom | base64 -w0)"
VERIFIER="$(head -c 256 /dev/urandom | base64 -w0)"

# ---- 1. 起服务 ----
echo "== start server on :$PORT =="
PERSONA_SERVER_DB="$DB" \
PERSONA_SERVER_TOKENS="verify:$TOKEN" \
PERSONA_SERVER_BACKUP_DIR="$TMP/backup" \
PERSONA_SERVER_HOST=127.0.0.1 \
PERSONA_SERVER_PORT="$PORT" \
  "$BIN" >"$TMP/server.log" 2>&1 &
SRV_PID=$!

for _ in $(seq 1 50); do
  if curl -fsS "$BASE/health" >/dev/null 2>&1; then break; fi
  sleep 0.2
done
curl -fsS "$BASE/health" >/dev/null || fail "server 未就绪（见 $TMP/server.log）"
pass "1. /health 存活"

# ---- 2. 注册公开 ----
code="$(curl -sS -o "$TMP/reg.json" -w '%{http_code}' -X POST "$BASE/api/v1/accounts/register" \
  -H 'content-type: application/json' -d '{"username":"verify@example.com"}')"
[ "$code" = "201" ] || [ "$code" = "200" ] || fail "register 期望 2xx，得 $code: $(cat "$TMP/reg.json")"
ACCT="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["account_id"])' "$TMP/reg.json")"
[ -n "$ACCT" ] || fail "register 响应缺 account_id"
pass "2. register 公开，account_id=$ACCT"

api() { # api <method> <path> [bearer] [json-body]
  local m="$1" p="$2" b="${3:-}" d="${4:-}"
  local -a args=(-sS -o "$TMP/last.json" -w '%{http_code}' -X "$m" "$BASE/api/v1/accounts/$p")
  [ -n "$b" ] && args+=(-H "authorization: Bearer $b")
  [ -n "$d" ] && args+=(-H 'content-type: application/json' -d "$d")
  curl "${args[@]}"
}

# ---- 3. 写凭证 fail-closed ----
code="$(api POST "$ACCT/srp/register" "" "{\"salt\":\"$SALT\",\"verifier\":\"$VERIFIER\"}")"
[ "$code" = "401" ] || fail "srp/register 无 Bearer 期望 401，得 $code: $(cat "$TMP/last.json")"
pass "3. srp/register 无 Bearer → 401（写凭证 fail-closed）"

# ---- 4. 持静态令牌写凭证 ----
code="$(api POST "$ACCT/srp/register" "$TOKEN" "{\"device_name\":\"verify-rig\",\"salt\":\"$SALT\",\"verifier\":\"$VERIFIER\"}")"
case "$code" in 2*) ;; *) fail "srp/register 持证期望 2xx，得 $code: $(cat "$TMP/last.json")";; esac
pass "4. srp/register 持静态令牌 → $code"

# ---- 5. 恢复码 gate + 出码 ----
code="$(api POST "$ACCT/recovery-codes" "" '{}')"
[ "$code" = "401" ] || fail "recovery-codes 无 Bearer 期望 401，得 $code"
code="$(api POST "$ACCT/recovery-codes" "$TOKEN" '{}')"
case "$code" in 2*) ;; *) fail "recovery-codes 持证期望 2xx，得 $code: $(cat "$TMP/last.json")";; esac
RC="$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["codes"][0])' "$TMP/last.json")"
[ -n "$RC" ] || fail "恢复码响应缺 codes"
pass "5. recovery-codes 无 Bearer → 401；持证出码"

# ---- 6. 恢复码一次性 ----
code="$(api POST "$ACCT/recovery-codes/verify" "" "{\"code\":\"$RC\"}")"
[ "$code" = "200" ] || fail "恢复码首验期望 200，得 $code: $(cat "$TMP/last.json")"
python3 -c 'import json,sys;assert json.load(open(sys.argv[1]))["success"] is True' "$TMP/last.json" \
  || fail "首验 success != true"
code="$(api POST "$ACCT/recovery-codes/verify" "" "{\"code\":\"$RC\"}")"
python3 -c 'import json,sys;assert json.load(open(sys.argv[1]))["success"] is False' "$TMP/last.json" \
  || fail "复用未作废（success 应为 false）"
pass "6. 恢复码一次性：复用 → success=false"

# ---- 7. challenge 公开 + 真 B ----
code="$(api POST "$ACCT/srp/challenge" "" "{\"device_name\":\"verify-rig\",\"client_public\":\"$(head -c 256 /dev/urandom | base64 -w0)\"}")"
case "$code" in 2*) ;; *) fail "challenge 期望 2xx，得 $code: $(cat "$TMP/last.json")";; esac
python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));assert len(d["server_public"])>100' "$TMP/last.json" \
  || fail "challenge 未返回 server_public"
pass "7. srp/challenge 公开，返回真实 server_public"

# ---- 8. 伪证明拒绝 ----
code="$(api POST "$ACCT/srp/verify" "" \
  "{\"session_id\":\"$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["session_id"])' "$TMP/last.json")\",\"client_proof\":\"$(head -c 64 /dev/urandom | base64 -w0)\"}")"
[ "$code" = "401" ] || fail "伪 M1 期望 401，得 $code: $(cat "$TMP/last.json")"
pass "8. srp/verify 伪证明 → 401"

# ---- 9. sessions 证据语义 ----
code="$(api POST "$ACCT/sessions" "$TOKEN" '{}')"
[ "$code" = "422" ] || fail "sessions 零证据期望 422，得 $code: $(cat "$TMP/last.json")"
code="$(api POST "$ACCT/sessions" "$TOKEN" \
  '{"srp_token":"tok","passkey_assertion":{"id":"x","raw_id":"x","client_data_json":"e30","authenticator_data":"AA","signature":"AA","user_handle":"x"}}')"
[ "$code" = "422" ] || fail "sessions 双证据期望 422，得 $code: $(cat "$TMP/last.json")"
pass "9. sessions 零/双证据均 → 422（恰好一种证据）"

# ---- 10. 家族 gate ----
for spec in "GET $ACCT/devices|" "POST $ACCT/devices|{}" "DELETE $ACCT/devices/dev-x|" "DELETE $ACCT/sessions/tok|"; do
  m="${spec%% *}"; rest="${spec#* }"; p="${rest%%|*}"; d="${rest#*|}"
  code="$(api "$m" "$p" "" "$d")"
  [ "$code" = "401" ] || fail "$m $p 无 Bearer 期望 401，得 $code"
done
pass "10. devices/sessions 全家族无 Bearer → 401"

echo ""
echo "账号侧红线实机勾稽：全部通过（server 日志见 $TMP/server.log，已随 tmp 清理）"
