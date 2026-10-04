#!/usr/bin/env bash
# 同步组配对中转（S1）实机勾稽：起真实 persona-server 进程，curl 走
# /api/v1/pairing/* 信箱全流程。协议数学（SRP/短码/指纹）由 core 单测与
# server 进程内端到端测试锁定（server/src/api/pairing.rs 的
# pairing_relay_drives_real_core_protocol_end_to_end）；本脚本验证的是
# 进程/路由/migration/信箱消费语义在真实 wire 上成立。
#
# 断言清单：
#   1. /health 存活
#   2. 建会话（带 salt）→ 201 + session_id + TTL
#   3. GET 会话元信息 → salt 回读一致 + 队列长度 0
#   4. to-host 投递 2 条 → GET 即消费（读回 2 条、再读为空）
#   5. to-guest 同款（GET 顺序 = 投递顺序）
#   6. 队列满（4 条）→ 第 5 条 422
#   7. 未知 session → 404；坏 base64 → 422；超限 payload → 422
#   8. DELETE → 204，随后 GET 404；重复 DELETE 幂等 204
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d /tmp/persona-pairing-verify.XXXXXX)"
PORT="${PERSONA_VERIFY_PORT:-18994}"
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

b64() { base64 -w0; }

echo "== build persona-server =="
cargo build --manifest-path "$REPO/server/Cargo.toml" --quiet
BIN="$REPO/target/debug/persona-server"
[ -x "$BIN" ] || fail "server 二进制不存在: $BIN"

echo "== start server on :$PORT =="
PERSONA_SERVER_DB="$TMP/verify.db" \
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

PAIR="$BASE/api/v1/pairing"

# ---- 2. 建会话 ----
code="$(curl -sS -o "$TMP/s.json" -w '%{http_code}' -X POST "$PAIR/sessions" \
  -H 'content-type: application/json' -d "{\"salt\":\"$(head -c 16 /dev/urandom | base64 -w0)\"}")"
[ "$code" = "201" ] || fail "建会话期望 201，得 $code: $(cat "$TMP/s.json")"
SID="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["session_id"])' "$TMP/s.json")"
TTL="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["expires_in_secs"])' "$TMP/s.json")"
[ "$TTL" = "600" ] || fail "TTL 期望 600，得 $TTL"
pass "2. 建会话 201，session_id=$SID，TTL=600s"

# ---- 3. 元信息回读 salt（用确定 salt 再建一个会话验证回读） ----
FIXED_SALT="AAAAAAAAAAAAAAAAAAAAAA=="  # 16 字节 0 的 base64
code="$(curl -sS -o "$TMP/s2.json" -w '%{http_code}' -X POST "$PAIR/sessions" \
  -H 'content-type: application/json' -d "{\"salt\":\"$FIXED_SALT\"}")"
[ "$code" = "201" ] || fail "建定盐会话期望 201，得 $code"
SID2="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["session_id"])' "$TMP/s2.json")"
code="$(curl -sS -o "$TMP/info.json" -w '%{http_code}' "$PAIR/sessions/$SID2")"
[ "$code" = "200" ] || fail "元信息期望 200，得 $code"
GOT_SALT="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["salt"])' "$TMP/info.json")"
[ "$GOT_SALT" = "$FIXED_SALT" ] || fail "salt 回读不一致: $GOT_SALT"
LEN="$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d["to_host_len"],d["to_guest_len"])' "$TMP/info.json")"
[ "$LEN" = "0 0" ] || fail "初始队列长度应为 0 0，得 $LEN"
pass "3. GET 元信息：salt 回读一致，队列初始 0 0"

# ---- 4/5. 双向信箱 GET 即消费 ----
for direction in to-host to-guest; do
  for i in 1 2; do
    payload="$(printf "msg-%s-%s" "$direction" "$i" | base64 -w0)"
    code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST \
      "$PAIR/sessions/$SID/messages/$direction" \
      -H 'content-type: application/json' -d "{\"payload\":\"$payload\"}")"
    [ "$code" = "202" ] || fail "$direction 投递 $i 期望 202，得 $code"
  done
  read_count="$(curl -sS "$PAIR/sessions/$SID/messages/$direction" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["messages"]))')"
  [ "$read_count" = "2" ] || fail "$direction 首读期望 2 条，得 $read_count"
  read_count="$(curl -sS "$PAIR/sessions/$SID/messages/$direction" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["messages"]))')"
  [ "$read_count" = "0" ] || fail "$direction 再读应为空，得 $read_count"
done
pass "4/5. to-host/to-guest 各投 2 条：GET 即消费，读后为空"

# ---- 6. 队列满 ----
for i in 1 2 3 4; do
  curl -sS -o /dev/null -X POST "$PAIR/sessions/$SID/messages/to-host" \
    -H 'content-type: application/json' -d "{\"payload\":\"$(printf "q%s" "$i" | base64 -w0)\"}"
done
code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$PAIR/sessions/$SID/messages/to-host" \
  -H 'content-type: application/json' -d '{"payload":"dw=="}')"
[ "$code" = "422" ] || fail "队列满期望 422，得 $code"
pass "6. 单方向队列上限 4：第 5 条 → 422"

# ---- 7. 边界：404 / 坏 base64 / 超限 payload ----
code="$(curl -sS -o /dev/null -w '%{http_code}' "$PAIR/sessions/no-such-session")"
[ "$code" = "404" ] || fail "未知会话期望 404，得 $code"
code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$PAIR/sessions/$SID/messages/to-host" \
  -H 'content-type: application/json' -d '{"payload":"!!!bad!!!"}')"
[ "$code" = "422" ] || fail "坏 base64 期望 422，得 $code"
BIG="$(head -c 5000 /dev/zero | base64 -w0)"
code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$PAIR/sessions/$SID/messages/to-host" \
  -H 'content-type: application/json' -d "{\"payload\":\"$BIG\"}")"
[ "$code" = "422" ] || fail "超限 payload 期望 422，得 $code"
pass "7. 未知会话 404；坏 base64 422；超限 payload 422"

# ---- 8. DELETE 语义 ----
code="$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE "$PAIR/sessions/$SID2")"
[ "$code" = "204" ] || fail "DELETE 期望 204，得 $code"
code="$(curl -sS -o /dev/null -w '%{http_code}' "$PAIR/sessions/$SID2")"
[ "$code" = "404" ] || fail "删除后 GET 期望 404，得 $code"
code="$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE "$PAIR/sessions/$SID2")"
[ "$code" = "204" ] || fail "重复 DELETE 应幂等 204，得 $code"
pass "8. DELETE → 204；随后 GET 404；重复 DELETE 幂等"

echo ""
echo "同步组配对中转实机勾稽：全部通过"
