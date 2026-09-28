#!/usr/bin/env python3
"""Steam Guard 独立参照实现 —— 仅验收用，不引入运行时依赖。

背景：Valve 未发布 Steam Guard 算法的官方测试向量。本脚本是与
`core/src/crypto/steam.rs` **互相独立**的第三份实现（纯 Python stdlib：
hmac/hashlib/struct/base64），语义对齐 ValvePython/steam 的 guard.py
（generate_twofactor_code_for_time）。两侧在同一 (shared_secret, counter)
上出码必须逐字符一致 —— core/src/crypto/steam.rs 的
`code_matches_independent_python_reference_vectors` 测试把本脚本的输出
作为钉死向量，任何一侧漂移都会红灯。

用法：
    python3 scripts/steam_guard_verify.py --secret <base64> --time <unix-seconds>
    python3 scripts/steam_guard_verify.py --secret <base64> --counter <u64>
    python3 scripts/steam_guard_verify.py --vectors   # 打印钉死向量（JSON）

算法（30s 窗、HMAC-SHA1、Steam 26 字符表）：
    counter = unix_time // 30
    hmac = HMAC-SHA1(shared_secret, counter_be_u64)
    start = hmac[19] & 0x0f
    full  = int.from_bytes(hmac[start:start+4], "big") & 0x7fffffff
    code  = "".join(ALPHABET[full % 26], 5 次，每次 full //= 26)
"""

import argparse
import base64
import hashlib
import hmac
import json
import struct
import sys

# 与 core/src/crypto/steam.rs 的 STEAM_CHARS 常量一致（26 字符）
ALPHABET = "23456789BCDFGHJKMNPQRTVWXY"
PERIOD = 30
DIGITS = 5


def steam_guard_from_counter(secret: bytes, counter: int) -> str:
    if not secret:
        raise ValueError("empty shared_secret")
    if not 0 <= counter < 2**64:
        raise ValueError("counter out of u64 range")
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    start = digest[19] & 0x0F
    full = struct.unpack(">I", digest[start : start + 4])[0] & 0x7FFFFFFF
    chars = []
    for _ in range(DIGITS):
        chars.append(ALPHABET[full % 26])
        full //= 26
    return "".join(chars)


def decode_secret(secret_b64: str) -> bytes:
    """标准 base64，容忍空白与 padding 缺省（对齐 decode_steam_secret）。"""
    normalized = "".join(secret_b64.split())
    if not normalized:
        raise ValueError("empty shared_secret")
    padding = "=" * (-len(normalized) % 4)
    return base64.b64decode(normalized + padding)


def steam_guard_from_time(secret_b64: str, unix_time: int) -> str:
    return steam_guard_from_counter(decode_secret(secret_b64), unix_time // PERIOD)


# 钉死向量样本：两组不同长度/填充形态的密钥 × 若干计数器（含 u64 边界）。
# 这些字面量同时出现在本脚本与 steam.rs 的向量测试中 —— 修改任一侧必须
# 用另一侧重跑核对。
VECTOR_SECRETS = {
    # base64(b"0123456789abcdefghij")，20 字节、带 1 个 '=' 填充
    "MDAxMjM0NTY3ODlhYmNkZWZnaGo=": [0, 1, 42, 12345, 2**64 - 1],
    # base64(b"persona-vector-b")，16 字节、带 '==' 填充
    "cGVyc29uYS12ZWN0b3ItYg==": [0, 1, 42, 12345],
}


def vectors() -> list[dict]:
    out = []
    for secret_b64, counters in VECTOR_SECRETS.items():
        for counter in counters:
            out.append(
                {
                    "secret_b64": secret_b64,
                    "counter": counter,
                    "code": steam_guard_from_counter(decode_secret(secret_b64), counter),
                }
            )
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Independent Steam Guard verifier")
    parser.add_argument("--secret", help="Steam shared_secret (standard base64)")
    parser.add_argument("--time", type=int, help="unix timestamp in seconds")
    parser.add_argument("--counter", type=int, help="raw counter (time // 30)")
    parser.add_argument("--vectors", action="store_true", help="print pinned vectors as JSON")
    args = parser.parse_args()

    if args.vectors:
        print(json.dumps(vectors(), indent=2))
        return 0
    if not args.secret:
        parser.error("--secret is required (or use --vectors)")
    if args.counter is not None:
        code = steam_guard_from_counter(decode_secret(args.secret), args.counter)
    elif args.time is not None:
        code = steam_guard_from_time(args.secret, args.time)
    else:
        parser.error("need --counter or --time")
    print(code)
    return 0


if __name__ == "__main__":
    sys.exit(main())
