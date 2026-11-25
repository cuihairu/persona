#!/usr/bin/env python3
"""Standalone Steam Guard reference implementation — for acceptance only, no runtime dependency.

Background: Valve never published official test vectors for the Steam Guard
algorithm. This script is a third implementation **mutually independent** from
`core/src/crypto/steam.rs` (pure Python stdlib: hmac/hashlib/struct/base64),
semantically aligned with ValvePython/steam's guard.py
(generate_twofactor_code_for_time). Both sides must produce character-identical
codes for the same (shared_secret, counter) — the
`code_matches_independent_python_reference_vectors` test in core/src/crypto/steam.rs
pins this script's output as the reference vectors, so any drift on either side
lights up red.

Usage:
    python3 scripts/steam_guard_verify.py --secret <base64> --time <unix-seconds>
    python3 scripts/steam_guard_verify.py --secret <base64> --counter <u64>
    python3 scripts/steam_guard_verify.py --vectors   # print the pinned vectors (JSON)

Algorithm (30s window, HMAC-SHA1, Steam's 26-character alphabet):
    counter = unix_time // 30
    hmac = HMAC-SHA1(shared_secret, counter_be_u64)
    start = hmac[19] & 0x0f
    full  = int.from_bytes(hmac[start:start+4], "big") & 0x7fffffff
    code  = "".join(ALPHABET[full % 26], 5 times, dividing full //= 26 each time)
"""

import argparse
import base64
import hashlib
import hmac
import json
import struct
import sys

# Matches the STEAM_CHARS constant in core/src/crypto/steam.rs (26 characters)
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
    """Standard base64, tolerant of whitespace and omitted padding (aligned with decode_steam_secret)."""
    normalized = "".join(secret_b64.split())
    if not normalized:
        raise ValueError("empty shared_secret")
    padding = "=" * (-len(normalized) % 4)
    return base64.b64decode(normalized + padding)


def steam_guard_from_time(secret_b64: str, unix_time: int) -> str:
    return steam_guard_from_counter(decode_secret(secret_b64), unix_time // PERIOD)


# Pinned-vector samples: two keys of different lengths/padding forms × several
# counters (including the u64 boundary). These literals appear both here and in
# steam.rs's vector tests — a change on either side must be re-verified by
# re-running the other.
VECTOR_SECRETS = {
    # base64(b"0123456789abcdefghij"), 20 bytes with 1 '=' padding
    "MDAxMjM0NTY3ODlhYmNkZWZnaGo=": [0, 1, 42, 12345, 2**64 - 1],
    # base64(b"persona-vector-b"), 16 bytes with '==' padding
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
