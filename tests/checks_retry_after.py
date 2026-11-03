#!/usr/bin/env python3
"""checks_retry_after.py — 429 responses carry a Retry-After header AND a
retry_after field in the JSON body.

Scoping: the global policy (OWCTL_RATELIMIT_MAX/WINDOW, default 120/60) is left
untouched. This check swaps in a throwaway _RateLimiter instance with a tiny
limit (2) so the 429 is forced without disturbing the shared limiter used by
every other check.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["OWCTL_DATA"] = tempfile.mkdtemp()
os.environ["OWCTL_ALLOW_OPEN"] = "1"

import owctl  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

CHECKS = []


def check(name, cond, extra=""):
    CHECKS.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


def main():
    # Throwaway limiter: 2 requests per 60s window, keyed on real TCP addr.
    owctl._rate_limiter = owctl._RateLimiter(limit=2, window=60)
    client = TestClient(owctl.app)

    codes = [client.get("/api/settings").status_code for _ in range(2)]
    check("throwaway budget: 200 x2", all(c == 200 for c in codes), str(codes))

    r = client.get("/api/settings")
    check("over budget: 429", r.status_code == 429, str(r.status_code))
    check("Retry-After header present", "retry-after" in {k.lower() for k in r.headers}, str(dict(r.headers)))
    try:
        body = r.json()
    except Exception as e:  # noqa: BLE001
        body = None
        check("body is JSON", False, str(e))
    if body is not None:
        check("body has retry_after field", "retry_after" in body, str(body))
        check("body has retry_after int >= 1",
              isinstance(body.get("retry_after"), int) and body["retry_after"] >= 1,
              str(body))
        check("Retry-After header == body.retry_after",
              r.headers.get("retry-after") == str(body.get("retry_after")),
              f"header={r.headers.get('retry-after')} body={body.get('retry_after')}")

    # Restore the real limiter so the global policy is unchanged.
    owctl._rate_limiter = owctl._RateLimiter(
        int(os.environ.get("OWCTL_RATELIMIT_MAX", "120")),
        int(os.environ.get("OWCTL_RATELIMIT_WINDOW", "60")),
    )

    print(f"\n=== SUMMARY ===\n{sum(1 for _, ok, _ in CHECKS if ok)}/{len(CHECKS)} checks passed")
    failed = [n for n, ok, _ in CHECKS if not ok]
    if failed:
        for n in failed:
            print(" -", n)
        sys.exit(1)
    print("ALL RETRY-AFTER CHECKS PASSED")


if __name__ == "__main__":
    main()