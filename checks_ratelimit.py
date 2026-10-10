#!/usr/bin/env python3
"""checks_ratelimit.py — per-IP rate limiting on /api.

Contract:
- Within the limit -> 200.
- Exceeding the limit -> 429 with a Retry-After header.
- Limit is configurable (OWCTL_RATELIMIT_MAX / OWCTL_RATELIMIT_WINDOW).
- Different "IPs" (client host) get independent budgets.

Run: .venv/bin/python checks_ratelimit.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["OWCTL_DATA"] = tempfile.mkdtemp()
os.environ["OWCTL_ALLOW_OPEN"] = "1"   # test the limiter, not auth
os.environ["OWCTL_RATELIMIT_MAX"] = "5"
os.environ["OWCTL_RATELIMIT_WINDOW"] = "60"

import owctl  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

CHECKS = []


def check(name, cond, extra=""):
    CHECKS.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


def main():
    client = TestClient(owctl.app)

    # 5 allowed within the window
    codes = [client.get("/api/settings").status_code for _ in range(5)]
    check("within limit: all 200", all(c == 200 for c in codes), str(codes))

    # 6th -> 429 with Retry-After
    r = client.get("/api/settings")
    check("over limit: 429", r.status_code == 429, str(r.status_code))
    check("over limit: Retry-After header", "retry-after" in {k.lower() for k in r.headers}, str(dict(r.headers)))

    # a different client (different host) is NOT blocked
    r2 = client.get("/api/settings", headers={"X-Forwarded-For": "10.0.0.99"})
    check("different IP: still 200", r2.status_code == 200, str(r2.status_code))

    print(f"\n=== SUMMARY ===\n{sum(1 for _, ok, _ in CHECKS if ok)}/{len(CHECKS)} checks passed")
    failed = [n for n, ok, _ in CHECKS if not ok]
    if failed:
        for n in failed:
            print(" -", n)
        sys.exit(1)
    print("ALL RATE-LIMIT CHECKS PASSED")


if __name__ == "__main__":
    main()
