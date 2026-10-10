#!/usr/bin/env python3
"""checks_headers.py — security response headers on API + static responses.

Contract: every response carries X-Content-Type-Options=nosniff,
X-Frame-Options=DENY, and Referrer-Policy.

Run: .venv/bin/python checks_headers.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["OWCTL_DATA"] = tempfile.mkdtemp()
os.environ["OWCTL_ALLOW_OPEN"] = "1"

import owctl  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

CHECKS = []


def check(name, cond, extra=""):
    CHECKS.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


def main():
    client = TestClient(owctl.app)
    for path in ["/", "/api/settings"]:
        r = client.get(path)
        h = r.headers
        check(f"{path}: nosniff", h.get("x-content-type-options", "").lower() == "nosniff", str(h.get("x-content-type-options")))
        check(f"{path}: x-frame-options deny", h.get("x-frame-options", "").upper() == "DENY", str(h.get("x-frame-options")))
        check(f"{path}: referrer-policy", bool(h.get("referrer-policy")), str(h.get("referrer-policy")))

    print(f"\n=== SUMMARY ===\n{sum(1 for _, ok, _ in CHECKS if ok)}/{len(CHECKS)} checks passed")
    failed = [n for n, ok, _ in CHECKS if not ok]
    if failed:
        for n in failed:
            print(" -", n)
        sys.exit(1)
    print("ALL SECURITY-HEADER CHECKS PASSED")


if __name__ == "__main__":
    main()
