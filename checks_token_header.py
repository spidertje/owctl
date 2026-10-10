#!/usr/bin/env python3
"""checks_token_header.py — token must be provided via the Authorization header.

Contract:
- Correct Bearer header -> 200.
- Token via ?token= query string -> 401 (no longer accepted).
- Missing -> 401.

Run: .venv/bin/python checks_token_header.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["OWCTL_DATA"] = tempfile.mkdtemp()
# do NOT set OWCTL_ALLOW_OPEN — we want the token enforced here.

import owctl  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

CHECKS = []


def check(name, cond, extra=""):
    CHECKS.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


def main():
    client = TestClient(owctl.app)
    tok = owctl.get_setting("ui_token", "")
    check("a token is in effect", len(tok) >= 32, f"len={len(tok)}")

    r = client.get("/api/settings", headers={"Authorization": f"Bearer {tok}"})
    check("header token: 200", r.status_code == 200, str(r.status_code))

    r = client.get("/api/settings?token=" + tok)
    check("query-string token: 401 (rejected)", r.status_code == 401, str(r.status_code))

    r = client.get("/api/settings")
    check("no token: 401", r.status_code == 401, str(r.status_code))

    print(f"\n=== SUMMARY ===\n{sum(1 for _, ok, _ in CHECKS if ok)}/{len(CHECKS)} checks passed")
    failed = [n for n, ok, _ in CHECKS if not ok]
    if failed:
        for n in failed:
            print(" -", n)
        sys.exit(1)
    print("ALL TOKEN-HEADER CHECKS PASSED")


if __name__ == "__main__":
    main()
