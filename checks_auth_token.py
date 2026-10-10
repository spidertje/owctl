#!/usr/bin/env python3
"""checks_auth_token.py — token auto-generation on first boot.

Contract:
- If OWCTL_TOKEN env var is set -> that token is authoritative, no DB write.
- Else if a ui_token setting already exists -> reuse it (idempotent, no regen).
- Else generate a fresh >=32-char token, persist in settings, report generated=True.

Run: .venv/bin/python checks_auth_token.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["OWCTL_DATA"] = tempfile.mkdtemp()

CHECKS = []


def check(name, cond, extra=""):
    CHECKS.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


def main():
    import owctl
    owctl.init_db()

    # 1) env var wins
    os.environ["OWCTL_TOKEN"] = "env-token-abcdef"
    tok, generated = owctl.ensure_auth_token()
    check("env: token honored", tok == "env-token-abcdef", repr(tok))
    check("env: not generated", generated is False, repr(generated))
    del os.environ["OWCTL_TOKEN"]

    # 2) startup (at import) auto-generated a token for an empty db -> it is persisted.
    #    (Generation runs once at module import / app startup, before this point.)
    stored = owctl.get_setting("ui_token", "")
    check("first boot: token auto-generated + persisted", len(stored) >= 32, f"len={len(stored)}")

    # 3) idempotent: ensure_auth_token reuses the stored token, does not regenerate
    tok3, generated3 = owctl.ensure_auth_token()
    check("reuse: same token as stored", tok3 == stored, f"{tok3[:8]} vs {stored[:8]}")
    check("reuse: not generated", generated3 is False, repr(generated3))

    # 4) token guard accepts the generated token, rejects others
    from fastapi.testclient import TestClient
    client = TestClient(owctl.app)
    r = client.get("/api/settings", headers={"Authorization": f"Bearer {stored}"})
    check("guard: generated token accepted", r.status_code == 200, str(r.status_code))
    r2 = client.get("/api/settings", headers={"Authorization": "Bearer wrong"})
    check("guard: wrong token rejected", r2.status_code == 401, str(r2.status_code))
    r3 = client.get("/api/settings")
    check("guard: missing token rejected", r3.status_code == 401, str(r3.status_code))

    print(f"\n=== SUMMARY ===\n{sum(1 for _, ok, _ in CHECKS if ok)}/{len(CHECKS)} checks passed")
    failed = [n for n, ok, _ in CHECKS if not ok]
    if failed:
        for n in failed:
            print(" -", n)
        sys.exit(1)
    print("ALL AUTH-TOKEN CHECKS PASSED")


if __name__ == "__main__":
    main()
