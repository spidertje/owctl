#!/usr/bin/env python3
"""checks_auth_setup.py — first-boot "set admin password + confirm" flow.

Contract:
- GET /api/auth/status: needs_setup True on a fresh instance, False once a
  password is set.
- POST /api/auth/setup:
    * password == confirm, len >= 4  -> 200 + session (logged in as admin).
    * mismatch                       -> 400 "do not match".
    * too short (< 4)                -> 400.
    * after setup, a second call     -> 409 (already set).
- After setup, normal /api/auth/login works with the chosen password.
- The dashboard ships the confirm field + setup-mode JS (node --check valid).

Run: .venv/bin/python checks_auth_setup.py
"""
import os
import re
import sys
import tempfile
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.environ["OWCTL_DATA"] = tempfile.mkdtemp()
os.environ.pop("OWCTL_TOKEN", None)
os.environ.pop("OWCTL_ALLOW_OPEN", None)

CHECKS = []


def check(name, cond, extra=""):
    CHECKS.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


def extract_inline_js(html):
    blocks = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.S | re.I)
    return "\n;\n".join(b for b in blocks if b.strip())


def main():
    from starlette.testclient import TestClient
    import owctl
    c = TestClient(owctl.app)

    # status: fresh -> needs setup
    st = c.get("/api/auth/status")
    check("status -> needs_setup True on fresh instance", st.status_code == 200 and st.json().get("needs_setup") is True,
          f"{st.status_code} {st.text[:80]}")

    # setup: mismatch -> 400
    bad = c.post("/api/auth/setup", json={"password": "abcd", "confirm": "wxyz"})
    check("setup mismatch -> 400", bad.status_code == 400, f"{bad.status_code} {bad.text[:80]}")
    check("setup mismatch -> message about match", "match" in bad.json().get("detail", "").lower(), bad.json().get("detail", ""))

    # setup: too short -> 400
    short = c.post("/api/auth/setup", json={"password": "ab", "confirm": "ab"})
    check("setup too-short -> 400", short.status_code == 400, f"{short.status_code} {short.text[:80]}")

    # setup: correct -> 200 + session
    good = c.post("/api/auth/setup", json={"password": "hunter2", "confirm": "hunter2"})
    gj = good.json()
    check("setup ok -> 200 + session", good.status_code == 200 and "session" in gj, f"{good.status_code} {good.text[:80]}")
    check("setup ok -> role admin", gj.get("role") == "admin", gj.get("role", ""))

    # status: now -> needs_setup False
    st2 = c.get("/api/auth/status")
    check("status -> needs_setup False after setup", st2.json().get("needs_setup") is False, st2.text[:80])

    # second setup -> 409
    dup = c.post("/api/auth/setup", json={"password": "other4", "confirm": "other4"})
    check("second setup -> 409", dup.status_code == 409, f"{dup.status_code} {dup.text[:80]}")

    # login with the chosen password works
    lg = c.post("/api/auth/login", json={"username": "admin", "password": "hunter2"})
    check("login with setup password -> 200", lg.status_code == 200 and "session" in lg.json(), f"{lg.status_code} {lg.text[:80]}")
    lgw = c.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    check("login wrong password -> 401", lgw.status_code == 401, f"{lgw.status_code}")

    # --- dashboard ships the confirm field + setup JS ---
    html = open(os.path.join(HERE, "static", "index.html"), encoding="utf-8").read()
    check("ships #login-confirm field", 'id="login-confirm"' in html)
    check("setup mode calls /api/auth/setup", "/api/auth/setup" in html)
    check("setup mode reads /api/auth/status", "/api/auth/status" in html)
    check("has _setupFields / _loginFields", "_setupFields" in html and "_loginFields" in html)

    js = extract_inline_js(html)
    jsfile = os.path.join(tempfile.mkdtemp(), "dash.js")
    open(jsfile, "w", encoding="utf-8").write(js)
    r = subprocess.run(["node", "--check", jsfile], capture_output=True, text=True)
    check("inline JS passes `node --check` (valid syntax)", r.returncode == 0, (r.stderr or r.stdout).strip()[:300])

    print(f"\n=== SUMMARY ===\n{sum(1 for _, ok, _ in CHECKS if ok)}/{len(CHECKS)} checks passed")
    failed = [n for n, ok, _ in CHECKS if not ok]
    if failed:
        for n in failed:
            print(" -", n)
        sys.exit(1)
    print("ALL AUTH-SETUP CHECKS PASSED")


if __name__ == "__main__":
    main()
