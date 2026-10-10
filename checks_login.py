#!/usr/bin/env python3
"""checks_login.py — dashboard login gate: JS parses + auth contract.

Contract:
- The inline dashboard <script> is syntactically valid JS (node --check).
- index.html ships the gate markup (login-gate, login-form, bootApp).
- The API the gate relies on: /api/network is 401 without a valid token,
  200 with the correct Bearer token, 401 with a wrong token.

Run: .venv/bin/python checks_login.py
"""
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.environ["OWCTL_DATA"] = tempfile.mkdtemp()
os.environ["OWCTL_ALLOW_OPEN"] = ""  # ensure auth is enforced
TOKEN = "checklogin-" + os.urandom(24).hex()
os.environ["OWCTL_TOKEN"] = TOKEN

CHECKS = []


def check(name, cond, extra=""):
    CHECKS.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


def extract_inline_js(html):
    # grab all <script> blocks (inline, no src) and concatenate
    blocks = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.S | re.I)
    return "\n;\n".join(b for b in blocks if b.strip())


def main():
    html = open(os.path.join(HERE, "static", "index.html"), encoding="utf-8").read()

    check("ships #login-gate markup", 'id="login-gate"' in html)
    check("ships login input", 'id="login-token"' in html)
    check("button wired to tryLogin()", 'onclick="tryLogin(' in html)
    check("Enter-to-login wired", "tryLogin(this.value)" in html)
    check("ships bootApp()", "function bootApp()" in html)
    check("main hidden until auth", 'style="display:none"' in html and 'id="tab-network"' in html)
    check("no prompt() token fallback", "prompt('owctl token" not in html)

    js = extract_inline_js(html)
    check("has inline <script>", len(js) > 500, f"{len(js)} chars")
    jsfile = os.path.join(tempfile.mkdtemp(), "dash.js")
    open(jsfile, "w", encoding="utf-8").write(js)
    import subprocess
    r = subprocess.run(["node", "--check", jsfile], capture_output=True, text=True)
    check("inline JS passes `node --check` (valid syntax)", r.returncode == 0, (r.stderr or r.stdout).strip()[:300])

    # --- runtime API contract the gate depends on ---
    from starlette.testclient import TestClient
    import owctl
    client = TestClient(owctl.app)

    st = client.get("/api/network")
    check("no token -> 401", st.status_code == 401, f"got {st.status_code}")

    wrong = client.get("/api/network", headers={"Authorization": "***"})
    check("wrong token -> 401", wrong.status_code == 401, f"got {wrong.status_code}")

    ok = client.get("/api/network", headers={"Authorization": f"Bearer {TOKEN}"})
    check("valid token -> 200", ok.status_code == 200, f"got {ok.status_code}")

    print(f"\n=== SUMMARY ===\n{sum(1 for _, ok, _ in CHECKS if ok)}/{len(CHECKS)} checks passed")
    failed = [n for n, ok, _ in CHECKS if not ok]
    if failed:
        for n in failed:
            print(" -", n)
        sys.exit(1)
    print("ALL LOGIN CHECKS PASSED")


if __name__ == "__main__":
    main()
