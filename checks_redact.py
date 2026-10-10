#!/usr/bin/env python3
"""checks_redact.py — device passwords must not leak through GET /api/devices.

Contract:
- ssh_password / luci_pass are NOT returned as plaintext.
- A boolean has_ssh_password / has_luci_pass indicates presence instead.
- The raw value is still usable server-side (device apply paths read from DB).

Run: .venv/bin/python checks_redact.py
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
    owctl.init_db()
    # seed a device with both passwords
    owctl.execute(
        "INSERT INTO devices(id,name,host,access,ssh_password,luci_user,luci_pass) "
        "VALUES(1,'r1','192.168.1.1','ssh','hunter2','root','lucipw')")

    r = client.get("/api/devices")
    check("list: 200", r.status_code == 200, r.text[:200])
    body = r.json()
    dev = body[0] if isinstance(body, list) and body else {}

    check("ssh_password not returned", dev.get("ssh_password") in (None, ""), str(dev.get("ssh_password")))
    check("luci_pass not returned", dev.get("luci_pass") in (None, ""), str(dev.get("luci_pass")))
    check("has_ssh_password flag true", dev.get("has_ssh_password") is True, str(dev.get("has_ssh_password")))
    check("has_luci_pass flag true", dev.get("has_luci_pass") is True, str(dev.get("has_luci_pass")))

    # raw value must still be in the DB (server-side apply paths depend on it)
    row = owctl.q("SELECT ssh_password, luci_pass FROM devices WHERE id=1")
    check("db still has ssh_password", row[0]["ssh_password"] == "hunter2", str(row[0]))
    check("db still has luci_pass", row[0]["luci_pass"] == "lucipw", str(row[0]))

    # a device with no passwords -> flags false
    owctl.execute(
        "INSERT INTO devices(id,name,host,access) VALUES(2,'ap','192.168.1.2','luci')")
    body2 = client.get("/api/devices").json()
    ap = next(d for d in body2 if d["id"] == 2)
    check("no-pass device: has_ssh_password false", ap.get("has_ssh_password") is False, str(ap.get("has_ssh_password")))
    check("no-pass device: has_luci_pass false", ap.get("has_luci_pass") is False, str(ap.get("has_luci_pass")))

    # redaction must not wipe stored creds on update: UI sends empty passwords
    # (redacted values) -> server keeps the existing ones.
    client.put("/api/devices/1", json={
        "name": "r1", "role": "router", "access": "ssh", "ssh_port": 22, "ssh_user": "root",
        "ssh_password": "", "luci_user": "root", "luci_pass": ""})
    row = owctl.q("SELECT ssh_password, luci_pass FROM devices WHERE id=1")
    check("update with empty pw: ssh_password kept", row[0]["ssh_password"] == "hunter2", str(row[0]))
    check("update with empty pw: luci_pass kept", row[0]["luci_pass"] == "lucipw", str(row[0]))

    # a real new value still overwrites
    client.put("/api/devices/1", json={
        "name": "r1", "role": "router", "access": "ssh", "ssh_port": 22, "ssh_user": "root",
        "ssh_password": "newpass123", "luci_user": "root", "luci_pass": ""})
    row = owctl.q("SELECT ssh_password, luci_pass FROM devices WHERE id=1")
    check("update with new pw: overwritten", row[0]["ssh_password"] == "newpass123", str(row[0]))
    check("update with new pw: luci kept", row[0]["luci_pass"] == "lucipw", str(row[0]))

    print(f"\n=== SUMMARY ===\n{sum(1 for _, ok, _ in CHECKS if ok)}/{len(CHECKS)} checks passed")
    failed = [n for n, ok, _ in CHECKS if not ok]
    if failed:
        for n in failed:
            print(" -", n)
        sys.exit(1)
    print("ALL REDACTION CHECKS PASSED")


if __name__ == "__main__":
    main()
