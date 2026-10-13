# Copyright (C) 2026 spidertje
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#!/usr/bin/env python3
"""checks_api_audit.py — audit log for mutating API requests.

Contract:
- POST/PUT/DELETE on /api/* are recorded (method, path, client ip, ts, status).
- GET/HEAD are NOT recorded (read-only, low signal).
- Recent entries are readable via GET /api/audit/api.

Run: .venv/bin/python checks_api_audit.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["OWCTL_DATA"] = tempfile.mkdtemp()
os.environ["OWCTL_ALLOW_OPEN"] = "1"
os.environ.pop("OWCTL_RATELIMIT_MAX", None)

import owctl  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

CHECKS = []


def check(name, cond, extra=""):
    CHECKS.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


def main():
    client = TestClient(owctl.app)
    owctl.init_db()

    # seed a device so a PUT works
    owctl.execute("INSERT INTO devices(id,name,host,access) VALUES(1,'r1','192.168.1.1','ssh')")

    # read-only GET should not be logged
    client.get("/api/devices")

    # mutating requests should be logged
    client.put("/api/devices/1", json={"name": "r1", "access": "ssh"})
    client.post("/api/settings", json={})  # logs the attempt regardless of status

    # read via the endpoint: returns {"entries": [ {method, path, client, ts, status} ]}
    r = client.get("/api/audit/api")
    check("audit endpoint: 200", r.status_code == 200, str(r.status_code))
    log = r.json().get("entries", []) if isinstance(r.json(), dict) else r.json()
    check("audit: has entries", len(log) >= 1, f"len={len(log)}")

    methods = {e.get("method") for e in log}
    check("audit: PUT recorded", "PUT" in methods, str(methods))
    check("audit: no GET recorded", "GET" not in methods, str(methods))
    entry = next(e for e in log if e.get("method") == "PUT")
    check("audit: path recorded", "/api/devices/1" in (entry.get("path") or ""), str(entry))
    check("audit: has timestamp", bool(entry.get("ts")), str(entry))
    check("audit: has client key", bool(entry.get("client")), str(entry))

    print(f"\n=== SUMMARY ===\n{sum(1 for _, ok, _ in CHECKS if ok)}/{len(CHECKS)} checks passed")
    failed = [n for n, ok, _ in CHECKS if not ok]
    if failed:
        for n in failed:
            print(" -", n)
        sys.exit(1)
    print("ALL API-AUDIT CHECKS PASSED")


if __name__ == "__main__":
    main()
