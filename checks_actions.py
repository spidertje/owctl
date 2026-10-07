#!/usr/bin/env python3
"""Action audit log checks for owctl.

Run: .venv/bin/python checks_actions.py
Exits non-zero on any failure.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# (a) import owctl with a temp OWCTL_DATA so we never touch the real DB
tmp = tempfile.mkdtemp()
os.environ["OWCTL_DATA"] = tmp

import owctl  # noqa: E402

CHECKS = []


def check(name, cond, extra=""):
    CHECKS.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


# (b) log_action directly: ok, failed-with-error, missing device
owctl.init_db()
owctl.log_action({"id": 1, "name": "router1"}, "backup", "kind=uci-export", ok=True)
owctl.log_action({"id": 2, "name": "switch1"}, "reboot", "reboot sent", ok=False, error="ssh timeout")
owctl.log_action(None, "upgrade", "packages=all")

rows = owctl.q("SELECT * FROM owctl_actions ORDER BY id")
assert len(rows) == 3, f"expected 3 rows, got {len(rows)}"
r0, r1, r2 = rows
check("ok row result=ok", r0["result"] == "ok", f"got {r0['result']}")
check("ok row device_id/name", r0["device_id"] == 1 and r0["device_name"] == "router1",
      f"id={r0['device_id']} name={r0['device_name']}")
check("ok row action/detail", r0["action"] == "backup" and r0["detail"] == "kind=uci-export",
      f"action={r0['action']} detail={r0['detail']}")
check("ok row error empty", r0["error"] == "", f"error={r0['error']!r}")

check("failed row result=failed", r1["result"] == "failed", f"got {r1['result']}")
check("failed row error text", r1["error"] == "ssh timeout", f"error={r1['error']!r}")

check("missing device row is NULL", r2["device_id"] is None and r2["device_name"] is None,
      f"id={r2['device_id']} name={r2['device_name']}")
check("missing device result=failed", r2["result"] == "failed", f"got {r2['result']}")

# (c) log_action must never raise, even when the DB is unreachable
bad_path = os.path.join(tmp, "nope", "does_not_exist", "owctl.db")
owctl.DB_PATH = bad_path
owctl.DATA_DIR = os.path.dirname(bad_path)
try:
    owctl.log_action({"id": 9, "name": "ghost"}, "reboot", "boom", ok=False, error="x")
    raised = False
except Exception as e:
    raised = True
check("log_action swallows DB error", not raised, "raised" if raised else "ok")

# restore DB path so route check works
owctl.DB_PATH = os.path.join(tmp, "owctl.db")
owctl.DATA_DIR = tmp
owctl.init_db()

# (d) /api/actions route exists in the FastAPI app
routes = [r.path for r in owctl.app.routes]
check("/api/actions route exists", "/api/actions" in routes, f"routes={[r for r in routes if 'action' in r]}")

# also exercise the route via the ASGI app to confirm it is callable and read-only
from fastapi.testclient import TestClient  # noqa: E402
client = TestClient(owctl.app)
resp = client.get("/api/actions?limit=100")
check("/api/actions returns 200", resp.status_code == 200, f"status={resp.status_code}")
if resp.status_code == 200:
    body = resp.json()
    check("/api/actions returns a list", isinstance(body, list), f"type={type(body)}")
    if isinstance(body, list) and len(body) >= 3:
        check("/api/actions newest-first (ts desc)", body[0]["id"] >= body[-1]["id"],
              f"first={body[0]['id']} last={body[-1]['id']}")

print(f"\n{sum(1 for _, ok, _ in CHECKS if ok)}/{len(CHECKS)} checks passed")
failed = [n for n, ok, _ in CHECKS if not ok]
if failed:
    print("FAILURES:", failed)
    sys.exit(1)
print("ALL PASSED")