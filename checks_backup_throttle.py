#!/usr/bin/env python3
"""checks_backup_throttle.py — scheduler DB-backup throttle regression guard.

Contract (audit P2, LOW): _db_backup() ran VACUUM INTO on EVERY scheduler
cycle (default 30 min) while keeping only 14 copies — the retention window
was ~7 hours of history. Scheduler-driven snapshots are now throttled to one
per BACKUP_MIN_INTERVAL_S (1h); manual /api/backup (force=True) is never
throttled. This check proves:
  - first backup runs (not skipped);
  - an immediate second scheduler-driven call is SKIPPED (no new snapshot);
  - after the interval elapses it runs again;
  - force=True always runs, even immediately after a fresh backup.
Run: .venv/bin/python checks_backup_throttle.py
"""
import os, sys, time, tempfile

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
os.environ["OWCTL_DATA"] = tempfile.mkdtemp()
os.environ["OWCTL_ALLOW_OPEN"] = "1"

import owctl  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

FAILS = 0
def check(name, ok, detail=""):
    global FAILS
    if not ok:
        FAILS += 1
    print(("PASS " if ok else "FAIL ") + name + (f" :: {detail}" if detail and not ok else ""))

owctl.init_db()
owctl.execute("INSERT INTO settings(key,value) VALUES('k1','v1')")
owctl._last_backup_at = 0.0
client = TestClient(owctl.app)
BD = owctl.BACKUP_DIR

def last_path():
    ps = [os.path.join(BD, f) for f in os.listdir(BD) if f.startswith("owctl-db-")]
    return sorted(ps)[-1] if ps else None

# 1) first scheduler-driven backup runs
r1 = owctl._db_backup()
check("first backup runs", r1.get("ok") and not r1.get("skipped") and os.path.exists(r1.get("path", "")), f"{r1}")
p1 = r1.get("path")

# 2) immediate second scheduler-driven call is throttled (no new file written)
r2 = owctl._db_backup()
check("immediate 2nd backup skipped (throttled)", r2.get("ok") and r2.get("skipped") is True and "path" not in r2, f"{r2}")

# 3) after the interval elapses it runs again
owctl._last_backup_at = time.time() - owctl.BACKUP_MIN_INTERVAL_S - 1
r3 = owctl._db_backup()
check("after interval: backup runs again", r3.get("ok") and not r3.get("skipped") and os.path.exists(r3.get("path", "")), f"{r3}")

# 4) force=True bypasses the throttle even immediately after a fresh backup
owctl._last_backup_at = time.time()  # pretend a backup JUST happened
r4 = owctl._db_backup(force=True)
check("force=True always runs", r4.get("ok") and not r4.get("skipped") and os.path.exists(r4.get("path", "")), f"{r4}")

# 5) manual /api/backup endpoint is force (admin-gated; open mode here)
r5 = client.post("/api/backup")
check("POST /api/backup succeeds (200)", r5.status_code == 200, f"status={r5.status_code} {r5.text[:120]}")

# 6) the most recent backup is a valid readable sqlite DB (VACUUM INTO integrity)
import sqlite3
last = last_path()
check("a backup file exists", last is not None and os.path.exists(last), str(last))
if last:
    with sqlite3.connect(last) as c:
        probe = c.execute("SELECT value FROM settings WHERE key='k1'").fetchone()
    check("snapshot is a valid DB with the data", probe and probe[0] == "v1", f"{probe}")

# 7) the throttle constant is a sane 1-hour window
check("BACKUP_MIN_INTERVAL_S is 1h", owctl.BACKUP_MIN_INTERVAL_S == 3600, str(owctl.BACKUP_MIN_INTERVAL_S))

print()
if FAILS:
    print(f"=== {FAILS} check(s) FAILED ===")
    sys.exit(1)
print("8/8 checks passed")
print("ALL BACKUP-THROTTLE CHECKS PASSED")
