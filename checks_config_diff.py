#!/usr/bin/env python3
"""checks_config_diff.py — validate config-history diff view feature.

Asserts:
  1. diff_snapshots('a\nb\n','a\nx\n') contains the minus-b and plus-x lines.
  2. The /api/devices/{did}/config-history endpoint with ?from=&to= returns
     a 'diff' key containing the expected unified-diff change.
  3. The endpoint WITHOUT from/to still returns the unchanged list shape.
"""
import os
import sys
import tempfile

_tmp = tempfile.mkdtemp(prefix="owctl-cfgdiff-")
os.environ["OWCTL_DATA"] = os.path.join(_tmp, "data")
os.environ.setdefault("OWCTL_ALLOW_OPEN", "1")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import owctl  # noqa: E402
import importlib
importlib.reload(owctl)
owctl.init_db()  # ensure DB schema exists (fresh DB per run)
from starlette.testclient import TestClient

PASS = FAIL = 0


def check(label, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {label}")
    else:
        FAIL += 1
        print(f"FAIL {label} :: {detail}")


# ---- 1. pure helper test ----
helper_out = owctl.diff_snapshots("a\nb\n", "a\nx\n")
check("diff_snapshots contains -b line", "-b" in helper_out, f"got: {helper_out!r}")
check("diff_snapshots contains +x line", "+x" in helper_out, f"got: {helper_out!r}")


# ---- 2. end-to-end: endpoint with from/to ----
owctl.execute("DELETE FROM devices WHERE host='diff-test-ck'")
owctl.execute(
    "INSERT INTO devices(name, host, access, added_at) VALUES(?,?,?,?)",
    ("diff-test-ck", "192.0.2.99", "ssh", owctl.now()),
)
dev = owctl.q("SELECT * FROM devices WHERE host='192.0.2.99'")[0]

# Seed config_history with two snapshots (network unchanged, firewall changed)
owctl.execute(
    "INSERT INTO config_history(device_id, ts, hash) VALUES(?,?,?)",
    (dev["id"], "2026-01-01 00:00:00.000", "/etc/config/network=aaaa0001;/etc/config/firewall=bbbb0002"),
)
owctl.execute(
    "INSERT INTO config_history(device_id, ts, hash) VALUES(?,?,?)",
    (dev["id"], "2026-01-02 00:00:00.000", "/etc/config/network=aaaa0001;/etc/config/firewall=cccc0003"),
)

client = TestClient(owctl.app)

# --- Style A: ?from=<id>&to=<id> (spec param names) ---
# Get the actual snapshot ids
snap_a = owctl.q("SELECT id FROM config_history WHERE device_id=? ORDER BY ts ASC", (dev["id"],))[0]
snap_b = owctl.q("SELECT id FROM config_history WHERE device_id=? ORDER BY ts DESC", (dev["id"],))[0]
r = client.get(f"/api/devices/{dev['id']}/config-history?from={snap_a['id']}&to={snap_b['id']}")
check("config-history ?from&to returns 200", r.status_code == 200, f"status={r.status_code}")
if r.status_code == 200:
    j = r.json()
    check("response is a dict", isinstance(j, dict), f"got type={type(j).__name__}")
    if isinstance(j, dict):
        check("response has 'diff' key", "diff" in j, f"keys={list(j.keys())}")
        check("response has 'from' key", "from" in j, f"keys={list(j.keys())}")
        check("response has 'to' key", "to" in j, f"keys={list(j.keys())}")
        if "diff" in j:
            d = j["diff"]
            check("diff is a non-empty string", isinstance(d, str) and len(d) > 0, f"diff={d!r}")
            check("diff has --- old header", "--- old" in d, f"diff={d[:200]!r}")
            check("diff has +++ new header", "+++ new" in d, f"diff={d[:200]!r}")
            # The firewall hash changed from bbbb0002 to cccc0003 — both must appear
            check("diff contains old hash bbbb0002", "bbbb0002" in d, f"diff={d[:200]!r}")
            check("diff contains new hash cccc0003", "cccc0003" in d, f"diff={d[:200]!r}")

# --- Style B: ?from_=<id>&to_=<id> (Python-safe alias) ---
r2 = client.get(f"/api/devices/{dev['id']}/config-history?from_={snap_a['id']}&to_={snap_b['id']}")
check("config-history ?from_&to_ returns 200", r2.status_code == 200, f"status={r2.status_code}")
if r2.status_code == 200:
    j2 = r2.json()
    check("from_/to_ response is a dict with diff", isinstance(j2, dict) and "diff" in j2, f"type={type(j2).__name__} keys={list(j2.keys()) if isinstance(j2, dict) else 'N/A'}")

# --- Style C: ISO timestamp values ---
ts_a = "2026-01-01 00:00:00.000"
ts_b = "2026-01-02 00:00:00.000"
r3 = client.get(f"/api/devices/{dev['id']}/config-history?from={ts_a}&to={ts_b}")
check("config-history ?from=<ts>&to=<ts> returns 200", r3.status_code == 200, f"status={r3.status_code}")
if r3.status_code == 200:
    j3 = r3.json()
    check("ts-based response is a dict with diff", isinstance(j3, dict) and "diff" in j3, f"type={type(j3).__name__}")


# ---- 3. endpoint WITHOUT from/to returns list shape ----
r4 = client.get(f"/api/devices/{dev['id']}/config-history")
check("config-history without from/to returns 200", r4.status_code == 200, f"status={r4.status_code}")
if r4.status_code == 200:
    j4 = r4.json()
    check("response is a list", isinstance(j4, list), f"got type={type(j4).__name__}")
    check("list has 2 entries", len(j4) == 2, f"got {len(j4)}")
    if isinstance(j4, list) and len(j4) >= 1:
        check("entry has 'ts' key", "ts" in j4[0], f"first={j4[0]!r}")
        check("entry has 'files' key", "files" in j4[0], f"first={j4[0]!r}")


print()
print(f"Results: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
