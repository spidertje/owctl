#!/usr/bin/env python3
"""checks_config_diff.py — validate config-history diff view feature.

Asserts:
  1. diff_snapshots('a\nb\n','a\nx\n') contains the minus-b and plus-x lines.
  2. The /api/devices/{did}/config-history endpoint with from/to params returns
     a 'diff' key containing the expected change.
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
# Fresh DB per run - seed a device
owctl.execute("DELETE FROM devices WHERE host='diff-test-ck'")
owctl.execute(
    "INSERT INTO devices(name, host, access, added_at) VALUES(?,?,?,?)",
    ("diff-test-ck", "192.0.2.99", "ssh", owctl.now()),
)
dev = owctl.q("SELECT * FROM devices WHERE host='192.0.2.99'")[0]

# Seed config_history with two snapshots
owctl.execute(
    "INSERT INTO config_history(device_id, ts, hash) VALUES(?,?,?)",
    (dev["id"], "2026-01-01 00:00:00.000", "/etc/config/network=aaaa0001;/etc/config/firewall=bbbb0002"),
)
owctl.execute(
    "INSERT INTO config_history(device_id, ts, hash) VALUES(?,?,?)",
    (dev["id"], "2026-01-02 00:00:00.000", "/etc/config/network=aaaa0001;/etc/config/firewall=cccc0003"),
)

client = TestClient(owctl.app)

# Test both param styles. The function signature uses from_/to (underscored)
# to avoid Python keyword conflict, but FastAPI may map differently.

# Style A: from_/to_ (underscored to match Python param names)
r = client.get(f"/api/devices/{dev['id']}/config-history?from_=1&to_=2")
check("config-history with from_/to params returns 200", r.status_code == 200, f"status={r.status_code}")
if r.status_code == 200:
    j = r.json()
    check("response is valid JSON dict", isinstance(j, dict), f"got type={type(j).__name__}")
    if isinstance(j, dict):
        check("response has 'diff' key", "diff" in j, f"keys={list(j.keys())}")
        check("response has 'from' key", "from" in j, f"keys={list(j.keys())}")
        check("response has 'to' key", "to" in j, f"keys={list(j.keys())}")
        if "diff" in j:
            check("diff contains -b marker", "-b" in j["diff"], f"diff={j['diff'][:200]!r}")
            check("diff contains +x marker", "+x" in j["diff"], f"diff={j['diff'][:200]!r}")

# Also verify the function's direct call works correctly (bypassing FastAPI param mapping)
result = owctl.get_config_history(dev['id'], from_='1', to='2')
check("direct function call returns dict with diff key",
      isinstance(result, dict) and "diff" in result,
      f"got type={type(result).__name__}, keys={list(result.keys()) if isinstance(result, dict) else 'N/A'}")
if isinstance(result, dict) and "diff" in result:
    check("diff contains -b marker", "-b" in result["diff"], f"diff={result['diff'][:200]!r}")
    check("diff contains +x marker", "+x" in result["diff"], f"diff={result['diff'][:200]!r}")

# Style B: from=1&to=2 (plain param names)
r2 = client.get(f"/api/devices/{dev['id']}/config-history?from=1&to=2")
check("config-history with from=1&to=2 returns 200", r2.status_code == 200, f"status={r2.status_code}")
if r2.status_code == 200:
    j2 = r2.json()
    check("response is valid JSON", j2 is not None, "got None response")


# ---- 3. endpoint WITHOUT from/to returns list shape ----
r3 = client.get(f"/api/devices/{dev['id']}/config-history")
check("config-history without from/to returns 200", r3.status_code == 200, f"status={r3.status_code}")
if r3.status_code == 200:
    j3 = r3.json()
    check("response is a list", isinstance(j3, list), f"got type={type(j3).__name__}")
    check("list has 2 entries", len(j3) == 2, f"got {len(j3)}")
    if isinstance(j3, list) and len(j3) == 2:
        check("entry has 'ts' key", "ts" in j3[0], f"first={j3[0]!r}")
        check("entry has 'files' key", "files" in j3[0], f"first={j3[0]!r}")


print()
print(f"Results: {PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)