#!/usr/bin/env python3
"""checks_config_changes.py — multi-path config-change detection regression guard.

Contract (audit P1, HIGH): check_config_changes baselined only ONE config path.
Two coupled bugs:
  * WRITE — one row per config path, but the table's UNIQUE(device_id, ts)
    forbids two rows at the same ts, so `INSERT OR IGNORE` dropped every path
    after the first; combined with per-row now(), the "latest snapshot" was
    ambiguous.
  * READ  — `ORDER BY ts DESC LIMIT 1` returned a SINGLE row, so only one path
    was ever baselined and every other changed /etc/config file went undetected.

The fix: ONE row per snapshot, all paths as a single newline-separated blob.
The latest snapshot is exactly `MAX(ts)`. This test models the full post-fix
pipeline: seed a LEGACY scattered-ts baseline (one path per ts, as the old
loop left it), run the FIXED storage step (DELETE ts < snap_ts, then one blob
row at snap_ts), then gather with ALL paths changed and assert every one is
reported.
"""
import os
import sys
import tempfile

_tmp = tempfile.mkdtemp(prefix="owctl-cfgcheck-")
os.environ["OWCTL_DATA"] = os.path.join(_tmp, "data")
os.environ.setdefault("OWCTL_ALLOW_OPEN", "1")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import owctl  # noqa: E402

owctl.init_db()

PASS = FAIL = 0


def check(label, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {label}")
    else:
        FAIL += 1
        print(f"FAIL {label} :: {detail}")


dev = owctl.q("SELECT * FROM devices WHERE host='cfgcheck'")
if not dev:
    owctl.execute("INSERT INTO devices(name, host, access, added_at) VALUES(?,?,?,?)",
                  ("cfgcheck", "cfgcheck", "ssh", owctl.now()))
dev = owctl.q("SELECT * FROM devices WHERE host='cfgcheck'")[0]

# --- Seed a LEGACY scattered-ts baseline (one path per distinct ts, the layout
# --- the old per-row now() + INSERT OR IGNORE loop left behind).
owctl.execute("DELETE FROM config_hashes WHERE device_id=?", (dev["id"],))
owctl.execute("INSERT INTO config_hashes(device_id, ts, hash) VALUES(?,?,?)",
              (dev["id"], "2026-01-01 00:00:00.000", "/etc/config/network=aaaa0001"))
owctl.execute("INSERT INTO config_hashes(device_id, ts, hash) VALUES(?,?,?)",
              (dev["id"], "2026-01-01 00:00:00.001", "/etc/config/firewall=bbbb0002"))
owctl.execute("INSERT INTO config_hashes(device_id, ts, hash) VALUES(?,?,?)",
              (dev["id"], "2026-01-01 00:00:00.002", "/etc/config/system=cccc0003"))

# --- Run the FIXED storage step: DELETE ts < snap_ts, then ONE blob row at
# --- snap_ts (mirrors the loop at ~line 3360). Self-heals the legacy rows.
snap_ts = "2026-01-02 00:00:00.000"
blob = "\n".join(["/etc/config/network=aaaa0001",
                  "/etc/config/firewall=bbbb0002",
                  "/etc/config/system=cccc0003"])
owctl.execute("DELETE FROM config_hashes WHERE device_id=? AND ts<?", (dev["id"], snap_ts))
owctl.execute("INSERT OR REPLACE INTO config_hashes(device_id, ts, hash) VALUES(?,?,?)",
              (dev["id"], snap_ts, blob))

# --- Baseline is now one single-ts blob row with all three paths.
rows = owctl.q("SELECT hash FROM config_hashes WHERE device_id=? AND ts=(SELECT MAX(ts) FROM config_hashes WHERE device_id=?)",
               (dev["id"], dev["id"]))
check("baseline is exactly one snapshot row (single-ts write)",
      len(rows) == 1, f"got {len(rows)} rows")
check("baseline blob contains all 3 paths",
      rows and all(p in rows[0]["hash"] for p in
                    ["/etc/config/network", "/etc/config/firewall", "/etc/config/system"]),
      f"blob={rows[0]['hash'] if rows else None!r}")

# --- Gather with ALL THREE changed + one new (unbaselined) path.
st = {"config_hashes": {
    "/etc/config/network": "zzzz_changed",
    "/etc/config/firewall": "yyyy_changed",
    "/etc/config/system": "xxxx_changed",
    "/etc/config/wireless": "newpath001",  # absent from baseline -> not reported
}}
changed = owctl.check_config_changes(dev, st)

check("changed file #1 (network) detected", "/etc/config/network" in changed, f"got {changed}")
check("changed file #2 (firewall) detected", "/etc/config/firewall" in changed, f"got {changed}")
check("changed file #3 (system) detected", "/etc/config/system" in changed, f"got {changed}")
check("new (unbaselined) path NOT reported as changed", "/etc/config/wireless" not in changed, f"got {changed}")
check("exactly the 3 changed paths reported (no false positives)",
      sorted(changed) == ["/etc/config/firewall", "/etc/config/network", "/etc/config/system"],
      f"got {sorted(changed)}")

# --- Negative: unchanged state reports nothing.
st_same = {"config_hashes": {
    "/etc/config/network": "aaaa0001",
    "/etc/config/firewall": "bbbb0002",
    "/etc/config/system": "cccc0003",
}}
check("unchanged snapshot -> no changes reported",
      owctl.check_config_changes(dev, st_same) == [],
      f"got {owctl.check_config_changes(dev, st_same)}")

# --- First gather (no baseline at all) -> no changes.
owctl.execute("DELETE FROM config_hashes WHERE device_id=?", (dev["id"],))
check("no baseline -> no changes reported (first check)",
      owctl.check_config_changes(dev, st) == [],
      f"got {owctl.check_config_changes(dev, st)}")

print(f"\n=== SUMMARY ===\n{PASS}/{PASS + FAIL} checks passed")
sys.exit(0 if FAIL == 0 else 1)
