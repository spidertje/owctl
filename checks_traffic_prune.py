#!/usr/bin/env python3
"""checks_traffic_prune.py — per-interface traffic-sample prune regression guard.

Contract (audit P1, MED): the prune kept only 48 rows TOTAL per device
(`WHERE device_id=? ORDER BY ts DESC LIMIT 48`), despite its comment saying
"per device/iface". On a box with several interfaces, the busiest one would
evict every other interface's samples from the trend chart.

The fix partitions by (device_id, iface) so each interface keeps its own 48
newest samples. This test seeds one device with TWO interfaces, pushes each
past 48 rows, runs the fixed prune, and asserts BOTH interfaces still have
their newest samples (old code left one interface with only its tail, the
other with nearly nothing).
"""
import os
import sys
import tempfile

_tmp = tempfile.mkdtemp(prefix="owctl-traffic-")
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


dev = owctl.q("SELECT * FROM devices WHERE host='traffic'")
if not dev:
    owctl.execute("INSERT INTO devices(name, host, access, added_at) VALUES(?,?,?,?)",
                  ("traffic", "traffic", "ssh", owctl.now()))
dev = owctl.q("SELECT * FROM devices WHERE host='traffic'")[0]
did = dev["id"]

# Seed 60 samples on eth0 (busy) and 60 on eth1 (quiet), interleaved by ts so
# the global LIMIT 48 (old code) would keep only the last 48 of the union —
# leaving eth1 with only its newest ~24.
owctl.execute("DELETE FROM traffic_samples WHERE device_id=?", (did,))
base = "2026-01-01 00:00:00.000"
for i in range(60):
    ts = base[:-3] + f"{i:03d}"  # 2026-01-01 00:00:00.000 ... .059
    owctl.execute(
        "INSERT INTO traffic_samples(device_id, ts, iface, rx_bytes, tx_bytes) VALUES(?,?,?,?,?)",
        (did, f"{base[:-4]}{i:03d}", "eth0", i * 1000, i * 2000))
    owctl.execute(
        "INSERT INTO traffic_samples(device_id, ts, iface, rx_bytes, tx_bytes) VALUES(?,?,?,?,?)",
        (did, f"{base[:-4]}{i:03d}", "eth1", i * 500, i * 600))


def per_iface_counts():
    rows = owctl.q("SELECT iface, COUNT(*) c FROM traffic_samples WHERE device_id=? GROUP BY iface", (did,))
    return {r["iface"]: r["c"] for r in rows}


# Run the FIXED prune (same SQL as the storage loop at ~line 3384).
owctl.execute("""DELETE FROM traffic_samples WHERE id NOT IN (
    SELECT id FROM (
        SELECT id,
               ROW_NUMBER() OVER (PARTITION BY device_id, iface ORDER BY ts DESC) AS rn
        FROM traffic_samples
        WHERE device_id=?
    ) WHERE rn <= 48
) AND device_id=?""", (did, did))

counts = per_iface_counts()
check("eth0 keeps exactly 48 samples (its own cap)",
      counts.get("eth0") == 48, f"counts={counts}")
check("eth1 keeps exactly 48 samples (its own cap, NOT evicted by eth0)",
      counts.get("eth1") == 48, f"counts={counts}")
check("total retained = 96 (48 per interface), not 48 global",
      counts.get("eth0", 0) + counts.get("eth1", 0) == 96, f"counts={counts}")

# The NEWEST sample of each interface must be present (not the tail of one
# interface's history that the old global LIMIT would have kept).
for iface in ("eth0", "eth1"):
    newest = owctl.q("SELECT ts FROM traffic_samples WHERE device_id=? AND iface=? ORDER BY ts DESC LIMIT 1", (did, iface))
    oldest = owctl.q("SELECT ts FROM traffic_samples WHERE device_id=? AND iface=? ORDER BY ts ASC LIMIT 1", (did, iface))
    check(f"{iface}: newest sample retained", bool(newest), f"newest={newest}")
    # Oldest retained should be ~12 rows back (60 - 48), proving the 12 oldest
    # were pruned, not the newest.
    check(f"{iface}: oldest retained is not the very first sample",
          oldest and newest and oldest[0]["ts"] < newest[0]["ts"],
          f"oldest={oldest} newest={newest}")

print(f"\n=== SUMMARY ===\n{PASS}/{PASS + FAIL} checks passed")
sys.exit(0 if FAIL == 0 else 1)
