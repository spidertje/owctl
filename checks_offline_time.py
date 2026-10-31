#!/usr/bin/env python3
"""Offline time feature verification for owctl.

Seeds a temp OWCTL_DATA dir, inserts offline_events rows (open and closed),
asserts network_overview recent_offline computes elapsed correctly for both
open (still offline) and closed events, and asserts offline_events column
semantics remain unchanged (non-negative offline_seconds on close).
"""
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Must set env BEFORE importing owctl so it picks up the temp dir
scratch = tempfile.mkdtemp(prefix="owctl-offlinetime-")
os.environ["OWCTL_DATA"] = scratch
os.environ["OWCTL_ALLOW_OPEN"] = "1"

import owctl

RESULTS = []


def check(name, cond, extra=""):
    RESULTS.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


def main():
    owctl.DATA_DIR = scratch
    owctl.DB_PATH = os.path.join(scratch, "owctl.db")
    owctl.init_db()

    conn = sqlite3.connect(owctl.DB_PATH)
    conn.execute(
        "INSERT INTO devices(id, name, host, access, status) VALUES(1, 'mock', '127.0.0.1', 'ssh', 'unknown')"
    )
    conn.commit()
    conn.close()

    dev = {"id": 1, "name": "mock", "host": "127.0.0.1", "access": "ssh", "status": "unknown"}

    # ---- Test 1: OPEN event (still offline) ----
    # Insert an offline_events row with went_offline ~120s ago, went_online NULL
    ts_now = owctl.now()
    ts_off = datetime.fromisoformat(ts_now.replace(" ", "T")) - timedelta(seconds=120)
    went_offline_str = ts_off.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    conn = sqlite3.connect(owctl.DB_PATH)
    conn.execute(
        "INSERT INTO offline_events(device_id, device_name, went_offline) VALUES(?,?,?)",
        (1, "mock", went_offline_str),
    )
    conn.commit()
    conn.close()

    # GET /api/network and assert recent_offline[0]
    from starlette.testclient import TestClient
    client = TestClient(owctl.app)

    # Need to login first
    lr = client.post("/api/auth/login", json={"username": "admin", "password": "offline-time-pass-123"})
    check("login (first boot) -> 200", lr.status_code == 200, f"got {lr.status_code}")
    sess = (lr.json() or {}).get("session", "")
    H = {"Authorization": f"Bearer {sess}"}

    r = client.get("/api/network", headers=H)
    check("network endpoint returns 200", r.status_code == 200, str(r.status_code))

    data = r.json()
    recent = data.get("recent_offline", [])
    check("recent_offline list present", len(recent) >= 1, f"got {len(recent)} items")

    if recent:
        entry = recent[0]
        check("entry has device_name", entry.get("device_name") == "mock", str(entry.get("device_name")))
        check("entry went_offline matches", entry.get("went_offline") == went_offline_str, str(entry.get("went_offline")))
        check("entry went_online is None (still offline)", entry.get("went_online") is None, str(entry.get("went_online")))
        offline_seconds = entry.get("offline_seconds")
        check("offline_seconds is int (non-null)", isinstance(offline_seconds, int), f"got {type(offline_seconds)}: {offline_seconds}")
        check("offline_seconds >= 60 (approx 120s elapsed)", offline_seconds is not None and offline_seconds >= 60, f"got {offline_seconds}")

    # ---- Test 2: CLOSED event (went online ~60s after went offline) ----
    # Insert a second offline_events row that is closed
    ts_off2 = datetime.fromisoformat(ts_now.replace(" ", "T")) - timedelta(seconds=180)
    went_offline_str2 = ts_off2.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    ts_on2 = ts_off2 + timedelta(seconds=60)
    went_online_str2 = ts_on2.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    conn = sqlite3.connect(owctl.DB_PATH)
    conn.execute(
        "INSERT INTO offline_events(device_id, device_name, went_offline, went_online, offline_seconds) VALUES(?,?,?,?,?)",
        (1, "mock", went_offline_str2, went_online_str2, 60),
    )
    conn.commit()
    conn.close()

    r = client.get("/api/network", headers=H)
    check("network endpoint returns 200 (after closed event)", r.status_code == 200, str(r.status_code))

    data = r.json()
    recent = data.get("recent_offline", [])
    check("recent_offline list has 2 items", len(recent) >= 2, f"got {len(recent)} items")

    if len(recent) >= 2:
        # Most recent is the closed one (higher id)
        entry = recent[0]
        check("closed entry has device_name", entry.get("device_name") == "mock", str(entry.get("device_name")))
        check("closed entry went_offline matches", entry.get("went_offline") == went_offline_str2, str(entry.get("went_offline")))
        check("closed entry went_online is not None", entry.get("went_online") == went_online_str2, str(entry.get("went_online")))
        offline_seconds = entry.get("offline_seconds")
        check("closed entry offline_seconds is int", isinstance(offline_seconds, int), f"got {type(offline_seconds)}: {offline_seconds}")
        # Should be ~60 seconds
        check("closed entry offline_seconds == ~60", offline_seconds is not None and 50 <= offline_seconds <= 70, f"got {offline_seconds}")

    # ---- Test 3: Verify DB column semantics unchanged ----
    # Use record_heartbeat to close an open event and verify offline_seconds column is non-negative
    conn = sqlite3.connect(owctl.DB_PATH)
    conn.execute(
        "INSERT INTO offline_events(device_id, device_name, went_offline) VALUES(?,?,?)",
        (1, "mock", owctl.now()),
    )
    conn.commit()
    conn.close()

    # Now transition offline -> online via record_heartbeat
    # Need to set heartbeat state to offline first
    owctl._HEARTBEAT_STATE[1] = False
    owctl.record_heartbeat(dev, True)  # offline -> online transition closes the event

    evs = owctl.q("SELECT * FROM offline_events WHERE device_id=1 ORDER BY id DESC LIMIT 1")
    check("record_heartbeat closed the most recent open event", len(evs) == 1 and evs[0]["went_online"] is not None, str(evs))
    if evs:
        ev = evs[0]
        check("DB column offline_seconds non-negative after record_heartbeat close",
              ev["offline_seconds"] is not None and ev["offline_seconds"] >= 0, f"got {ev['offline_seconds']}")

    # Summary
    print("\n=== SUMMARY ===")
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print(f"{passed}/{len(RESULTS)} checks passed")
    if passed != len(RESULTS):
        print("FAILURES:")
        for n, ok, extra in RESULTS:
            if not ok:
                print(" -", n, extra)
        sys.exit(1)
    print("ALL OFFLINE TIME CHECKS PASSED")


if __name__ == "__main__":
    main()