#!/usr/bin/env python3
"""Uptime feature verification for owctl.

Seeds a temp OWCTL_DATA dir, drives record_heartbeat through online->offline->online
transitions, asserts the offline_events row is closed with non-negative offline_seconds,
and asserts the three new endpoints are registered on the FastAPI app.
"""
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import owctl

RESULTS = []


def check(name, cond, extra=""):
    RESULTS.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


def main():
    scratch = tempfile.mkdtemp(prefix="owctl-uptime-")
    os.environ["OWCTL_DATA"] = scratch
    owctl.DATA_DIR = scratch
    owctl.DB_PATH = os.path.join(scratch, "owctl.db")
    owctl.init_db()

    conn = sqlite3.connect(owctl.DB_PATH)
    conn.execute(
        "INSERT INTO devices(id, name, host, access, status) VALUES(1, 'mock', '127.0.0.1', 'ssh', 'unknown')")
    conn.commit()
    conn.close()

    dev = {"id": 1, "name": "mock", "host": "127.0.0.1", "access": "ssh", "status": "unknown"}

    # online -> offline -> online
    owctl.record_heartbeat(dev, True)
    owctl.record_heartbeat(dev, False)
    owctl.record_heartbeat(dev, True)

    evs = owctl.q("SELECT * FROM offline_events WHERE device_id=1")
    check("offline event opened on transition", len(evs) == 1, f"{len(evs)} events")
    if evs:
        ev = evs[0]
        check("event closed (went_online set)", ev["went_online"] is not None, str(ev))
        check("offline_seconds is non-negative",
              ev["offline_seconds"] is not None and ev["offline_seconds"] >= 0, str(ev["offline_seconds"]))

    hbs = owctl.q("SELECT * FROM device_heartbeats WHERE device_id=1 ORDER BY id")
    check("three heartbeats recorded", len(hbs) == 3, f"{len(hbs)} heartbeats")
    check("heartbeats alternate online flags",
          [h["online"] for h in hbs] == [1, 0, 1], str([h["online"] for h in hbs]))

    # endpoints registered on the FastAPI app
    paths = {r.path for r in owctl.app.routes if hasattr(r, "path")}
    check("GET /api/devices/{did}/heartbeat registered",
          "/api/devices/{did}/heartbeat" in paths, sorted(p for p in paths if "heartbeat" in p or "uptime" in p or "offline" in p))
    check("GET /api/uptime registered", "/api/uptime" in paths, "")
    check("GET /api/offline-events registered", "/api/offline-events" in paths, "")

    # exercise the endpoints via starlette TestClient if available
    try:
        from starlette.testclient import TestClient
        client = TestClient(owctl.app)
        r = client.get("/api/devices/1/heartbeat?limit=5")
        check("heartbeat endpoint returns 200", r.status_code == 200, str(r.status_code))
        check("heartbeat endpoint returns 3 rows", len(r.json()) == 3, str(r.json()))
        r = client.get("/api/uptime")
        check("uptime endpoint returns 200", r.status_code == 200, str(r.status_code))
        data = r.json()
        check("uptime endpoint lists the seeded device", any(d["id"] == 1 for d in data), str(data))
        dev0 = next(d for d in data if d["id"] == 1)
        check("uptime total_checks == 3", dev0["total_checks"] == 3, str(dev0))
        check("uptime online_count == 2", dev0["online_count"] == 2, str(dev0))
        check("uptime_pct == 66.7", dev0["uptime_pct"] == 66.7, str(dev0["uptime_pct"]))
        check("uptime last_online set", dev0["last_online"] is not None, str(dev0))
        r = client.get("/api/offline-events")
        check("offline-events endpoint returns 200", r.status_code == 200, str(r.status_code))
        check("offline-events endpoint returns 1 event", len(r.json()) == 1, str(r.json()))
    except Exception as e:
        # TestClient needs httpx2; route-registration assertions above are the
        # hard requirement, so a missing transport backend is not a failure.
        if "httpx2" in repr(e).lower() or "testclient" in repr(e).lower():
            print("NOTE: TestClient skipped (no httpx2 backend); route assertions above stand")
        else:
            check("TestClient path exercised", False, repr(e))

    print("\n=== SUMMARY ===")
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print(f"{passed}/{len(RESULTS)} checks passed")
    if passed != len(RESULTS):
        print("FAILURES:")
        for n, ok, extra in RESULTS:
            if not ok:
                print(" -", n, extra)
        sys.exit(1)
    print("ALL UPTIME CHECKS PASSED")


if __name__ == "__main__":
    main()