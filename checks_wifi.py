#!/usr/bin/env python3
"""checks_wifi.py — verify wifi_capable is persisted by record_status_snapshot
and exposed on /api/devices (the signal the WiFi tab filters on)."""
import os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
tmp = tempfile.mkdtemp()
os.environ["OWCTL_DATA"] = tmp
import owctl
from starlette.testclient import TestClient
client = TestClient(owctl.app)
owctl.init_db()
CHECKS = []
def check(name, cond, extra=""):
    CHECKS.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))

d_router = owctl.execute("INSERT INTO devices(name, host, role, status, added_at) VALUES(?,?,?,?,'x')",
                         ("router", "192.0.2.1", "router", "online"))
d_ap = owctl.execute("INSERT INTO devices(name, host, role, status, added_at) VALUES(?,?,?,?,'x')",
                     ("ap", "192.0.2.2", "ap", "online"))

# --- record_status_snapshot persists wifi_capable from the status dict ---
owctl.record_status_snapshot({"id": d_router}, {"wifi_capable": False, "clients": 3, "uptime_s": 10})
owctl.record_status_snapshot({"id": d_ap}, {"wifi_capable": True, "clients": 5, "uptime_s": 20})
r = owctl.q("SELECT wifi_capable FROM device_status WHERE device_id=?", (d_router,))[0]
a = owctl.q("SELECT wifi_capable FROM device_status WHERE device_id=?", (d_ap,))[0]
check("snapshot persists wifi_capable=0 for radio-less router", r["wifi_capable"] == 0, f"got {r['wifi_capable']}")
check("snapshot persists wifi_capable=1 for AP", a["wifi_capable"] == 1, f"got {a['wifi_capable']}")

# --- /api/devices exposes wifi_capable ---
devs = {d["id"]: d for d in client.get("/api/devices").json()}
check("/api/devices returns wifi_capable field", "wifi_capable" in devs[d_router])
check("router wifi_capable is False (hidden)", devs[d_router]["wifi_capable"] is False, f"got {devs[d_router]['wifi_capable']}")
check("ap wifi_capable is True (shown)", devs[d_ap]["wifi_capable"] is True, f"got {devs[d_ap]['wifi_capable']}")

# --- a device never checked has wifi_capable None -> frontend falls back to role ---
d_fresh = owctl.execute("INSERT INTO devices(name, host, role, status, added_at) VALUES(?,?,?,?,'x')",
                        ("fresh-ap", "192.0.2.3", "ap", "unknown"))
devs = {d["id"]: d for d in client.get("/api/devices").json()}
check("never-checked device has wifi_capable None", devs[d_fresh]["wifi_capable"] is None,
      f"got {devs[d_fresh]['wifi_capable']}")

print(f"\n=== SUMMARY ===\n{sum(1 for _,ok,_ in CHECKS if ok)}/{len(CHECKS)} checks passed")
failed = [n for n,ok,_ in CHECKS if not ok]
if failed:
    print("FAILURES:", failed); sys.exit(1)
print("ALL WIFI-CAPABLE CHECKS PASSED")
