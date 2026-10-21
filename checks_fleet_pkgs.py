# Copyright (C) 2026 spidertje
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.

"""checks_fleet_pkgs.py — fleet-wide package view + upgrade (3.5).

GET /api/fleet/packages over seeded device_status snapshots (no SSH), and
POST /api/fleet/upgrade with do_upgrade mocked (no real opkg).
Run: .venv/bin/python checks_fleet_pkgs.py
"""
import json, os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ["OWCTL_DATA"] = "/tmp/owctl-fleet-test-" + str(os.getpid())
os.environ["OWCTL_ALLOW_OPEN"] = "1"
os.makedirs(os.environ["OWCTL_DATA"], exist_ok=True)
import owctl  # noqa
from owctl import q, execute
from starlette.testclient import TestClient
client = TestClient(owctl.app)

FAILS = []
def check(name, cond, extra=""):
    ok = bool(cond)
    print(("ok   " if ok else "FAIL ") + name + (f"  {extra}" if (extra and not ok) else ""))
    if not ok:
        FAILS.append(name)

# Seed two devices, each with installed + upgradable packages.
execute("INSERT INTO devices(name,host,role) VALUES('Rtr-A','10.0.0.1','router')")
execute("INSERT INTO devices(name,host,role) VALUES('Rtr-B','10.0.0.2','router')")
a = q("SELECT id FROM devices WHERE host='10.0.0.1'")[0]["id"]
b = q("SELECT id FROM devices WHERE host='10.0.0.2'")[0]["id"]

def seed(did, installed, upgradable):
    execute("INSERT INTO device_status(device_id,ts,firmware,installed_pkgs,upgradable_pkgs) VALUES(?,?,?,?,?)",
            (did, "now", "23.05.4", json.dumps(installed), json.dumps(upgradable)))

seed(a, [{"pkg": "dnsmasq", "version": "2.87"}], [{"pkg": "dnsmasq", "installed": "2.87", "available": "2.90"}])
seed(b, [{"pkg": "dnsmasq", "version": "2.87"}], [])  # B has no updates

st = client.get("/api/fleet/packages")
check("GET /fleet/packages -> 200", st.status_code == 200, str(st.status_code))
body = st.json()
check("devices counted = 2", body.get("device_count") == 2, str(body.get("device_count")))
check("devices_with_updates = 1", body.get("devices_with_updates") == 1, str(body.get("devices_with_updates")))
check("total_updates = 1", body.get("total_updates") == 1, str(body.get("total_updates")))
check("updates_by_package dnsmasq on Rtr-A",
      body.get("updates_by_package", {}).get("dnsmasq") == ["Rtr-A"],
      str(body.get("updates_by_package")))
ra = [d for d in body["devices"] if d["name"] == "Rtr-A"][0]
check("Rtr-A upgradable_count=1", ra["upgradable_count"] == 1, str(ra["upgradable_count"]))
check("Rtr-A installed_count=1", ra["installed_count"] == 1, str(ra["installed_count"]))

# POST /api/fleet/upgrade with do_upgrade mocked (no real opkg/SSH).
calls = []
def mock_upgrade(dev, packages):
    calls.append((dev["name"], list(packages)))
    return "upgraded " + dev["name"]
owctl.do_upgrade = mock_upgrade

st2 = client.post("/api/fleet/upgrade", json={"devices": [a, b]})
check("POST /fleet/upgrade -> 200", st2.status_code == 200, str(st2.status_code))
ub = st2.json()
check("both upgraded ok", ub.get("ok") == 2 and ub.get("failed") == 0, str({k: ub.get(k) for k in ("ok", "failed")}))
check("do_upgrade called per device", len(calls) == 2 and {c[0] for c in calls} == {"Rtr-A", "Rtr-B"}, str(calls))

# scoped to one device, with a package filter passed through
calls.clear()
st3 = client.post("/api/fleet/upgrade", json={"devices": [a], "packages": ["dnsmasq"]})
check("scoped upgrade ok", st3.status_code == 200 and st3.json().get("ok") == 1, str(st3.json()))
check("package filter passed through", calls == [("Rtr-A", ["dnsmasq"])], str(calls))

# unknown device -> reported failed, not 500
st4 = client.post("/api/fleet/upgrade", json={"devices": [99999]})
check("unknown device isolated", st4.status_code == 200 and st4.json().get("failed") == 1, str(st4.json()))

# error isolation: one device throws, other still ok
def mock_mixed(dev, packages):
    if dev["name"] == "Rtr-B":
        raise RuntimeError("ssh down")
    return "ok " + dev["name"]
owctl.do_upgrade = mock_mixed
st5 = client.post("/api/fleet/upgrade", json={"devices": [a, b]})
check("error isolated", st5.status_code == 200 and st5.json().get("ok") == 1 and st5.json().get("failed") == 1, str(st5.json()))

print()
if FAILS:
    print(f"FAILED: {len(FAILS)} check(s)")
    for f in FAILS:
        print("  - " + f)
    os.system(f"rm -rf {os.environ['OWCTL_DATA']}")
    sys.exit(1)
print(f"ALL FLEET-PKG CHECKS PASSED ({len(FAILS)} failures)")
os.system(f"rm -rf {os.environ['OWCTL_DATA']}")
