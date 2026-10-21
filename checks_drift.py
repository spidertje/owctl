# Copyright (C) 2026 spidertje
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.

"""checks_drift.py — cross-device drift report (2.9).

Pure comparator + /api/drift over seeded device_status snapshots.
No SSH. Run: .venv/bin/python checks_drift.py
"""
import json, os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ["OWCTL_DATA"] = "/tmp/owctl-drift-test-" + str(os.getpid())
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

# Seed two devices with status snapshots.
execute("INSERT INTO devices(name,host,role) VALUES('Router-A','10.0.0.1','router')")
execute("INSERT INTO devices(name,host,role) VALUES('Router-B','10.0.0.2','router')")
a = q("SELECT id FROM devices WHERE host='10.0.0.1'")[0]["id"]
b = q("SELECT id FROM devices WHERE host='10.0.0.2'")[0]["id"]

def seed(did, firmware, dnsmasq, odhcpd):
    pkgs = [{"pkg": "dnsmasq", "version": dnsmasq}, {"pkg": "odhcpd", "version": odhcpd}]
    execute("INSERT INTO device_status(device_id,ts,firmware,clients,installed_pkgs) VALUES(?,?,?,?,?)",
            (did, "now", firmware, 3, json.dumps(pkgs)))

seed(a, "23.05.4", "2.87-1", "20230601")
seed(b, "23.05.4", "2.88-2", "20230601")   # dnsmasq differs -> drift

st = client.get("/api/drift")
check("GET /api/drift -> 200", st.status_code == 200, str(st.status_code))
body = st.json()
check("devices counted = 2", body.get("devices") == 2, str(body.get("devices")))
check("dnsmasq flagged drift", body["drift"].get("dnsmasq", {}).get("status") == "drift", str(body["drift"].get("dnsmasq")))
check("dnsmasq 2 distinct", len(body["drift"].get("dnsmasq", {}).get("distinct", [])) == 2)
check("odhcpd uniform (ok)", body["drift"].get("odhcpd", {}).get("status") == "ok", str(body["drift"].get("odhcpd")))
check("firmware uniform (ok)", body["drift"].get("firmware", {}).get("status") == "ok")
check("divergent list = [dnsmasq]", body.get("divergent") == ["dnsmasq"], str(body.get("divergent")))
check("count = 1", body.get("count") == 1, str(body.get("count")))

# Pure comparator unit checks.
rows = [
    {"name": "x", "values": {"f": "1"}},
    {"name": "y", "values": {"f": "1"}},
]
check("comparator uniform", owctl.compare_device_drift(rows, ["f"])["f"]["status"] == "ok")
rows2 = [
    {"name": "x", "values": {"f": "1"}},
    {"name": "y", "values": {"f": "2"}},
]
c2 = owctl.compare_device_drift(rows2, ["f"])
check("comparator drift", c2["f"]["status"] == "drift" and len(c2["f"]["distinct"]) == 2)
# missing: one null
rows3 = [
    {"name": "x", "values": {"f": "1"}},
    {"name": "y", "values": {}},
]
check("comparator missing", owctl.compare_device_drift(rows3, ["f"])["f"]["status"] == "missing")
# all-null field omitted
rows4 = [{"name": "x", "values": {}}, {"name": "y", "values": {}}]
check("comparator all-null omitted", "f" not in owctl.compare_device_drift(rows4, ["f"]))

# <2 devices case
execute("DELETE FROM device_status WHERE device_id=?", (b,))
st2 = client.get("/api/drift")
body2 = st2.json()
check("<2 snapshots -> note", st2.status_code == 200 and "note" in body2, str(body2))

print()
if FAILS:
    print(f"FAILED: {len(FAILS)} check(s)")
    for f in FAILS:
        print("  - " + f)
    os.system(f"rm -rf {os.environ['OWCTL_DATA']}")
    sys.exit(1)
print(f"ALL DRIFT CHECKS PASSED ({len(FAILS)} failures)")
os.system(f"rm -rf {os.environ['OWCTL_DATA']}")
