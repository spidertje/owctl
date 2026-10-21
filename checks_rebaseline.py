# Copyright (C) 2026 spidertje
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.

"""checks_rebaseline.py — firmware/package re-baseline (preview + apply).

_ver_key + preview (over seeded device_status snapshots, no SSH) and
POST /api/rebaseline/apply with do_rebaseline mocked (no real opkg).
Run: .venv/bin/python checks_rebaseline.py
"""
import json, os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ["OWCTL_DATA"] = "/tmp/owctl-reb-test-" + str(os.getpid())
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

# ---- _ver_key (pure) ----
check("ver_key 2.90", owctl._ver_key("2.90") == (2, 90), str(owctl._ver_key("2.90")))
check("ver_key epoch", owctl._ver_key("1:2.3") == (1, 2, 3), str(owctl._ver_key("1:2.3")))
check("ver_key ordering", owctl._ver_key("2.9") < owctl._ver_key("2.10")
      < owctl._ver_key("2.90"), "2.9 vs 2.10 vs 2.90")
check("ver_key alpha", owctl._ver_key("2.90-beta") == (2, 90, 0), str(owctl._ver_key("2.90-beta")))

# ---- preview (seeded snapshots) ----
execute("INSERT INTO devices(name,host,role) VALUES('A','10.0.0.1','router')")
execute("INSERT INTO devices(name,host,role) VALUES('B','10.0.0.2','router')")
execute("INSERT INTO devices(name,host,role) VALUES('C','10.0.0.3','router')")
a = q("SELECT id FROM devices WHERE host='10.0.0.1'")[0]["id"]
b = q("SELECT id FROM devices WHERE host='10.0.0.2'")[0]["id"]
c = q("SELECT id FROM devices WHERE host='10.0.0.3'")[0]["id"]

def seed(did, fw, dnsmasq, odhcpd, openwrt):
    pkgs = []
    for name, ver in (("dnsmasq", dnsmasq), ("odhcpd", odhcpd), ("openwrt", openwrt)):
        if ver:
            pkgs.append({"pkg": name, "version": ver})
    execute("INSERT INTO device_status(device_id,ts,firmware,installed_pkgs) VALUES(?,?,?,?)",
            (did, "now", fw, json.dumps(pkgs)))

# Majority firmware = 23.05.4 (A and B). C is on 22.03.0 -> lagging.
# dnsmasq baseline = 2.90 (C). A/B have 2.87 -> lagging on dnsmasq.
seed(a, "23.05.4", "2.87", "20230601", "23.05.4")
seed(b, "23.05.4", "2.87", "20230601", "23.05.4")
seed(c, "22.03.0", "2.90", "20220101", "22.03.0")

st = client.get("/api/rebaseline/preview")
check("GET /rebaseline/preview -> 200", st.status_code == 200, str(st.status_code))
body = st.json()
check("device_count=3", body.get("device_count") == 3, str(body.get("device_count")))
check("baseline_firmware=23.05.4", body.get("baseline_firmware") == "23.05.4",
      str(body.get("baseline_firmware")))
check("baseline dnsmasq=2.90", body.get("baseline", {}).get("dnsmasq") == "2.90",
      str(body.get("baseline")))
check("baseline odhcpd=20230601", body.get("baseline", {}).get("odhcpd") == "20230601",
      str(body.get("baseline")))
lag_names = {l["name"] for l in body.get("lagging", [])}
check("A lagging (dnsmasq)", "A" in lag_names, str(body.get("lagging")))
check("C lagging (firmware)", "C" in lag_names, str(body.get("lagging")))
c_lag = [l for l in body.get("lagging", []) if l["name"] == "C"][0]
check("C differs firmware 22.03.0", c_lag["differs"].get("firmware") == "22.03.0",
      str(c_lag["differs"]))
a_lag = [l for l in body.get("lagging", []) if l["name"] == "A"][0]
check("A differs dnsmasq 2.87", a_lag["differs"].get("dnsmasq") == "2.87", str(a_lag["differs"]))
check("A not differing firmware", "firmware" not in a_lag["differs"], str(a_lag["differs"]))

# <2 devices case
execute("DELETE FROM device_status WHERE device_id IN (?,?)", (a, b))
st2 = client.get("/api/rebaseline/preview")
check("<2 snapshots -> note", st2.status_code == 200 and "note" in st2.json(), str(st2.json()))
execute("INSERT INTO device_status(device_id,ts,firmware,installed_pkgs) VALUES(?,?,?,?)",
        (a, "now", "23.05.4", json.dumps([{"pkg": "dnsmasq", "version": "2.87"}])))

# ---- apply (do_rebaseline mocked) ----
calls = []
def mock_reb(dev, packages, sysupgrade=False):
    calls.append((dev["name"], list(packages), bool(sysupgrade)))
    return "rebaselined " + dev["name"]
owctl.do_rebaseline = mock_reb

st3 = client.post("/api/rebaseline/apply", json={"devices": [a, b, c], "sysupgrade": True})
check("POST /rebaseline/apply -> 200", st3.status_code == 200, str(st3.status_code))
ab = st3.json()
check("all 3 ok", ab.get("ok") == 3 and ab.get("failed") == 0, str({k: ab.get(k) for k in ("ok", "failed")}))
check("do_rebaseline called per device", len(calls) == 3 and {x[0] for x in calls} == {"A", "B", "C"}, str(calls))
check("sysupgrade passed through", all(x[2] is True for x in calls), str(calls))
check("packages default to 3", all(x[1] == ["dnsmasq", "odhcpd", "openwrt"] for x in calls), str(calls))

# scoped + custom packages
calls.clear()
st4 = client.post("/api/rebaseline/apply", json={"devices": [a], "packages": ["dnsmasq"]})
check("scoped apply ok", st4.status_code == 200 and st4.json().get("ok") == 1, str(st4.json()))
check("custom package passed", calls == [("A", ["dnsmasq"], False)], str(calls))

# unknown device isolated
st5 = client.post("/api/rebaseline/apply", json={"devices": [99999]})
check("unknown device isolated", st5.status_code == 200 and st5.json().get("failed") == 1, str(st5.json()))

# error isolation
def mock_mixed(dev, packages, sysupgrade=False):
    if dev["name"] == "C":
        raise RuntimeError("ssh down")
    return "ok " + dev["name"]
owctl.do_rebaseline = mock_mixed
st6 = client.post("/api/rebaseline/apply", json={"devices": [a, b, c]})
check("error isolated", st6.status_code == 200 and st6.json().get("ok") == 2
      and st6.json().get("failed") == 1, str(st6.json()))

print()
if FAILS:
    print(f"FAILED: {len(FAILS)} check(s)")
    for f in FAILS:
        print("  - " + f)
    os.system(f"rm -rf {os.environ['OWCTL_DATA']}")
    sys.exit(1)
print(f"ALL REBASELINE CHECKS PASSED ({len(FAILS)} failures)")
os.system(f"rm -rf {os.environ['OWCTL_DATA']}")
