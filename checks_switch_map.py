# Copyright (C) 2026 spidertje
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.

"""checks_switch_map.py — network-wide switch-port map (port->VLAN + link state).

Pure parser + join helper are unit-tested directly; the /api/switch-map
endpoint is driven with the two readers mocked (no real SSH).

Ground-truth convention (matches checks_switch_ports.py + do_vlan_port):
a port token with the 't' suffix is a TAGGED member of the VLAN; a bare
token is the untagged/native member.
Run: .venv/bin/python checks_switch_map.py
"""
import os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ["OWCTL_DATA"] = "/tmp/owctl-swmap-test-" + str(os.getpid())
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

# ---- parse_switch_port_map (pure) ----
sample = (
    "port 0 lan1 1\n"
    "port 1 lan2 0\n"
    "port 2 lan3 1\n"
    "port 3 wan 1\n"
)
pm = owctl.parse_switch_port_map(sample)
check("parser 4 ports", set(pm.keys()) == {0, 1, 2, 3}, str(pm.keys()))
check("parser name", pm[0]["name"] == "lan1", str(pm[0]))
check("parser up=true", pm[0]["up"] is True)
check("parser up=false", pm[1]["up"] is False)
check("parser wan", pm[3]["name"] == "wan" and pm[3]["up"] is True)
check("parser empty input", owctl.parse_switch_port_map("") == {})
check("parser ignores junk", owctl.parse_switch_port_map("nope\nport x a 1\n") == {})
check("parser sorted keys", list(owctl.parse_switch_port_map("port 2 b 1\nport 0 a 1\n")) == [0, 2])

# ---- build_switch_map (pure join) ----
# Convention (matches checks_switch_ports.py + do_vlan_port): 't' suffix =>
# tagged; bare => untagged. UCI `ports` tokens are numeric port indices.
# vlan0: 0(lan1,untag) 1(lan2,untag) 3t(wan,tagged)
# vlan2: 2(lan3,untag) 1t(lan2,tagged)
assignments = {
    "0": {"ports": ["0", "1", "3t"], "tag": None},
    "2": {"ports": ["2", "1t"], "tag": None},
}
status = {0: {"name": "lan1", "up": True}, 1: {"name": "lan2", "up": False},
          2: {"name": "lan3", "up": True}, 3: {"name": "wan", "up": True}}
m = owctl.build_switch_map(assignments, status)
check("map 4 ports", set(m.keys()) == {0, 1, 2, 3}, str(m.keys()))
# lan1: only vlan0, untagged
check("map lan1 vlan0 untagged", m[0]["vlans"] == [{"id": 0, "tagged": False}], str(m[0]))
check("map lan1 up", m[0]["up"] is True and m[0]["name"] == "lan1")
# wan: vlan0 tagged
v_wan = {v["id"]: v["tagged"] for v in m[3]["vlans"]}
check("map wan vlan0 tagged", v_wan == {0: True}, str(m[3]))
# lan2: vlan0 untagged + vlan2 tagged
v2 = {v["id"]: v["tagged"] for v in m[1]["vlans"]}
check("map lan2 in vlan0+vlan2", set(v2) == {0, 2}, str(m[1]["vlans"]))
check("map lan2 vlan0 untagged", v2[0] is False, str(m[1]["vlans"]))
check("map lan2 vlan2 tagged", v2[2] is True, str(m[1]["vlans"]))
check("map lan2 down", m[1]["up"] is False)
# lan3: vlan2 untagged
v3 = {v["id"]: v["tagged"] for v in m[2]["vlans"]}
check("map lan3 vlan2 untagged", v3 == {2: False}, str(m[2]["vlans"]))
# union: a status-only port (no assignment) still appears
m3 = owctl.build_switch_map({}, {9: {"name": "p9", "up": False}})
check("map status-only port present", set(m3.keys()) == {9} and m3[9]["vlans"] == [], str(m3))
# empty both
check("map empty", owctl.build_switch_map({}, {}) == {})
# named-token fallback (name -> idx via status); tagged = name+'t' appended
m4 = owctl.build_switch_map({"0": {"ports": ["lan1", "want"], "tag": None}},
                            {0: {"name": "lan1", "up": True}, 3: {"name": "wan", "up": True}})
check("map named tokens", m4[0]["vlans"] == [{"id": 0, "tagged": False}]
      and m4[3]["vlans"] == [{"id": 0, "tagged": True}], str(m4))

# ---- /api/switch-map endpoint (readers mocked) ----
execute("INSERT INTO devices(name,host,role,access) VALUES('Switch-A','10.0.0.9','router','ssh')")
execute("INSERT INTO devices(name,host,role,access) VALUES('AP-Only','10.0.0.10','router','luci')")
a = q("SELECT id FROM devices WHERE host='10.0.0.9'")[0]["id"]

owctl.read_switch_ports = lambda dev: {
    "name": dev.get("name"), "host": dev.get("host"),
    "switches": {"switch0": {
        "0": {"ports": ["0", "1", "3t"], "tag": None},
        "2": {"ports": ["2", "1t"], "tag": None},
    }}, "error": None}
owctl.read_switch_port_map = lambda dev: {
    0: {"name": "lan1", "up": True}, 1: {"name": "lan2", "up": False},
    2: {"name": "lan3", "up": True}, 3: {"name": "wan", "up": True}}

st = client.get("/api/switch-map")
check("GET /switch-map -> 200", st.status_code == 200, str(st.status_code))
body = st.json()
check("device_count=2", body.get("device_count") == 2, str(body.get("device_count")))
check("switch_devices=1", body.get("switch_devices") == 1, str(body.get("switch_devices")))
sw = [d for d in body["devices"] if d["device_id"] == a][0]
check("switch has_switch", sw["has_switch"] is True, str(sw))
check("switch port_count=4", sw["port_count"] == 4, str(sw["port_count"]))
check("switch linked=3", sw["linked"] == 3, str(sw["linked"]))
check("switch port 1 (lan2) in 2 vlans",
      len(sw["ports"]["1"]["vlans"]) == 2, str(sw["ports"].get("1")))
check("switch port 1 (lan2) vlan2 tagged",
      any(v["id"] == 2 and v["tagged"] for v in sw["ports"]["1"]["vlans"]),
      str(sw["ports"].get("1")))
check("switch port 3 (wan) vlan0 tagged",
      any(v["id"] == 0 and v["tagged"] for v in sw["ports"]["3"]["vlans"]),
      str(sw["ports"].get("3")))
ap = [d for d in body["devices"] if d["name"] == "AP-Only"][0]
check("ap-only has_switch=False", ap["has_switch"] is False, str(ap))
check("ap-only ports empty", ap["ports"] == {}, str(ap["ports"]))
check("ap-only error=luci-only", ap["error"] == "luci-only", str(ap["error"]))

print()
if FAILS:
    print(f"FAILED: {len(FAILS)} check(s)")
    for f in FAILS:
        print("  - " + f)
    os.system(f"rm -rf {os.environ['OWCTL_DATA']}")
    sys.exit(1)
print(f"ALL SWITCH-MAP CHECKS PASSED ({len(FAILS)} failures)")
os.system(f"rm -rf {os.environ['OWCTL_DATA']}")
