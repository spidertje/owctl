# Copyright (C) 2026 spidertje
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""checks_switch_ports.py — verify switch-port VLAN tagging: parser, reader,
endpoint, validation, plus VLAN membership ledger + CIDR L3 in do_vlan."""
import os
os.environ["OWCTL_DATA"] = "/tmp/owctl-swport-test-" + str(os.getpid())
os.environ["OWCTL_ALLOW_OPEN"] = "1"
os.makedirs(os.environ["OWCTL_DATA"], exist_ok=True)
import importlib
import owctl
importlib.reload(owctl)
from starlette.testclient import TestClient

client = TestClient(owctl.app)
passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"PASS {name}")
    else: failed += 1; print(f"FAIL {name}")

did = owctl.execute("INSERT INTO devices(name, host, access, added_at) VALUES(?,?,?,?)",
                    ("sw1", "192.0.2.10", "ssh", owctl.now()))

# ---- 1. pure parser ----
SAMPLE = """switch.switch0=name='switch0'
switch.switch0.reset=1
switch.switch0.vlan0='0'
switch.switch0.vlan0.device='switch0'
switch.switch0.vlan0.ports='0 1t'
switch.switch0.vlan2='2'
switch.switch0.vlan2.device='switch0'
switch.switch0.vlan2.ports='1 3 4'
switch.switch0.vlan10='10'
switch.switch0.vlan10.ports='5t'"""
pv = owctl.parse_switch_vlans(SAMPLE)
check("parser: vlan0 has ports", pv.get("0", {}).get("ports") == ["0", "1t"])
check("parser: vlan0 tag detected", pv.get("0", {}).get("tag") == 1)
check("parser: vlan2 ports", sorted(pv.get("2", {}).get("ports", [])) == ["1", "3", "4"])
check("parser: vlan2 no tag", pv.get("2", {}).get("tag") is None)
check("parser: vlan10 single tagged port", pv.get("10", {}).get("ports") == ["5t"]
      and pv.get("10", {}).get("tag") == 5)
check("parser: empty input -> {}", owctl.parse_switch_vlans("") == {})
check("parser: garbage -> {}", owctl.parse_switch_vlans("network.lan=interface") == {})

# ---- 2. CIDR L3 helper (the 1.1 fix's dependency) ----
check("parse_subnet /24", owctl._parse_subnet("192.168.10.0/24") == ("192.168.10.1", "255.255.255.0"))
check("parse_subnet /27 (old table would have failed)",
      owctl._parse_subnet("192.168.10.0/27") == ("192.168.10.1", "255.255.255.224"))
check("parse_subnet /16", owctl._parse_subnet("10.20.0.0/16") == ("10.20.0.1", "255.255.0.0"))
check("parse_subnet /30", owctl._parse_subnet("192.168.50.0/30") == ("192.168.50.1", "255.255.255.252"))
check("parse_subnet garbage -> None", owctl._parse_subnet("nope") is None)

# ---- 3. GET switch-ports via monkeypatched reader ----
owctl.read_switch_ports = lambda dev: {"name": "sw1", "host": "192.0.2.10",
                                       "switches": {"switch0": pv}, "error": None}
r = client.get(f"/api/devices/{did}/switch-ports")
check("GET switch-ports 200", r.status_code == 200)
check("GET switch-ports shape",
      r.json()["device"] == "sw1" and r.json()["switches"]["switch0"]["2"]["ports"] == ["1", "3", "4"])

# reader reports no switch package -> empty map, not an error
owctl.read_switch_ports = lambda dev: {"name": "ap1", "host": "192.0.2.11",
                                       "switches": {}, "error": None}
r = client.get(f"/api/devices/{did}/switch-ports")
check("GET no switch package -> empty map", r.status_code == 200 and r.json()["switches"] == {})

# ---- 4. POST switch-ports (do_vlan_port mocked) ----
real_do_vlan_port = owctl.do_vlan_port
calls = []
def mock_port(dev, switch_dev, vlan_id, ports, tag=None, apply=True):
    calls.append(dict(switch=switch_dev, vlan=vlan_id, ports=ports, tag=tag, apply=apply))
    return {"device": dev["name"], "ok": True, "switch": switch_dev,
            "vlan": vlan_id, "ports": ports}
owctl.do_vlan_port = mock_port
r = client.post(f"/api/devices/{did}/switch-ports",
                json={"vlan_id": 20, "ports": ["1", "2"], "tag": 1})
check("POST switch-ports 200", r.status_code == 200 and r.json()["ok"])
check("POST forwards args", calls and calls[-1]["vlan"] == 20
      and calls[-1]["ports"] == ["1", "2"] and calls[-1]["tag"] == 1
      and calls[-1]["apply"] is True)

r = client.post(f"/api/devices/{did}/switch-ports",
                json={"vlan_id": 20, "ports": ["1"], "apply": False})
check("POST save-only passes apply=False", calls[-1]["apply"] is False)

r = client.post(f"/api/devices/{did}/switch-ports", json={"ports": ["1"]})
check("POST missing vlan_id -> 400", r.status_code == 400)

# ---- 5. do_vlan_port validation (real function, no SSH needed — 400s first) ----
owctl.do_vlan_port = real_do_vlan_port  # undo section 4's mock
from fastapi import HTTPException
def expect_400(fn):
    try:
        fn(); return False
    except HTTPException as e:
        return e.status_code == 400
devrow = client.get(f"/api/devices/{did}").json() if False else owctl.q(
    "SELECT * FROM devices WHERE id=?", (did,))[0]
check("do_vlan_port: bad port token -> 400", expect_400(lambda: owctl.do_vlan_port(devrow, "switch0", 20, ["abc"])))
check("do_vlan_port: bad switch name -> 400", expect_400(lambda: owctl.do_vlan_port(devrow, "sw 0", 20, ["1"])))
check("do_vlan_port: vlan 0 -> 400", expect_400(lambda: owctl.do_vlan_port(devrow, "switch0", 0, ["1"])))
check("do_vlan_port: vlan 9999 -> 400", expect_400(lambda: owctl.do_vlan_port(devrow, "switch0", 9999, ["1"])))
check("do_vlan_port: empty ports -> 400", expect_400(lambda: owctl.do_vlan_port(devrow, "switch0", 20, [])))

# ---- 6. membership ledger (1.2) ----
owctl.record_vlan_membership("10", did, "router")
m = owctl.vlan_members("10")
check("membership recorded", len(m) == 1 and m[0]["device_id"] == did and m[0]["role"] == "router")
owctl.record_vlan_membership("10", did, "switch")  # upsert role
m = owctl.vlan_members("10")
check("membership upsert role", len(m) == 1 and m[0]["role"] == "switch")

# drive the endpoint's upsert path with a mocked do_vlan (no real SSH)
owctl.do_vlan = lambda dev, vid, name, subnet, dhcp, devices, rid, apply=True: {
    "device": dev["name"], "role": "router", "ok": True}
r = client.post("/api/vlans/apply", json={"vlan_id": 30, "name": "vlan_30",
                                          "subnet": "192.168.30.0/24", "dhcp": True,
                                          "devices": [did], "router_id": did})
check("apply still ok with mocked do_vlan", r.status_code == 200 and r.json()["results"][0]["ok"])
# the real do_vlan path (unmocked) is exercised in checks_vlans.py; here assert
# the ledger helper + list_vlans shape
vl = [v for v in client.get("/api/vlans").json() if v["id"] == "30"]
check("list_vlans exposes members key", vl and "members" in vl[0])

# ---- 7. VLAN delete: pure cmd builder ----
cmds = owctl.vlan_delete_cmds(10)
check("delete cmds: network section", "uci delete network.vlan_10" in cmds)
check("delete cmds: firewall zone", "uci delete firewall.vlan_10" in cmds)
check("delete cmds: dhcp loop matches vlan_10", "vlan_10" in cmds and "uci delete $s" in cmds)
check("delete cmds: no switch package touched", "switch." not in cmds)
check("delete cmds: idempotent guards", cmds.count("|| true") >= 5)
check("delete cmds: distinct vlan id", "vlan_10" not in owctl.vlan_delete_cmds(20)
      and "vlan_20" in owctl.vlan_delete_cmds(20))

# ---- 8. VLAN delete endpoint ----
owctl.do_vlan_delete = lambda dev, vid, apply=True: {"device": dev["name"], "ok": True}
owctl.record_vlan_membership("40", did, "router")
check("ledger seeded for delete test", len(owctl.vlan_members("40")) == 1)
r = client.post("/api/vlans/delete", json={"vlan_id": 40})
check("delete 200 + ok", r.status_code == 200 and r.json()["results"][0]["ok"])
check("delete clears membership", owctl.vlan_members("40") == [])

# delete with no members and no devices -> falls back to all ssh devices
owctl.execute("INSERT INTO vlans(vlan_id, name, subnet, dhcp, created_at) VALUES(?,?,?,?,?)",
              ("50", "vlan_50", None, 0, owctl.now()))
r = client.post("/api/vlans/delete", json={"vlan_id": 50})
check("delete discovered vlan (no members) still runs on ssh devices",
      r.status_code == 200 and len(r.json()["results"]) >= 1)
check("delete removes vlan row", all(v["id"] != "50" for v in client.get("/api/vlans").json()))

# missing vlan_id -> 400
r = client.post("/api/vlans/delete", json={})
check("delete missing vlan_id -> 400", r.status_code == 400)

# failed delete NOT removed from vlans table
owctl.do_vlan_delete = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("ssh down"))
owctl.execute("INSERT INTO vlans(vlan_id, name, subnet, dhcp, created_at) VALUES(?,?,?,?,?)",
              ("60", "vlan_60", None, 0, owctl.now()))
r = client.post("/api/vlans/delete", json={"vlan_id": 60, "devices": [did]})
check("failed delete reported", r.status_code == 200 and not r.json()["results"][0]["ok"])
check("failed delete keeps vlan row", any(v["id"] == "60" for v in client.get("/api/vlans").json()))

# ---- 9. VLAN edit: read-back endpoint (edit prefill + verify) ----
# First: the REAL read_vlan_state, with only _exec_capture faked — proves the
# parser-reuse logic (the load-bearing part), not just endpoint plumbing.
SAMPLE_NET = """network.vlan_10=interface
network.vlan_10.proto=static
network.vlan_10.ipaddr='192.168.10.1'
network.vlan_10.netmask='255.255.255.0'
network.vlan_10.ifname='br-lan.10'
network.vlan_10.vlan='10'"""
SAMPLE_DHCP = """dhcp.vlan_10=dhcp
dhcp.vlan_10.interface='vlan_10'
dhcp.vlan_10.start='100'
dhcp.vlan_10.limit='150'"""
SAMPLE_FW = """firewall.vlan_10=zone
firewall.vlan_10.name='vlan_10'
firewall.vlan_10.network='vlan_10'
firewall.vlan_10.input='ACCEPT'
firewall.vlan_10.output='ACCEPT'
firewall.vlan_10.forward='REJECT'"""
real_exec_capture = owctl._exec_capture
real_ssh_connect = owctl._ssh_connect
def fake_exec_capture(c, cmd, timeout=30):
    if cmd.startswith("uci show network"):
        return SAMPLE_NET, "", 0
    if cmd.startswith("uci show dhcp"):
        return SAMPLE_DHCP, "", 0
    if cmd.startswith("uci show firewall"):
        return SAMPLE_FW, "", 0
    return "", "", 0
class _FakeConn:
    def close(self): pass
owctl._exec_capture = fake_exec_capture
owctl._ssh_connect = lambda dev: _FakeConn()
try:
    rs = owctl.read_vlan_state(owctl.q("SELECT * FROM devices WHERE id=?", (did,))[0], 10)
finally:
    owctl._exec_capture = real_exec_capture
    owctl._ssh_connect = real_ssh_connect
check("real read_vlan_state: subnet from parser", rs.get("subnet") == "192.168.10.0/24")
check("real read_vlan_state: dhcp true", rs.get("dhcp") is True)
check("real read_vlan_state: zone policy parsed",
      rs.get("zone") == {"input": "ACCEPT", "output": "ACCEPT", "forward": "REJECT"})
check("real read_vlan_state: no error", rs.get("error") is None)
# endpoint plumbing (read_vlan_state mocked) ----
owctl.read_vlan_state = lambda dev, vid: {"name": dev["name"], "host": dev["host"],
    "vlan_id": str(vid), "subnet": "192.168.10.0/24", "dhcp": True,
    "zone": {"input": "ACCEPT", "output": "ACCEPT", "forward": "REJECT"}, "error": None}
r = client.get(f"/api/devices/{did}/vlans/10")
check("read vlan state 200", r.status_code == 200)
check("read vlan state configured", r.json()["configured"] is True
      and r.json()["subnet"] == "192.168.10.0/24" and r.json()["dhcp"] is True)
check("read vlan state zone policy", r.json()["zone"]["forward"] == "REJECT")
# VLAN not configured -> configured:False, no error
owctl.read_vlan_state = lambda dev, vid: {"name": dev["name"], "host": dev["host"],
    "vlan_id": str(vid), "subnet": None, "dhcp": False, "zone": None, "error": None}
r = client.get(f"/api/devices/{did}/vlans/99")
check("read unconfigured vlan -> configured False", r.status_code == 200
      and r.json()["configured"] is False)
# reader error (ssh down) -> 502
owctl.read_vlan_state = lambda dev, vid: {"name": dev["name"], "host": dev["host"],
    "vlan_id": str(vid), "error": "ssh down"}
r = client.get(f"/api/devices/{did}/vlans/10")
check("read vlan state ssh error -> 502", r.status_code == 502)

print(f"\n=== SUMMARY ===\n{passed}/{passed+failed} checks passed")
print("ALL SWITCH-PORT CHECKS PASSED" if failed == 0 else "SOME CHECKS FAILED")
os.system(f"rm -rf {os.environ['OWCTL_DATA']}")
import sys; sys.exit(1 if failed else 0)
