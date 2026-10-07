"""checks_vlans_discover.py — verify VLAN discovery: parser + subnet/dhcp autofill + endpoint."""
import os
os.environ["OWCTL_DATA"] = "/tmp/owctl-disc-test-" + str(os.getpid())
os.makedirs(os.environ["OWCTL_DATA"], exist_ok=True)
import importlib, owctl
importlib.reload(owctl)
from starlette.testclient import TestClient
client = TestClient(owctl.app)
passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"PASS {name}")
    else: failed += 1; print(f"FAIL {name}")

# ---- netmask_to_prefix ----
check("netmask /24", owctl.netmask_to_prefix("255.255.255.0") == 24)
check("netmask /16", owctl.netmask_to_prefix("255.255.0.0") == 16)
check("netmask /30", owctl.netmask_to_prefix("255.255.255.252") == 30)
check("netmask garbage -> None", owctl.netmask_to_prefix("nope") is None)
check("netmask None -> None", owctl.netmask_to_prefix(None) is None)

# ---- parse_vlan_ids (regression) ----
SAMPLE = """
network.lan=interface
network.lan.proto=dhcp
network.lan.vlan='10'
network.lan2=interface
network.lan2.ifname=br-lan.2
network.lan2.vlan='2'
network.vlan_40=switch
network.vlan_40.device=switch0
network.vlan_40.vlan='40'
network.vlan_0=switch
network.vlan_0.vlan='0'
"""
check("parse_vlan_ids extracts 2,10,40 (skips 0)", owctl.parse_vlan_ids(SAMPLE) == [2, 10, 40])
check("parse_vlan_ids empty -> []", owctl.parse_vlan_ids("") == [])
check("parse_vlan_ids dedupes", owctl.parse_vlan_ids("a.vlan='5'\nb.vlan='5'") == [5])
check("parse_vlan_ids unquoted", owctl.parse_vlan_ids("x.vlan=7") == [7])

# ---- parse_vlan_details: subnet + dhcp autofill ----
NET = """
network.lan=interface
network.lan.proto=static
network.lan.ipaddr=192.168.50.1
network.lan.netmask=255.255.255.0
network.lan.ifname=br-lan.50
network.lan.vlan='50'

network.vlan_50=switch
network.vlan_50.device=switch0
network.vlan_50.vlan='50'
"""
DHC = """
dhcp.lan=dhcp
dhcp.lan.interface=lan
dhcp.lan.start=100
dhcp.lan.limit=150
"""
d = owctl.parse_vlan_details(NET, DHC)
check("details: vlan 50 present", 50 in d)
check("details: subnet autofilled 192.168.50.0/24", d[50]["subnet"] == "192.168.50.0/24")
check("details: dhcp True (dhcp.lan.interface=lan)", d[50]["dhcp"] is True)

d2 = owctl.parse_vlan_details("network.v=switch\nnetwork.v.device=switch0\nnetwork.v.vlan='7'\n")
check("details: switch-only VLAN absent (no interface)", 7 not in d2)
check("details: switch-only -> empty dict", d2 == {})

d3 = owctl.parse_vlan_details(
    "network.x=interface\nnetwork.x.proto=static\nnetwork.x.ipaddr=10.1.2.1\nnetwork.x.netmask=255.255.255.0\nnetwork.x.vlan='30'\n",
    "dhcp.other=dhcp\ndhcp.other.interface=other\n")
check("details: dhcp on other iface -> False", d3[30]["dhcp"] is False)
check("details: still autofills subnet", d3[30]["subnet"] == "10.1.2.0/24")

# ---- endpoint: merged subnet/dhcp persisted ----
did = owctl.execute("INSERT INTO devices(name, host, access, added_at) VALUES(?,?,?,?)",
                    ("r1", "192.0.2.1", "ssh", owctl.now()))
owctl.discover_vlans = lambda dev: {
    "name": dev.get("name"), "host": dev["host"],
    "vlans": [40],
    "details": {40: {"subnet": "192.168.40.0/24", "dhcp": True}},
    "error": None}
r = client.post("/api/vlans/discover", json={})
j = r.json()
check("endpoint found vlan 40", j["vlans_found"] == [40])
r2 = client.get("/api/vlans")
v40 = [v for v in r2.json() if v["id"] == "40"][0]
check("endpoint persisted subnet", v40["subnet"] == "192.168.40.0/24")
check("endpoint persisted dhcp", v40["dhcp"] is True)

# discovery must not clobber an apply-set value on re-run (COALESCE keeps old)
owctl.execute("UPDATE vlans SET subnet='192.168.41.0/24', dhcp=1, name='vlan_40' WHERE vlan_id='40'")
owctl.discover_vlans = lambda dev: {
    "name": dev.get("name"), "host": dev["host"], "vlans": [40],
    "details": {40: {"subnet": None, "dhcp": False}}, "error": None}
r = client.post("/api/vlans/discover", json={})
r2 = client.get("/api/vlans")
v40 = [v for v in r2.json() if v["id"] == "40"][0]
check("re-discover preserves apply-set subnet", v40["subnet"] == "192.168.41.0/24")

# switch-only VLAN: in vlans but not details -> still recorded via union, subnet None
owctl.discover_vlans = lambda dev: {
    "name": dev.get("name"), "host": dev["host"],
    "vlans": [7], "details": {}, "error": None}
r = client.post("/api/vlans/discover", json={})
check("switch-only vlan 7 found via union", 7 in r.json()["vlans_found"])
r2 = client.get("/api/vlans")
v7 = [v for v in r2.json() if v["id"] == "7"][0]
check("switch-only vlan recorded, subnet None", v7["subnet"] is None)

print(f"\n=== SUMMARY ===\n{passed}/{passed+failed} checks passed")
print("ALL DISCOVER CHECKS PASSED" if failed == 0 else "SOME CHECKS FAILED")
import sys; sys.exit(1 if failed else 0)
