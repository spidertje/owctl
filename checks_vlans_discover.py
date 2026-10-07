"""checks_vlans_discover.py — verify VLAN discovery parser + endpoint + UI delete fix."""
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

# parse_vlan_ids: pure parser
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
check("parse_vlan_ids None -> []", owctl.parse_vlan_ids(None) == [])
check("parse_vlan_ids dedupes", owctl.parse_vlan_ids("a.vlan='5'\nb.vlan='5'") == [5])
check("parse_vlan_ids unquoted", owctl.parse_vlan_ids("x.vlan=7") == [7])

# endpoint: stub discover_vlans to return fixed vlans per device
did = owctl.execute("INSERT INTO devices(name, host, access, added_at) VALUES(?,?,?,?)",
                    ("r1", "192.0.2.1", "ssh", owctl.now()))
did2 = owctl.execute("INSERT INTO devices(name, host, access, added_at) VALUES(?,?,?,?)",
                     ("ap1", "192.0.2.2", "ssh", owctl.now()))
did_luci = owctl.execute("INSERT INTO devices(name, host, access, added_at) VALUES(?,?,?,?)",
                         ("l1", "192.0.2.3", "luci", owctl.now()))
owctl.discover_vlans = lambda dev: {
    "name": dev.get("name"), "host": dev["host"],
    "vlans": {"r1": [10, 20], "ap1": [10], "l1": []}.get(dev.get("name"), []),
    "error": None if dev.get("access") == "ssh" else "luci-only device skipped"}
r = client.post("/api/vlans/discover", json={})
j = r.json()
check("discover scans only ssh devices (2)", j["devices_scanned"] == 2)
check("discover found vlans 10,20 sorted desc", j["vlans_found"] == [20, 10])
check("discover returns vlans list shape", isinstance(j["vlans"], list) and
      all("id" in v for v in j["vlans"]) and {v["id"] for v in j["vlans"]} == {"10", "20"})
# persisted
r2 = client.get("/api/vlans")
check("discovered vlans persisted to /api/vlans",
      {v["id"] for v in r2.json()} == {"10", "20"})

# discovery must not clobber an existing apply-set subnet
owctl.execute("UPDATE vlans SET name='vlan_10', subnet='192.168.10.0/24', dhcp=1 WHERE vlan_id='10'")
r = client.post("/api/vlans/discover", json={})
r2 = client.get("/api/vlans")
v10 = [v for v in r2.json() if v["id"] == "10"][0]
check("re-discover preserves apply-set subnet", v10["subnet"] == "192.168.10.0/24" and v10["dhcp"] is True)

print(f"\n=== SUMMARY ===\n{passed}/{passed+failed} checks passed")
print("ALL DISCOVER CHECKS PASSED" if failed == 0 else "SOME CHECKS FAILED")
import sys; sys.exit(1 if failed else 0)
