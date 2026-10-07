"""checks_vlans.py — verify GET /api/vlans + record-on-apply behavior."""
import os
os.environ["OWCTL_DATA"] = "/tmp/owctl-vlans-test-" + str(os.getpid())
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

# 1. empty state -> []
r = client.get("/api/vlans")
check("empty state returns []", r.status_code == 200 and r.json() == [])

# 2. successful apply records the vlan
did = owctl.execute("INSERT INTO devices(name, host, access, added_at) VALUES(?,?,?,?)",
                    ("r1", "192.0.2.1", "ssh", owctl.now()))
owctl.do_vlan = lambda dev, vid, name, subnet, dhcp, devices, rid: {
    "device": dev["name"], "role": "router", "ok": True}
r = client.post("/api/vlans/apply", json={"vlan_id": 10, "name": "vlan_10",
                                          "subnet": "192.168.10.0/24", "dhcp": True,
                                          "devices": [did], "router_id": did})
check("apply with ok result succeeds", r.status_code == 200 and r.json()["results"][0]["ok"])
r = client.get("/api/vlans")
vlans = r.json()
check("vlan recorded after successful apply",
      len(vlans) == 1 and vlans[0]["id"] == "10" and vlans[0]["name"] == "vlan_10"
      and vlans[0]["subnet"] == "192.168.10.0/24" and vlans[0]["dhcp"] is True)

# 3. upsert: re-applying same vlan updates, does not duplicate
r = client.post("/api/vlans/apply", json={"vlan_id": 10, "name": "vlan_10b",
                                          "subnet": "192.168.11.0/24", "dhcp": False,
                                          "devices": [did], "router_id": did})
r = client.get("/api/vlans")
vlans = r.json()
check("re-apply upserts (no dup, updated fields)",
      len(vlans) == 1 and vlans[0]["name"] == "vlan_10b"
      and vlans[0]["subnet"] == "192.168.11.0/24" and vlans[0]["dhcp"] is False)

# 4. failed apply does NOT record
owctl.do_vlan = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("ssh down"))
r = client.post("/api/vlans/apply", json={"vlan_id": 99, "name": "vlan_99",
                                          "subnet": "10.0.99.0/24", "dhcp": True,
                                          "devices": [did], "router_id": did})
check("failed apply reported", r.status_code == 200 and not r.json()["results"][0]["ok"])
r = client.get("/api/vlans")
check("failed apply not recorded", all(v["id"] != "99" for v in r.json()))

# 5. ordering: add vlan 2, expect 10 first (numeric desc)
owctl.execute("INSERT INTO vlans(vlan_id, name, subnet, dhcp, created_at) VALUES(?,?,?,?,?)",
              ("2", "vlan_2", "192.168.2.0/24", 1, owctl.now()))
r = client.get("/api/vlans")
check("ordered numerically desc", [v["id"] for v in r.json()] == ["10", "2"])

print(f"\n=== SUMMARY ===\n{passed}/{passed+failed} checks passed")
print("ALL VLAN CHECKS PASSED" if failed == 0 else "SOME CHECKS FAILED")
os.system(f"rm -rf {os.environ['OWCTL_DATA']}")
import sys; sys.exit(1 if failed else 0)
