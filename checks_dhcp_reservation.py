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
"""checks_dhcp_reservation.py — IP reservations: pure helpers + endpoints."""
import os
os.environ["OWCTL_DATA"] = "/tmp/owctl-resv-test-" + str(os.getpid())
os.environ["OWCTL_ALLOW_OPEN"] = "1"
os.makedirs(os.environ["OWCTL_DATA"], exist_ok=True)
import importlib
import owctl
importlib.reload(owctl)
from starlette.testclient import TestClient
from fastapi import HTTPException

client = TestClient(owctl.app)
passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print(f"PASS {name}")
    else: failed += 1; print(f"FAIL {name}")

did = owctl.execute("INSERT INTO devices(name, host, access, added_at) VALUES(?,?,?,?)",
                    ("r1", "192.0.2.1", "ssh", owctl.now()))

# ---- 1. parse_mac ----
check("parse_mac valid", owctl.parse_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff")
check("parse_mac dashes", owctl.parse_mac("aa-bb-cc-dd-ee-ff") == "aa:bb:cc:dd:ee:ff")
check("parse_mac garbage", owctl.parse_mac("zz:bb:cc:dd:ee:ff") is None)
check("parse_mac short", owctl.parse_mac("aabbccddeeff") is None)
check("parse_mac None", owctl.parse_mac(None) is None)

# ---- 2. merge_leases ----
out = owctl.merge_leases([], "printer", "aa:bb:cc:dd:ee:01", "192.168.10.50")
check("merge new appends", out == [{"name": "printer", "mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.10.50"}])
existing = [{"name": "printer", "mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.10.50"},
            {"name": "cam", "mac": "11:22:33:44:55:66", "ip": "192.168.10.60"}]
out = owctl.merge_leases(existing, "printer", "AA:BB:CC:DD:EE:01", "192.168.10.99")
check("merge same MAC replaces ip", len(out) == 2 and
      [x for x in out if x["mac"] == "aa:bb:cc:dd:ee:01"][0]["ip"] == "192.168.10.99")
try:
    owctl.merge_leases(existing, "x", "badmac", "1.2.3.4"); bad = False
except HTTPException as e:
    bad = e.status_code == 400
check("merge bad MAC -> 400", bad)

# ---- 3. remove_leases ----
out = owctl.remove_leases(existing, "11:22:33:44:55:66")
check("remove by MAC", len(out) == 1 and out[0]["mac"] == "aa:bb:cc:dd:ee:01")
out = owctl.remove_leases(existing, "99:99:99:99:99:99")
check("remove unknown -> unchanged", len(out) == 2)

# ---- 4. validate_reservation ----
check("valid ok", owctl.validate_reservation("192.168.10.50", "aa:bb:cc:dd:ee:01",
      subnet="192.168.10.0/24", gateway_ip="192.168.10.1") is None)
check("out of subnet", "not in subnet" in owctl.validate_reservation(
      "192.168.99.50", "aa:bb:cc:dd:ee:01", subnet="192.168.10.0/24") or False)
check("gateway collision", "gateway" in owctl.validate_reservation(
      "192.168.10.1", "aa:bb:cc:dd:ee:01", subnet="192.168.10.0/24",
      gateway_ip="192.168.10.1"))
check("dup ip other MAC", "already reserved" in owctl.validate_reservation(
      "192.168.10.60", "aa:bb:cc:dd:ee:01", subnet="192.168.10.0/24",
      leases=[{"name": "cam", "mac": "11:22:33:44:55:66", "ip": "192.168.10.60"}]))
check("same-MAC re-reserve ok", owctl.validate_reservation(
      "192.168.10.61", "11:22:33:44:55:66", subnet="192.168.10.0/24",
      leases=[{"name": "cam", "mac": "11:22:33:44:55:66", "ip": "192.168.10.60"}]) is None)
check("bad ip", "invalid IP" in owctl.validate_reservation("nope", "aa:bb:cc:dd:ee:01"))

# ---- 5. merge_known_devices ----
devs = owctl.merge_known_devices(
    leases=[{"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.10.50", "hostname": "printer"}],
    neighbors=[{"ip": "192.168.10.70", "iface": "br-lan", "mac": "99:88:77:66:55:44"}],
    reservations=[{"name": "cam", "mac": "11:22:33:44:55:66", "ip": "192.168.10.60"}])
check("merged 3 devices", len(devs) == 3)
by_mac = {d["mac"]: d for d in devs}
check("printer from lease", by_mac["aa:bb:cc:dd:ee:01"]["name"] == "printer"
      and by_mac["aa:bb:cc:dd:ee:01"]["current_ip"] == "192.168.10.50"
      and by_mac["aa:bb:cc:dd:ee:01"]["sources"] == ["lease"])
check("arp-only device", by_mac["99:88:77:66:55:44"]["current_ip"] == "192.168.10.70"
      and by_mac["99:88:77:66:55:44"]["sources"] == ["arp"]
      and by_mac["99:88:77:66:55:44"]["reserved"] is False)
check("reserved flag", by_mac["11:22:33:44:55:66"]["reserved"] is True
      and by_mac["11:22:33:44:55:66"]["reserved_ip"] == "192.168.10.60")

# ---- 6. build_lease_cmds ----
cmds = owctl.build_lease_cmds("vlan_10", [{"name": "printer", "mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.10.50"}])
check("lease cmds: del old", "uci del dhcp.vlan_10.dhcp_host" in cmds)
check("lease cmds: add dnsmasq", "uci add_list dhcp.vlan_10.dhcp_host='printer, aa:bb:cc:dd:ee:01, 192.168.10.50'" in cmds)
check("lease cmds: mirror odhcpd", "uci add_list dhcp.vlan_10.host=" in cmds)
check("lease cmds: commit", "uci commit dhcp" in cmds)
check("lease cmds: reload", "odhcpd reload" in cmds)
try:
    owctl.build_lease_cmds("bad iface", []); bad = False
except HTTPException as e:
    bad = e.status_code == 400
check("lease cmds bad iface -> 400", bad)

# ---- 7. GET /api/dhcp/devices ----
owctl.read_arp_neighbors = lambda dev: [{"ip": "192.168.10.70", "iface": "br-lan", "mac": "99:88:77:66:55:44"}]
r = client.get(f"/api/dhcp/devices?did={did}")
check("GET dhcp/devices 200", r.status_code == 200)
check("GET dhcp/devices shape", "device" in r.json() and "devices" in r.json()
      and r.json()["arp_count"] == 1)
r = client.get("/api/dhcp/devices")
check("GET dhcp/devices missing did -> 400", r.status_code == 400)

# ---- 8. POST /api/dhcp/reserve (mock _read_live_dhcp + exec) ----
owctl._read_live_dhcp = lambda dev: [
    {"vlan_id": 10, "iface": "vlan_10", "enabled": True,
     "static_leases": [{"name": "cam", "mac": "11:22:33:44:55:66", "ip": "192.168.10.60"}],
     "subnet": "192.168.10.0/24"}]
ran = []
def fake_exec_capture(c, cmd, timeout=60):
    ran.append(cmd)
    return "", "", 0
owctl._exec_capture = fake_exec_capture
class _FakeConn:
    def close(self): pass
owctl._ssh_connect = lambda dev: _FakeConn()
r = client.post("/api/dhcp/reserve", json={
    "did": did, "vlan_id": 10, "name": "printer",
    "mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.10.50"})
check("reserve 200", r.status_code == 200 and r.json()["ok"])
check("reserve merges existing lease", "printer" in ran[-1] and "cam" in ran[-1])
check("reserve lease count 2", r.json()["lease_count"] == 2)
# remove
r = client.post("/api/dhcp/reserve", json={
    "did": did, "vlan_id": 10, "name": "cam",
    "mac": "11:22:33:44:55:66", "ip": "192.168.10.60", "remove": True})
check("release 200", r.status_code == 200 and r.json()["ok"] and r.json()["removed"])
check("release removed cam", "cam" not in ran[-1])
# out of subnet -> 400
r = client.post("/api/dhcp/reserve", json={
    "did": did, "vlan_id": 10, "name": "x",
    "mac": "aa:bb:cc:dd:ee:02", "ip": "10.99.0.5"})
check("reserve out-of-subnet -> 400", r.status_code == 400)
# missing ip -> 400
r = client.post("/api/dhcp/reserve", json={
    "did": did, "vlan_id": 10, "name": "x", "mac": "aa:bb:cc:dd:ee:02"})
check("reserve missing ip -> 400", r.status_code == 400)
# bad mac -> 400
r = client.post("/api/dhcp/reserve", json={
    "did": did, "vlan_id": 10, "name": "x", "mac": "nope", "ip": "192.168.10.70"})
check("reserve bad mac -> 400", r.status_code == 400)
# save-only passes apply=False
owctl._read_live_dhcp = lambda dev: [{"vlan_id": 10, "iface": "vlan_10", "enabled": True,
    "static_leases": [], "subnet": "192.168.10.0/24"}]
r = client.post("/api/dhcp/reserve", json={
    "did": did, "vlan_id": 10, "name": "printer",
    "mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.10.50", "apply": False})
check("save-only no reload", "odhcpd reload" not in ran[-1] and "uci commit dhcp" in ran[-1])

print(f"\n=== SUMMARY ===\n{passed}/{passed+failed} checks passed")
print("ALL RESERVATION CHECKS PASSED" if failed == 0 else "SOME CHECKS FAILED")
os.system(f"rm -rf {os.environ['OWCTL_DATA']}")
import sys; sys.exit(1 if failed else 0)
