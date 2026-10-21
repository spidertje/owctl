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
"""checks_pending_network.py — network-wide pending-apply overview + apply-all."""
import os
os.environ["OWCTL_DATA"] = "/tmp/owctl-pend-test-" + str(os.getpid())
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

# two devices, seed pending entries on both
d1 = owctl.execute("INSERT INTO devices(name, host, access, added_at) VALUES(?,?,?,?)",
                   ("r1", "192.0.2.1", "ssh", owctl.now()))
d2 = owctl.execute("INSERT INTO devices(name, host, access, added_at) VALUES(?,?,?,?)",
                   ("sw1", "192.0.2.2", "ssh", owctl.now()))
owctl.execute("INSERT INTO pending_applies(device_id, feature, restart_cmd, saved_at) VALUES(?,?,?,?)",
              (d1, "vlan", "netifd restart", owctl.now()))
owctl.execute("INSERT INTO pending_applies(device_id, feature, restart_cmd, saved_at) VALUES(?,?,?,?)",
              (d2, "firewall", "fw4 restart", owctl.now()))
owctl.execute("INSERT INTO pending_applies(device_id, feature, restart_cmd, saved_at) VALUES(?,?,?,?)",
              (d2, "qos", "sqm restart", owctl.now()))

# ---- 1. empty state (fresh device, no pending) ----
d3 = owctl.execute("INSERT INTO devices(name, host, access, added_at) VALUES(?,?,?,?)",
                   ("clean", "192.0.2.3", "ssh", owctl.now()))
r = client.get(f"/api/devices/{d3}/pending-applies")
check("per-device no pending -> count 0", r.status_code == 200 and r.json()["count"] == 0)

# ---- 2. GET /api/pending overview ----
r = client.get("/api/pending")
j = r.json()
check("pending overview 200", r.status_code == 200)
check("pending overview count", j["count"] == 3)
check("pending overview devices", j["devices"] == 2)
check("pending overview feature union", j["features"] == ["firewall", "qos", "vlan"])
by_dev = {x["device_id"]: x for x in j["items"]}
check("r1 has vlan", by_dev.get(d1, {}).get("features") == ["vlan"])
check("sw1 has firewall+qos", sorted(by_dev.get(d2, {}).get("features", [])) == ["firewall", "qos"])
check("clean device excluded", d3 not in by_dev)

# ---- 3. POST /api/pending/apply (mock the SSH-gated op) ----
applied = []
def mock_apply(dev):
    feats = owctl.pending_apply_for(dev)
    applied.append(dev["name"])
    for f in feats:
        owctl.clear_pending_apply(dev, f["feature"])
    return {"device": dev["name"], "ok": True,
            "applied": sorted({f["feature"] for f in feats})}
owctl.apply_pending_for = mock_apply
r = client.post("/api/pending/apply", json={})
j = r.json()
check("apply-all 200", r.status_code == 200)
check("apply-all applied 2 devices", j["applied"] == 2 and j["failed"] == 0)
check("apply-all cleared both", "r1" in applied and "sw1" in applied)
# after apply, pending cleared
r = client.get("/api/pending")
check("pending overview empty after apply", r.json()["count"] == 0)

# ---- 4. scoped apply ----
owctl.execute("INSERT INTO pending_applies(device_id, feature, restart_cmd, saved_at) VALUES(?,?,?,?)",
              (d1, "dhcp", "/etc/init.d/odhcpd reload", owctl.now()))
applied.clear()
r = client.post("/api/pending/apply", json={"devices": [d1]})
j = r.json()
check("scoped apply only r1", j["applied"] == 1 and applied == ["r1"])

# ---- 5. failure isolation: one device errors, others still apply ----
def flaky(dev):
    if dev["name"] == "sw1":
        raise RuntimeError("ssh down")
    feats = owctl.pending_apply_for(dev)
    applied.append(dev["name"])
    for f in feats:
        owctl.clear_pending_apply(dev, f["feature"])
    return {"device": dev["name"], "ok": True, "applied": []}
owctl.apply_pending_for = flaky
owctl.execute("INSERT INTO pending_applies(device_id, feature, restart_cmd, saved_at) VALUES(?,?,?,?)",
              (d2, "qos", "sqm restart", owctl.now()))
owctl.execute("INSERT INTO pending_applies(device_id, feature, restart_cmd, saved_at) VALUES(?,?,?,?)",
              (d1, "vlan", "netifd restart", owctl.now()))
r = client.post("/api/pending/apply", json={})
j = r.json()
check("failure isolated: 1 ok 1 failed", j["applied"] == 1 and j["failed"] == 1)
check("failure reported", any(not x.get("ok") and "error" in x for x in j["results"]))

# ---- 6. per-device apply still works (regression) ----
owctl.apply_pending_for = lambda dev: {"device": dev["name"], "ok": True, "applied": []}
r = client.post(f"/api/devices/{d1}/pending-apply")
check("per-device apply 200", r.status_code == 200 and r.json()["ok"])

print(f"\n=== SUMMARY ===\n{passed}/{passed+failed} checks passed")
print("ALL PENDING-NETWORK CHECKS PASSED" if failed == 0 else "SOME CHECKS FAILED")
os.system(f"rm -rf {os.environ['OWCTL_DATA']}")
import sys; sys.exit(1 if failed else 0)
