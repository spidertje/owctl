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
#!/usr/bin/env python3
"""checks_mesh.py — mesh + packages feature verification for owctl.

Covers the three new pieces added in this pass:
  1. do_mesh() emits the right uci script (idempotent `mesh` section, mode=mesh,
     mesh=, htmode, channel, encryption, gateway flag) and disables cleanly.
  2. GET /api/devices/{did}/mesh reads live mesh uci sections back.
  3. GET /api/devices/{did}/packages returns installed/obsolete/meshd from the
     persisted device_status snapshot (no SSH round-trip after first gather).

Self-contained: throwaway OWCTL_DATA, reloads the app. Exits non-zero on failure.
"""
import os
os.environ["OWCTL_DATA"] = "/tmp/owctl-mesh-test-" + str(os.getpid())
os.makedirs(os.environ["OWCTL_DATA"], exist_ok=True)
os.environ["OWCTL_ALLOW_OPEN"] = "1"
import importlib
import owctl
importlib.reload(owctl)
from starlette.testclient import TestClient

client = TestClient(owctl.app)
passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print("PASS", name)
    else: failed += 1; print("FAIL", name)

# --- 1. do_mesh enabled: uci script shape ---
captured = {}
def fake_run(dev, cmd, action, detail, ok_msg):
    captured["cmd"] = cmd
    return {"device": dev["name"], "ok": True}
owctl._run_ssh = fake_run

dev = {"id": 1, "name": "r1", "host": "192.0.2.1", "access": "ssh"}
res = owctl.do_mesh(dev, {
    "enabled": True, "mesh_vap": "radio0", "mesh_id": "backbone",
    "mesh_network": "lan", "mesh_ctrl": "1", "mesh_gw_mode": "gwb",
    "mesh_gw_bcast": "0", "mesh_htmode": "HT40", "mesh_channel": "149",
    "mesh_encryption": "psk2", "mesh_key": "secret", "install_if_missing": True,
})
check("mesh enabled returns ok", res.get("ok") is True)
cmd = captured["cmd"]
check("mesh sets wifi-iface section", "uci set wireless.mesh=wifi-iface" in cmd)
check("mesh sets device=radio0", "uci set wireless.mesh.device='radio0'" in cmd)
check("mesh sets mode=mesh", "uci set wireless.mesh.mode=mesh" in cmd)
check("mesh sets mesh id", "uci set wireless.mesh.mesh='backbone'" in cmd)
check("mesh sets htmode", "uci set wireless.mesh.htmode='HT40'" in cmd)
check("mesh sets channel", "uci set wireless.mesh.channel='149'" in cmd)
check("mesh sets encryption", "uci set wireless.mesh.encryption='psk2'" in cmd)
check("mesh sets key", "uci set wireless.mesh.key='secret'" in cmd)
check("mesh sets gw_mode", "uci set wireless.mesh.mesh_gw_mode='gwb'" in cmd)
check("mesh commits wireless", "uci commit wireless" in cmd)
check("mesh reloads wifi", "wifi reload" in cmd)
check("mesh installs meshd when missing", "opkg install -y meshd" in cmd)

# --- 2. do_mesh disabled ---
captured.clear()
res = owctl.do_mesh(dev, {"enabled": False})
check("mesh disabled returns enabled=False", res.get("enabled") is False)
check("mesh disable sets enabled=0", "uci set wireless.mesh.enabled=0" in captured["cmd"])
check("mesh disable commits", "uci commit wireless" in captured["cmd"])
check("mesh disable does NOT reload", "wifi reload" not in captured["cmd"])

# --- 3. mesh endpoint applies + reads back ---
owctl.execute("INSERT INTO devices(name, host, access, added_at) VALUES(?,?,?,?)",
              ("meshbox", "192.0.2.9", "ssh", owctl.now()))
did = owctl.q("SELECT id FROM devices WHERE host='192.0.2.9'")[0]["id"]
owctl.do_mesh = lambda d, cfg: {"device": d["name"], "ok": True, "enabled": True, "backend": "meshd"}
r = client.post(f"/api/devices/{did}/mesh", json={"enabled": True, "mesh_id": "backbone"})
check("POST /api/devices/{did}/mesh 200", r.status_code == 200 and r.json().get("ok"))
owctl.do_mesh = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
r = client.post(f"/api/devices/{did}/mesh", json={"enabled": True})
check("mesh apply failure -> 502", r.status_code == 502)

# --- 4. packages endpoint reads persisted snapshot ---
owctl.execute("INSERT INTO devices(name, host, access, added_at) VALUES(?,?,?,?)",
              ("pkgbox", "192.0.2.8", "ssh", owctl.now()))
pid = owctl.q("SELECT id FROM devices WHERE host='192.0.2.8'")[0]["id"]
owctl.record_status_snapshot({"id": pid}, {
    "installed": [{"pkg": "libc", "version": "1.0"}, {"pkg": "meshd", "version": "2.0"}],
    "obsolete": ["oldpkg"],
    "meshd": "meshd",
})
r = client.get(f"/api/devices/{pid}/packages")
check("GET /api/devices/{did}/packages 200", r.status_code == 200)
pk = r.json()
check("packages returns installed list", pk["installed"] == [{"pkg": "libc", "version": "1.0"},
                                                              {"pkg": "meshd", "version": "2.0"}])
check("packages returns obsolete list", pk["obsolete"] == ["oldpkg"])
check("packages returns meshd", pk["meshd"] == "meshd")
check("packages stale=False", pk["stale"] is False)

# --- 5. packages endpoint: never-checked device -> stale ---
r = client.get(f"/api/devices/{did}/packages")
check("never-checked device -> stale", r.json()["stale"] is True and r.json()["installed"] == [])

print(f"\n=== SUMMARY ===\n{passed}/{passed+failed} checks passed")
print("ALL MESH/PACKAGE CHECKS PASSED" if failed == 0 else "SOME CHECKS FAILED")
os.system(f"rm -rf {os.environ['OWCTL_DATA']}")
import sys; sys.exit(1 if failed else 0)