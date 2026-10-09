#!/usr/bin/env python3
"""checks_roles.py — verify role normalization + network_gateway setting + /api/network shape."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# (a) import owctl with a temp OWCTL_DATA so we never touch the real DB
tmp = tempfile.mkdtemp()
os.environ["OWCTL_DATA"] = tmp

import owctl  # noqa: E402
from fastapi.testclient import TestClient

client = TestClient(owctl.app)
CHECKS = []


def check(name, cond, extra=""):
    CHECKS.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


owctl.init_db()

# ---- role normalization on add via POST /api/devices (uppercase 'AP' -> 'ap')
resp = client.post("/api/devices", json={"name": "ap1", "host": "192.0.2.1", "role": "AP", "access": "ssh"})
did = resp.json()["id"]
devs = client.get("/api/devices").json()
d = [x for x in devs if x["id"] == did][0]
check("add_device lowercases role 'AP'->'ap'", d["role"] == "ap", f"got {d['role']!r}")

# ---- role default 'router' when omitted
resp = client.post("/api/devices", json={"name": "r2", "host": "192.0.2.2", "access": "ssh"})
did2 = resp.json()["id"]
devs = client.get("/api/devices").json()
d = [x for x in devs if x["id"] == did2][0]
check("add_device default role 'router'", d["role"] == "router", f"got {d['role']!r}")

# ---- PUT /api/devices/{id} lowercases role
resp = client.put(f"/api/devices/{did}", json={"role": "SWITCH"})
devs = client.get("/api/devices").json()
d = [x for x in devs if x["id"] == did][0]
check("PUT device lowercases role", d["role"] == "switch", f"got {d['role']!r}")

# ---- GET /api/devices returns lowercase roles
devs = client.get("/api/devices").json()
check("GET /api/devices all roles lowercase", all(x["role"] == x["role"].lower() for x in devs),
      str([x["role"] for x in devs]))

# ---- network_gateway setting plumbing
resp = client.put("/api/settings", json={"network_gateway": did})
check("PUT /api/settings network_gateway", resp.status_code == 200)
resp = client.get("/api/settings")
check("GET /api/settings returns network_gateway int",
      resp.json().get("network_gateway") == did, f"got {resp.json().get('network_gateway')!r}")

# clear it
resp = client.put("/api/settings", json={"network_gateway": None})
check("PUT /api/settings null clears gateway", resp.status_code == 200)
resp = client.get("/api/settings")
check("GET /api/settings network_gateway None after clear",
      resp.json().get("network_gateway") is None, f"got {resp.json().get('network_gateway')!r}")

# ---- GET /api/network shape (gateway unset -> missing)
resp = client.get("/api/network")
j = resp.json()
check("/api/network 200", resp.status_code == 200)
check("/api/network has status", j.get("status") in ("online", "degraded", "offline"), f"got {j.get('status')!r}")
check("/api/network has gateway_missing", "gateway_missing" in j)
check("/api/network gateway_missing True when unset", j.get("gateway_missing") is True)
check("/api/network gateway null when missing", j.get("gateway") is None)
check("/api/network has devices list", isinstance(j.get("devices"), list))
check("/api/network has totals dict", isinstance(j.get("totals"), dict))
check("/api/network totals has devices/online/offline",
      all(k in j["totals"] for k in ("devices", "online", "offline")))
check("/api/network totals has clients/rx_mbps/tx_mbps/findings",
      all(k in j["totals"] for k in ("clients", "rx_mbps", "tx_mbps", "findings")))
check("/api/network totals.findings has 5 severities",
      set(j["totals"]["findings"].keys()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})
check("/api/network has vlans", isinstance(j.get("vlans"), list))
check("/api/network has recent_offline", isinstance(j.get("recent_offline"), list))

# ---- set gateway to an existing device id -> gateway is that device
resp = client.put("/api/settings", json={"network_gateway": did})
check("set gateway to device", resp.status_code == 200)
resp = client.get("/api/network")
j = resp.json()
check("/api/network gateway_missing False after set", j.get("gateway_missing") is False)
check("/api/network gateway is that device",
      j.get("gateway") is not None and j["gateway"]["id"] == did,
      f"got {j.get('gateway')!r}")

# ---- empty device list -> offline, gateway null, missing
owctl.execute("DELETE FROM devices")
resp = client.get("/api/network")
j = resp.json()
check("/api/network empty -> status offline", j.get("status") == "offline")
check("/api/network empty -> gateway null", j.get("gateway") is None)
check("/api/network empty -> gateway_missing True", j.get("gateway_missing") is True)

print(f"\n=== SUMMARY ===\n{sum(1 for _, ok, _ in CHECKS if ok)}/{len(CHECKS)} checks passed")
failed = [n for n, ok, _ in CHECKS if not ok]
if failed:
    print("FAILURES:", failed)
    sys.exit(1)
print("ALL ROLE/NETWORK CHECKS PASSED")