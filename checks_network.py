#!/usr/bin/env python3
"""checks_network.py — verify /api/network totals, bandwidth, findings and status logic."""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

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

# ---- seed 2 devices: 1 online, 1 offline
d1 = owctl.execute("INSERT INTO devices(name, host, status, added_at) VALUES(?,?,?,?)",
                   ("r1", "192.0.2.1", "online", owctl.now()))
d2 = owctl.execute("INSERT INTO devices(name, host, status, added_at) VALUES(?,?,?,?)",
                   ("ap1", "192.0.2.2", "offline", owctl.now()))

# ---- seed device_status: r1 has 7 clients, ap1 has 5
owctl.execute("INSERT INTO device_status(device_id, clients, uptime_s, firmware, ts) VALUES(?,?,?,?,?)",
               (d1, 7, 86400, "OpenWrt 23.05.4", owctl.now()))
owctl.execute("INSERT INTO device_status(device_id, clients, uptime_s, firmware, ts) VALUES(?,?,?,?,?)",
               (d2, 5, 1000, "OpenWrt 21.02.0", owctl.now()))

# ---- seed active_findings: 1 CRITICAL, 2 MEDIUM
owctl.execute("INSERT INTO active_findings(device_id, rule_id, severity, message, ts) VALUES(?,?,?,?,?)",
               (d1, "rule1", "CRITICAL", "Critical issue", owctl.now()))
owctl.execute("INSERT INTO active_findings(device_id, rule_id, severity, message, ts) VALUES(?,?,?,?,?)",
               (d2, "rule2", "MEDIUM", "Medium issue 1", owctl.now()))
owctl.execute("INSERT INTO active_findings(device_id, rule_id, severity, message, ts) VALUES(?,?,?,?,?)",
               (d2, "rule3", "MEDIUM", "Medium issue 2", owctl.now()))

# ---- seed traffic_samples for bandwidth: 1 Mbps tx for d1
# 1 Mbps = 1,000,000 bits/sec = 125,000 bytes/sec
ts2 = owctl.now()
# backdate ts1 by 10 seconds
from datetime import datetime, timedelta, timezone
t2 = datetime.fromisoformat(ts2)
t1 = t2 - timedelta(seconds=10)
ts1 = t1.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

owctl.execute("INSERT INTO traffic_samples(device_id, ts, iface, rx_bytes, tx_bytes) VALUES(?,?,?,?,?)",
               (d1, ts1, "eth0", 0, 0))
owctl.execute("INSERT INTO traffic_samples(device_id, ts, iface, rx_bytes, tx_bytes) VALUES(?,?,?,?,?)",
               (d1, ts2, "eth0", 0, 1_250_000)) # 1.25MB in 10s = 125KB/s = 1Mbps

# ---- Verify /api/network
resp = client.get("/api/network")
j = resp.json()
check("/api/network response ok", resp.status_code == 200)

t = j["totals"]
check("totals.devices == 2", t["devices"] == 2, f"got {t['devices']}")
check("totals.online == 1", t["online"] == 1, f"got {t['online']}")
check("totals.offline == 1", t["offline"] == 1, f"got {t['offline']}")
check("totals.clients == 12", t["clients"] == 12, f"got {t['clients']}")
check("totals.findings counts matched", t["findings"]["CRITICAL"] == 1 and t["findings"]["MEDIUM"] == 2 and t["findings"]["HIGH"] == 0,
      f"got {t['findings']}")
check("totals.tx_mbps == 1.0", t["tx_mbps"] == 1.0, f"got {t['tx_mbps']}")

# ---- Status rule check
check("overall status offline (one is offline)", j["status"] == "offline", f"got {j['status']}")

owctl.execute("UPDATE devices SET status='online' WHERE id=?", (d2,))
j = client.get("/api/network").json()
check("overall status online (all online, gateway missing default)", j["status"] == "degraded", f"got {j['status']}")

# Set gateway
client.put("/api/settings", json={"network_gateway": d1})
j = client.get("/api/network").json()
check("overall status online (all online + gateway set)", j["status"] == "online", f"got {j['status']}")

# Degraded check: one device unknown
owctl.execute("UPDATE devices SET status='unknown' WHERE id=?", (d2,))
j = client.get("/api/network").json()
check("overall status degraded (one is unknown)", j["status"] == "degraded", f"got {j['status']}")

print(f"\n=== SUMMARY ===\n{sum(1 for _, ok, _ in CHECKS if ok)}/{len(CHECKS)} checks passed")
failed = [n for n, ok, _ in CHECKS if not ok]
if failed:
    print("FAILURES:", failed)
    sys.exit(1)
print("ALL NETWORK AGGREGATION CHECKS PASSED")