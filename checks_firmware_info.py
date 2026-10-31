#!/usr/bin/env python3
"""checks_firmware_info.py — verify parse_openwrt_release and firmware_info persistence."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

tmp = tempfile.mkdtemp()
os.environ["OWCTL_DATA"] = tmp
os.environ["OWCTL_ALLOW_OPEN"] = "1"

import owctl  # noqa: E402
from fastapi.testclient import TestClient

client = TestClient(owctl.app)
CHECKS = []

def check(name, cond, extra=""):
    CHECKS.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))

owctl.init_db()

# ---- Unit tests for parse_openwrt_release

# 1) REAL multi-line DISTRIB blob
real_blob = """DISTRIB_DESCRIPTION='OpenWrt 23.05.4 (goldman) r24046-85e4097894'
DISTRIB_REVISION='r24046-85e4097894'
DISTRIB_TARGET='x86/64'
DISTRIB_ARCH='x86_64'
DISTRIB_VERSION='23.05.4'"""
res = owctl.parse_openwrt_release(real_blob)
check("parse: multi-line DISTRIB description", res["description"] == "OpenWrt 23.05.4 (goldman) r24046-85e4097894", str(res))
check("parse: multi-line DISTRIB version", res["version"] == "23.05.4", str(res))
check("parse: multi-line DISTRIB arch", res["arch"] == "x86_64", str(res))
check("parse: multi-line DISTRIB target", res["target"] == "x86/64", str(res))
check("parse: multi-line DISTRIB revision", res["revision"] == "r24046-85e4097894", str(res))

# 2) Single-line fallback (what test_e2e uses)
single_line = "OpenWrt 23.05.4 (goldman) r24046-85e4097894"
res2 = owctl.parse_openwrt_release(single_line)
check("parse: single-line description contains version", "23.05.4" in res2["description"], str(res2))
check("parse: single-line version extracted", res2["version"] == "23.05.4", str(res2))
check("parse: single-line revision extracted", res2["revision"] == "r24046-85e4097894", str(res2))
check("parse: single-line arch is None", res2["arch"] is None, str(res2))
check("parse: single-line target is None", res2["target"] is None, str(res2))

# 3) Empty string
res3 = owctl.parse_openwrt_release("")
check("parse: empty string returns all None except description", res3["description"] == "" and all(v is None for k, v in res3.items() if k != "description"), str(res3))

# ---- Integration: seed a device + device_status with firmware_info
# Insert a device
did = owctl.execute("INSERT INTO devices(name, host, status, added_at) VALUES(?,?,?,?)",
                     ("router1", "192.0.2.10", "online", owctl.now()))

# Insert a device_status row with firmware_info JSON
import json as _json
fi = {"description": "OpenWrt 23.05.4 (goldman) r24046-85e4097894",
      "version": "23.05.4", "arch": "x86_64", "target": "x86/64",
      "revision": "r24046-85e4097894"}
fi_json = _json.dumps(fi)
owctl.execute("""INSERT INTO device_status(device_id, clients, uptime_s, firmware, firmware_info, ts)
                 VALUES(?,?,?,?,?,?)""",
              (did, 3, 86400, "OpenWrt 23.05.4 (goldman) r24046-85e4097894", fi_json, owctl.now()))

# Set as network gateway
owctl.execute("INSERT INTO settings(key,value) VALUES(?,?)", ("network_gateway", str(did)))

# Verify /api/network returns firmware_info for device and gateway
resp = client.get("/api/network")
j = resp.json()
check("/api/network ok", resp.status_code == 200)

# Device firmware_info
dev = next(d for d in j["devices"] if d["id"] == did)
check("device firmware_info dict present", isinstance(dev.get("firmware_info"), dict), str(dev.get("firmware_info")))
check("device firmware_info.version == 23.05.4", dev.get("firmware_info", {}).get("version") == "23.05.4", str(dev.get("firmware_info")))
check("device firmware_info.arch == x86_64", dev.get("firmware_info", {}).get("arch") == "x86_64", str(dev.get("firmware_info")))
check("device firmware_info.target == x86/64", dev.get("firmware_info", {}).get("target") == "x86/64", str(dev.get("firmware_info")))
check("device firmware_info.revision == r24046-85e4097894", dev.get("firmware_info", {}).get("revision") == "r24046-85e4097894", str(dev.get("firmware_info")))
# Ensure firmware still contains the description (for baseline logic)
check("device firmware still has description", "OpenWrt 23.05.4" in dev.get("firmware", ""), str(dev.get("firmware")))

# Gateway firmware_info
gw = j["gateway"]
check("gateway present", gw is not None, str(gw))
check("gateway firmware_info dict present", isinstance(gw.get("firmware_info"), dict), str(gw.get("firmware_info")))
check("gateway firmware_info.version == 23.05.4", gw.get("firmware_info", {}).get("version") == "23.05.4", str(gw.get("firmware_info")))
check("gateway firmware still has description", "OpenWrt 23.05.4" in gw.get("firmware", ""), str(gw.get("firmware")))

print(f"\n=== SUMMARY ===\n{sum(1 for _, ok, _ in CHECKS if ok)}/{len(CHECKS)} checks passed")
failed = [n for n, ok, _ in CHECKS if not ok]
if failed:
    print("FAILURES:", failed)
    sys.exit(1)
print("ALL FIRMWARE_INFO CHECKS PASSED")