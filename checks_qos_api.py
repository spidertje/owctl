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
"""checks_qos_api.py — tests for the QoS + firewall API endpoints (step 4).

Drives the REAL FastAPI endpoints via TestClient. `_ssh_connect` is monkeypatched
to a dummy and `_exec_capture` to a command recorder, so the full request path
(validate → do_* → uci command → saved-state upsert → JSON response) is exercised
without a real box.

Run: .venv/bin/python checks_qos_api.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

tmp = tempfile.mkdtemp()
os.environ["OWCTL_DATA"] = tmp
os.environ["OWCTL_ALLOW_OPEN"] = "1"

import owctl  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

CHECKS = []


def check(name, cond, extra=""):
    CHECKS.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


SQM_LIVE = """\
sqm.wan=queue
sqm.wan.enabled=1
sqm.wan.interface='wan'
sqm.wan.upload='20000'
sqm.wan.download='100000'
sqm.wan.fq_codel='1'
sqm.wan.ecn='0'
"""

FW_LIVE = """\
firewall.defaults=defaults
firewall.defaults.input='ACCEPT'
firewall.defaults.forward='REJECT'
firewall.lan=zone
firewall.lan.name='lan'
firewall.lan.input='ACCEPT'
firewall.lan.forward='ACCEPT'
firewall.wan=zone
firewall.wan.name='wan'
firewall.wan.input='DROP'
firewall.wan.forward='REJECT'
firewall.cam=redirect
firewall.cam.name='cam'
firewall.cam.proto='tcp'
firewall.cam.src_dport='8080'
firewall.cam.dest_ip='192.168.1.50'
firewall.cam.dest_port='80'
"""

CMD_LOG = []
LIVE_OUTPUT = {"sqm": SQM_LIVE, "firewall": FW_LIVE}


class _FakeClient:
    def close(self):
        pass


def _fake_ssh_connect(dev):
    return _FakeClient()  # _exec_capture is patched, so this is never used


def _fake_exec_capture(client, cmd, timeout=300):
    CMD_LOG.append(cmd)
    if "uci show sqm" in cmd or "uci show nft-qos" in cmd:
        return LIVE_OUTPUT["sqm"], "", 0
    if "uci show firewall" in cmd:
        return LIVE_OUTPUT["firewall"], "", 0
    return "ok\n", "", 0


def main():
    client = TestClient(owctl.app)
    owctl.init_db()

    # seed: one SSH device, one LuCI-only device
    d1 = owctl.execute(
        "INSERT INTO devices(id, name, host, access, ssh_port, ssh_user) VALUES(?,?,?,?,?,?)",
        (1, "r1", "127.0.0.1", "ssh", 2222, "root"))
    owctl.execute(
        "INSERT INTO devices(id, name, host, access) VALUES(?,?,?,?)", (2, "ap1", "127.0.0.2", "luci"))

    owctl._ssh_connect = _fake_ssh_connect
    owctl._exec_capture = _fake_exec_capture

    # ── GET /api/qos?did= ─────────────────────────────────────────────────
    r = client.get("/api/qos", params={"did": 1})
    check("qos read: 200", r.status_code == 200, r.text[:200])
    body = r.json()
    check("qos read: saved + live keys", "saved" in body and "live" in body, str(list(body)))
    check("qos read: live parsed from box", body["live"] and body["live"]["download_kbps"] == 100000,
          str(body.get("live")))
    check("qos read: saved initially null", body["saved"] is None, str(body.get("saved")))

    r = client.get("/api/qos", params={"did": 999})
    check("qos read: unknown device 404", r.status_code == 404, str(r.status_code))

    r = client.get("/api/qos", params={"did": 2})
    check("qos read: luci device 400", r.status_code == 400, r.text[:120])

    # ── POST /api/qos/apply ───────────────────────────────────────────────
    cfg = {"did": 1, "enabled": True, "interface": "wan", "download_kbps": 90000,
           "upload_kbps": 9000, "qdisc": "fq_codel", "ecn": True}
    CMD_LOG.clear()
    r = client.post("/api/qos/apply", json=cfg)
    check("qos apply: 200", r.status_code == 200, r.text[:300])
    check("qos apply: ok flag", r.json().get("ok") is True, r.text[:200])
    check("qos apply: uci command sent", any("uci set sqm.wan.download='90000'" in c for c in CMD_LOG), str(CMD_LOG))
    check("qos apply: ecn on", any("uci set sqm.wan.ecn=1" in c for c in CMD_LOG), "")
    check("qos apply: committed + restarted", any("uci commit sqm" in c and "sqm restart" in c for c in CMD_LOG), "")
    row = owctl.q("SELECT * FROM qos WHERE device_id=?", (1,))
    check("qos apply: saved row upserted", len(row) == 1, str(row))

    # invalid speed
    r = client.post("/api/qos/apply", json={**cfg, "download_kbps": -5})
    check("qos apply: negative speed 400", r.status_code == 400, r.text[:120])

    # unknown device
    r = client.post("/api/qos/apply", json={**cfg, "did": 999})
    check("qos apply: unknown device 404", r.status_code == 404, str(r.status_code))

    # luci device
    r = client.post("/api/qos/apply", json={**cfg, "did": 2})
    check("qos apply: luci device 400", r.status_code == 400, r.text[:120])

    # ── GET /api/firewall?did= ────────────────────────────────────────────
    r = client.get("/api/firewall", params={"did": 1})
    check("fw read: 200", r.status_code == 200, r.text[:200])
    body = r.json()
    check("fw read: zones/redirects/rules/defaults keys",
          all(k in body["live"] for k in ("zones", "redirects", "rules", "defaults")), str(list(body["live"])))
    check("fw read: zone parsed", any(z["name"] == "wan" for z in body["live"]["zones"]), str(body["live"]["zones"]))
    check("fw read: redirect parsed", any(x["name"] == "cam" for x in body["live"]["redirects"]), str(body["live"]["redirects"]))
    check("fw read: saved initially empty", body["saved"] == {"forwards": [], "rules": []}, str(body.get("saved")))

    # ── POST /api/firewall/apply ──────────────────────────────────────────
    rule = {"name": "cam", "proto": "tcp", "src_dport": 8080, "dest_ip": "192.168.1.50", "dest_port": 80}
    CMD_LOG.clear()
    r = client.post("/api/firewall/apply", json={"did": 1, "kind": "forward", "rule": rule})
    check("fw apply fwd: 200", r.status_code == 200, r.text[:300])
    check("fw apply fwd: section command", any("uci set firewall.cam=redirect" in c for c in CMD_LOG), str(CMD_LOG))
    check("fw apply fwd: fw4 restart", any("fw4 restart" in c for c in CMD_LOG), "")
    fwd_rows = owctl.q("SELECT * FROM fw_rules WHERE device_id=? AND kind='forward'", (1,))
    check("fw apply fwd: saved", len(fwd_rows) == 1, str(fwd_rows))

    # re-apply same rule: still exactly one saved row (idempotent upsert)
    client.post("/api/firewall/apply", json={"did": 1, "kind": "forward", "rule": rule})
    fwd_rows = owctl.q("SELECT * FROM fw_rules WHERE device_id=? AND kind='forward'", (1,))
    check("fw apply fwd: idempotent upsert", len(fwd_rows) == 1, str(fwd_rows))

    # rule kind
    zr = {"name": "allow cam", "src": "lan", "dest": "wan", "target": "ACCEPT"}
    CMD_LOG.clear()
    r = client.post("/api/firewall/apply", json={"did": 1, "kind": "rule", "rule": zr})
    check("fw apply rule: 200", r.status_code == 200, r.text[:300])
    check("fw apply rule: section command", any("uci set firewall.allow_cam=rule" in c for c in CMD_LOG), str(CMD_LOG))

    # zone policy kind
    CMD_LOG.clear()
    r = client.post("/api/firewall/apply", json={"did": 1, "kind": "zone", "zone": "guest",
                                                 "policies": {"forward": "REJECT"}})
    check("fw apply zone: 200", r.status_code == 200, r.text[:300])
    check("fw apply zone: uci set", any("uci set firewall.guest.forward='REJECT'" in c for c in CMD_LOG), str(CMD_LOG))

    # validation: bad port
    r = client.post("/api/firewall/apply", json={"did": 1, "kind": "forward",
                                                 "rule": {**rule, "src_dport": 99999}})
    check("fw apply: bad port 400", r.status_code == 400, r.text[:120])

    # validation: bad target
    r = client.post("/api/firewall/apply", json={"did": 1, "kind": "rule",
                                                 "rule": {**zr, "target": "FORWARD"}})
    check("fw apply: bad target 400", r.status_code == 400, r.text[:120])

    # unknown device
    r = client.post("/api/firewall/apply", json={"did": 999, "kind": "forward", "rule": rule})
    check("fw apply: unknown device 404", r.status_code == 404, str(r.status_code))

    # luci device
    r = client.post("/api/firewall/apply", json={"did": 2, "kind": "forward", "rule": rule})
    check("fw apply: luci device 400", r.status_code == 400, r.text[:120])

    # ── DELETE endpoints ──────────────────────────────────────────────────
    CMD_LOG.clear()
    r = client.delete(f"/api/firewall/1/rule/allow%20cam")
    check("fw del rule: 200", r.status_code == 200, r.text[:300])
    check("fw del rule: uci delete", any("uci delete firewall.allow_cam" in c for c in CMD_LOG), str(CMD_LOG))
    rows = owctl.q("SELECT * FROM fw_rules WHERE device_id=? AND kind='rule'", (1,))
    check("fw del rule: saved row removed", len(rows) == 0, str(rows))

    r = client.delete(f"/api/firewall/1/forward/cam")
    check("fw del fwd: 200", r.status_code == 200, r.text[:300])
    rows = owctl.q("SELECT * FROM fw_rules WHERE device_id=? AND kind='forward'", (1,))
    check("fw del fwd: saved row removed", len(rows) == 0, str(rows))

    r = client.delete(f"/api/firewall/999/rule/nope")
    check("fw del: unknown device 404", r.status_code == 404, str(r.status_code))

    print(f"\n=== SUMMARY ===\n{sum(1 for _, ok, _ in CHECKS if ok)}/{len(CHECKS)} checks passed")
    failed = [n for n, ok, _ in CHECKS if not ok]
    if failed:
        print("FAILURES:")
        for n in failed:
            print(" -", n)
        sys.exit(1)
    print("ALL QOS/FIREWALL API CHECKS PASSED")


if __name__ == "__main__":
    main()
