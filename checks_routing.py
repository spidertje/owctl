# Copyright (C) 2026 spidertje
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied fitness for a
# particular purpose. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.
"""checks_routing.py — routing subsystem: parsers, command builders, logical
via resolution, per-device + fleet endpoints, and the audit rules.

Self-contained: throwaway OWCTL_DATA before import, drives endpoints with a
monkeypatched SSH layer (no live device). Exits non-zero on any failure.

Run: .venv/bin/python checks_routing.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["OWCTL_DATA"] = tempfile.mkdtemp()
os.environ["OWCTL_ALLOW_OPEN"] = "1"
os.makedirs(os.environ["OWCTL_DATA"], exist_ok=True)

import importlib, owctl
importlib.reload(owctl)
from fastapi.testclient import TestClient  # noqa: E402

CHECKS = []


def check(name, cond, extra=""):
    CHECKS.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


# ---- _valid_ip4 / _valid_cidr (pure) ----
check("ip4 valid", owctl._valid_ip4("192.168.1.1") is True)
check("ip4 valid 0/255", owctl._valid_ip4("0.0.0.0") and owctl._valid_ip4("255.255.255.255"))
check("ip4 rejects 256", owctl._valid_ip4("256.1.1.1") is False)
check("ip4 rejects non-num", owctl._valid_ip4("a.b.c.d") is False)
check("ip4 rejects None", owctl._valid_ip4(None) is False)
check("cidr valid /24", owctl._valid_cidr("10.20.0.0/24") is True)
check("cidr valid /32", owctl._valid_cidr("10.0.0.1/32") is True)
check("cidr valid /0", owctl._valid_cidr("0.0.0.0/0") is True)
check("cidr rejects /33", owctl._valid_cidr("10.0.0.0/33") is False)
check("cidr rejects bad base", owctl._valid_cidr("10.0.0.999/24") is False)

# ---- parse_ip_route (pure) ----
IPROUTE = (
    "default via 192.168.1.1 dev wan metric 100\n"
    "10.20.0.0/24 via 192.168.1.1 dev wan\n"
    "192.168.10.0/24 dev vlan_10 proto kernel scope link src 192.168.10.1\n"
)
rr = owctl.parse_ip_route(IPROUTE)
check("iproute count", len(rr) == 3, str(len(rr)))
check("iproute default gw", rr[0]["gateway"] == "192.168.1.1", str(rr[0]))
check("iproute default metric", rr[0]["metric"] == 100, str(rr[0]))
check("iproute cidr gw", rr[1]["gateway"] == "192.168.1.1", str(rr[1]))
check("iproute dev link no gw", rr[2]["gateway"] is None and rr[2]["dev"] == "vlan_10", str(rr[2]))
check("iproute empty -> []", owctl.parse_ip_route("") == [])
check("iproute None -> []", owctl.parse_ip_route(None) == [])

# ---- parse_ip_rule (pure) ----
IPRULE = (
    "0:      from all lookup local\n"
    "1000:   from 192.168.50.0/24 lookup owctl\n"
    "32766:  from all lookup main\n"
)
rules = owctl.parse_ip_rule(IPRULE)
check("iprule count", len(rules) == 3, str(len(rules)))
check("iprule lookup name", rules[1]["lookup"] == "owctl", str(rules[1]))
check("iprule from cidr", rules[1]["from"] == "192.168.50.0/24", str(rules[1]))
check("iprule priority", rules[0]["priority"] == 0, str(rules[0]))
check("iprule empty -> []", owctl.parse_ip_rule("") == [])

# ---- parse_routing (uci show network -> per-interface gateway + statics) ----
UCI = (
    "network.lan=interface\n"
    "network.lan.proto='static'\n"
    "network.lan.ipaddr='192.168.1.1'\n"
    "network.lan.gateway='192.168.1.254'\n"
    "network.wan=interface\n"
    "network.vlan_10=interface\n"
    "network.vlan_10.proto='static'\n"
    "network.vlan_10.ipaddr='192.168.10.1'\n"
    "network.vlan_10.gateway='10.0.0.254'\n"
    "network.wan.route='10.20.0.0/24' '10.30.0.0/24'\n"
    "network.wan.route.gateway='192.168.1.254' '192.168.1.254'\n"
    "network.wan.route.metric='100' '200'\n"
)
parsed = owctl.parse_routing(UCI)
check("parse_routing has lan", "lan" in parsed, str(list(parsed)))
check("parse_routing lan gw", parsed.get("lan", {}).get("gateway") == "192.168.1.254", str(parsed.get("lan")))
check("parse_routing wan statics", len(parsed.get("wan", {}).get("statics", [])) == 2, str(parsed.get("wan")))
if "wan" in parsed and parsed["wan"]["statics"]:
    s0 = parsed["wan"]["statics"][0]
    check("parse_routing static dst", s0["dst"] == "10.20.0.0/24", str(s0))
    check("parse_routing static gw", s0["gateway"] == "192.168.1.254", str(s0))
    check("parse_routing static metric", s0["metric"] == 100, str(s0))
check("parse_routing empty -> {}", owctl.parse_routing("") == {})

# ---- build_route_cmds (pure) ----
cmd = owctl.build_route_cmds({}, "10.20.0.0/24", "192.168.1.254", 100, "wan", apply=True)
check("route cmd sets dst", "10.20.0.0/24" in cmd)
check("route cmd sets gw", "192.168.1.254" in cmd)
check("route cmd sets metric", "100" in cmd)
check("route cmd commits network", "uci commit network" in cmd)
check("route cmd applies (netifd)", "netifd restart" in cmd)
cmd2 = owctl.build_route_cmds({}, "10.20.0.0/24", "192.168.1.254", None, "wan", apply=False)
check("route cmd save-only (no netifd)", "netifd restart" not in cmd2)
check("route cmd save-only no metric", "uci set network.wan.route.metric" not in cmd2)
# validation
def _raises(fn, *a, **k):
    try:
        fn(*a, **k)
        return False
    except owctl.HTTPException as e:
        return e.status_code == 400
check("route cmd rejects bad dst", _raises(owctl.build_route_cmds, {}, "notacidr", "1.1.1.1", None, "wan", True))
check("route cmd rejects bad gw", _raises(owctl.build_route_cmds, {}, "10.0.0.0/24", "notanip", None, "wan", True))

# ---- build_policy_route_cmds (pure) ----
p = owctl.build_policy_route_cmds({}, "owctl", "192.168.50.0/24", "10.0.0.0/8", "192.168.1.254", "wan", True)
check("policy cmd has table", "table owctl" in p)
check("policy cmd has from", "from 192.168.50.0/24" in p)
check("policy cmd has lookup", "lookup owctl" in p)
check("policy cmd rejects bad via", _raises(owctl.build_policy_route_cmds, {}, "t", "10.0.0.0/24", "10.0.0.0/8", "bad", "wan", True))

# ---- build_bgp_cmds (pure) ----
b = owctl.build_bgp_cmds({}, 65000, [{"addr": "10.0.0.254", "as": 65001}], True)
check("bgp cmd has asn", "local as 65000" in b)
check("bgp cmd has peer", "net 10.0.0.254/32" in b)
check("bgp cmd installs bird", "opkg install -y bird" in b)
check("bgp cmd restarts", "birdc configure" in b or "bird restart" in b)
check("bgp cmd rejects bad asn", _raises(owctl.build_bgp_cmds, {}, 0, [{"addr": "10.0.0.254", "as": 65001}], True))
check("bgp cmd rejects bad peer ip", _raises(owctl.build_bgp_cmds, {}, 65000, [{"addr": "bad", "as": 65001}], True))

# ---- resolve_via (logical vlan:<id>) ----
# seed a VLAN so resolve_via accepts vlan:<id>
owctl.execute("INSERT INTO vlans(vlan_id, name, subnet, dhcp, created_at) VALUES(?,?,?,?,?)",
              ("10", "vlan_10", "192.168.10.0/24", 1, owctl.now()))
check("resolve via concrete", owctl.resolve_via(None, "192.168.1.254") == "192.168.1.254")
check("resolve via vlan:10 -> marker", owctl.resolve_via(None, "vlan:10") == "vlan_10")
check("resolve via rejects unknown vlan", _raises(owctl.resolve_via, None, "vlan:99"))
check("resolve via rejects garbage", _raises(owctl.resolve_via, None, "not-a-via"))

# ---- read_routing via monkeypatched SSH ----
class _FakeChan:
    def __init__(self, out, err=b""):
        self._out = out; self._err = err
    def makefile(self, mode):
        import io
        return io.BytesIO(self._out if "rb" in mode else self._err)
    def makefile_stderr(self, mode):
        import io
        return io.BytesIO(self._err)
    def recv_exit_status(self):
        return 0
    def close(self):
        pass

def _fake_exec_capture(client, cmd, timeout=300):
    out = (
        "##uci##\n" + UCI + "\n"
        "##iproute##\n" + IPROUTE + "\n"
        "##iprule##" + IPRULE + "\n"
        "##bgp##\nrouter id '127.0.0.1';\nprotocol bgp owctl_self {\n\tlocal as 65000;\n}\n"
    )
    return out, "", 0

DEV = {"id": 1, "name": "router", "host": "192.168.1.1", "access": "ssh"}
class _FakeClient:
    def close(self):
        pass

owctl._ssh_connect = lambda dev: _FakeClient()
owctl._exec_capture = _fake_exec_capture
r = owctl.read_routing(DEV)
check("read_routing no error", r.get("error") is None, str(r.get("error")))
check("read_routing interfaces", "lan" in r.get("interfaces", {}), str(list(r.get("interfaces", {}))))
check("read_routing ip_routes", len(r.get("ip_routes", [])) >= 3, str(len(r.get("ip_routes", []))))
check("read_routing bgp present", (r.get("bgp") or {}).get("present") is True, str(r.get("bgp")))
check("read_routing bgp asn", (r.get("bgp") or {}).get("asn") == 65000, str(r.get("bgp")))
# luci-only device -> skipped
r2 = owctl.read_routing({"id": 2, "name": "ap", "host": "192.168.1.2", "access": "luci"})
check("read_routing luci skipped", r2.get("error", "").startswith("luci-only"), str(r2.get("error")))

# ---- parse_bgp_config (pure) ----
bgp_empty = owctl.parse_bgp_config("")
check("bgp parse empty -> absent", bgp_empty["present"] is False, str(bgp_empty))
bgp_txt = owctl.parse_bgp_config("protocol bgp self {\n\tlocal as 65000;\n}\nneighbor 10.0.0.254 { as 65001 }")
check("bgp parse present", bgp_txt["present"] is True, str(bgp_txt))
check("bgp parse asn", bgp_txt["asn"] == 65000, str(bgp_txt))
check("bgp parse peer", any(p["addr"] == "10.0.0.254" and p["as"] == 65001 for p in bgp_txt["peers"]), str(bgp_txt))

# ---- audit_status routing rules ----
# no routing data (LuCI) -> no routing findings
f_luci = owctl.audit_status({"routing": "", "bgp_present": ""})
check("audit no routing data -> no routing findings",
      not any(x["rule_id"] in ("no_default_route", "multiple_default_routes", "bgp_enabled") for x in f_luci),
      str([x["rule_id"] for x in f_luci]))
# no default route -> finding
f_nodflt = owctl.audit_status({"routing": "10.0.0.0/8 via 192.168.1.1 dev wan", "bgp_present": ""})
check("audit no default route -> finding", any(x["rule_id"] == "no_default_route" for x in f_nodflt), str(f_nodflt))
# multiple default routes -> finding
f_multi = owctl.audit_status({"routing": "default via 192.168.1.1 dev wan\ndefault via 10.0.0.1 dev vlan_10", "bgp_present": ""})
check("audit multiple defaults -> finding", any(x["rule_id"] == "multiple_default_routes" for x in f_multi), str(f_multi))
# single default -> no default finding
f_ok = owctl.audit_status({"routing": "default via 192.168.1.1 dev wan\n10.0.0.0/8 via 192.168.1.1 dev wan", "bgp_present": ""})
check("audit single default -> no default finding",
      not any(x["rule_id"] in ("no_default_route", "multiple_default_routes") for x in f_ok), str(f_ok))
# bgp present -> INFO finding
f_bgp = owctl.audit_status({"routing": "default via 192.168.1.1 dev wan", "bgp_present": "bird 2.0.10"})
check("audit bgp present -> finding", any(x["rule_id"] == "bgp_enabled" for x in f_bgp), str(f_bgp))

# ---- endpoints (TestClient) with a stubbed do_* op ----
client = TestClient(owctl.app, raise_server_exceptions=False)

# register a device
did = owctl.execute("INSERT INTO devices(name, host, access, added_at) VALUES(?,?,?,?)",
                    ("router", "192.168.1.1", "ssh", owctl.now()))

# per-device add route: stub do_route to avoid SSH
def _fake_do_route(dev, dst, via, metric, iface, apply=True):
    return {"device": dev["name"], "ok": True, "iface": iface or "lan"}
owctl.do_route = _fake_do_route
r = client.post(f"/api/devices/{did}/routes", json={"dst": "10.20.0.0/24", "via": "192.168.1.254"})
check("endpoint add route 200", r.status_code == 200, f"{r.status_code} {r.text[:120]}")
check("endpoint add route ok", r.json().get("ok") is True, str(r.json()))
# missing via -> 400
r = client.post(f"/api/devices/{did}/routes", json={"dst": "10.20.0.0/24"})
check("endpoint add route missing via -> 400", r.status_code == 400, str(r.status_code))

# per-device delete route
owctl.do_route_delete = lambda dev, dst, iface, apply=True: {"device": dev["name"], "ok": True}
r = client.post(f"/api/devices/{did}/routes/delete", json={"dst": "10.20.0.0/24"})
check("endpoint delete route 200", r.status_code == 200, f"{r.status_code} {r.text[:120]}")
r = client.post(f"/api/devices/{did}/routes/delete", json={})
check("endpoint delete route missing dst -> 400", r.status_code == 400, str(r.status_code))

# policy route
owctl.do_policy_route = lambda dev, table, match_dst, route_dst, via, iface, apply=True: {"device": dev["name"], "ok": True}
r = client.post(f"/api/devices/{did}/policy-routes",
                json={"table": "owctl", "match_dst": "192.168.50.0/24", "route_dst": "10.0.0.0/8", "via": "192.168.1.254"})
check("endpoint policy route 200", r.status_code == 200, f"{r.status_code} {r.text[:120]}")
r = client.post(f"/api/devices/{did}/policy-routes", json={"table": "t", "match_dst": "10.0.0.0/24", "route_dst": "10.0.0.0/8"})
check("endpoint policy route missing via -> 400", r.status_code == 400, str(r.status_code))

# bgp
owctl.do_bgp = lambda dev, asn, peers, apply=True: {"device": dev["name"], "ok": True}
r = client.post(f"/api/devices/{did}/bgp", json={"asn": 65000, "peers": [{"addr": "10.0.0.254", "as": 65001}]})
check("endpoint bgp 200", r.status_code == 200, f"{r.status_code} {r.text[:120]}")
r = client.post(f"/api/devices/{did}/bgp", json={"asn": 65000, "peers": []})
check("endpoint bgp no peers -> 400", r.status_code == 400, str(r.status_code))

# fleet routes view (empty -> routes: [])
r = client.get("/api/routes")
check("fleet routes 200", r.status_code == 200, str(r.status_code))
check("fleet routes shape", "routes" in r.json(), str(r.json())[:120])

# fleet apply (stub do_route) -> creates ledger + results
r = client.post("/api/routes/apply", json={"dst": "10.40.0.0/24", "via": "vlan:10", "devices": [did]})
check("fleet apply 200", r.status_code == 200, f"{r.status_code} {r.text[:200]}")
check("fleet apply ok count", r.json().get("ok") == 1, str(r.json()))
# the logical route row + realization were recorded
row = owctl.q("SELECT * FROM routes WHERE dst=?", ("10.40.0.0/24",))
check("fleet apply recorded route", len(row) == 1, str(row))
if row:
    real = owctl.q("SELECT * FROM routes_devices WHERE route_id=?", (row[0]["id"],))
    check("fleet apply recorded realization", len(real) == 1 and real[0]["state"] == "applied", str(real))

# fleet delete (stub do_route_delete)
r = client.post("/api/routes/delete", json={"dst": "10.40.0.0/24", "devices": [did]})
check("fleet delete 200", r.status_code == 200, f"{r.status_code} {r.text[:200]}")
row = owctl.q("SELECT * FROM routes WHERE dst=?", ("10.40.0.0/24",))
check("fleet delete removed route row", len(row) == 0, str(row))

# read routing endpoint (stubbed reader) -> 200 configured
owctl.read_routing = lambda dev: {"name": dev["name"], "host": dev["host"], "interfaces": {"lan": {}},
                                  "ip_routes": [], "policy": [], "bgp": {"present": False, "asn": None, "peers": []}, "error": None}
r = client.get(f"/api/devices/{did}/routing")
check("read routing endpoint 200", r.status_code == 200, f"{r.status_code} {r.text[:120]}")

print(f"\n=== SUMMARY ===\n{sum(1 for _, ok, _ in CHECKS if ok)}/{len(CHECKS)} checks passed")
failed = [n for n, ok, _ in CHECKS if not ok]
if failed:
    for n in failed:
        print(" -", n)
    sys.exit(1)
print("ALL ROUTING CHECKS PASSED")
