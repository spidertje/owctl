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
"""Verification harness for the DHCP/DNS apply+read UCI builders and parser.

Self-contained: points OWCTL_DATA at a throwaway DB before import, reloads the
app, and asserts the pure command builders + parser directly (no live SSH).
Exits non-zero on any failure.
"""
import os, sys
os.environ["OWCTL_DATA"] = "/tmp/owctl-dhcp-dns-test-" + str(os.getpid())
os.makedirs(os.environ["OWCTL_DATA"], exist_ok=True)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib, owctl
importlib.reload(owctl)

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print("PASS", name)
    else: failed += 1; print("FAIL", name)

# --- _uci_values: quoted, bare, list forms ---
check("values bare server", owctl._uci_values("server") == ["server"])
check("values quoted list", owctl._uci_values("'dhcp-option=6,1.1.1.1' '6,2001:db8::1'")
      == ["dhcp-option=6,1.1.1.1", "6,2001:db8::1"])
check("values bare ip", owctl._uci_values("8.8.8.8") == ["8.8.8.8"])
check("values 12h", owctl._uci_values("12h") == ["12h"])
check("values 0", owctl._uci_values("0") == ["0"])
check("values 1", owctl._uci_values("1") == ["1"])
check("values empty", owctl._uci_values("") == [])
check("values trailing ws", owctl._uci_values("  'a'  b  ") == ["a", "b"])

# --- _parse_uci_show: unquoted AND list values ---
SAMPLE = (
    "dhcp.lan=dhcp\n"
    "dhcp.lan.interface='lan'\n"
    "dhcp.lan.start=100\n"
    "dhcp.lan.limit=150\n"
    "dhcp.lan.dhcpv4=server\n"
    "dhcp.lan.dhcp_option='dhcp-option=6,1.1.1.1' '6,2001:db8::1'\n"
    "dhcp.lan.leasetime=12h\n"
    "dhcp.@dnsmasq[0].server='9.9.9.9' '149.112.112.112'\n"
)
s = owctl._parse_uci_show(SAMPLE)
check("parse dhcpv4 unquoted", s["dhcp.lan"]["dhcpv4"] == ["server"])
check("parse start unquoted", s["dhcp.lan"]["start"] == ["100"])
check("parse limit unquoted", s["dhcp.lan"]["limit"] == ["150"])
check("parse leasetime unquoted", s["dhcp.lan"]["leasetime"] == ["12h"])
check("parse list option", s["dhcp.lan"]["dhcp_option"] == ["dhcp-option=6,1.1.1.1", "6,2001:db8::1"])
check("parse @dnsmasq server list", s["dhcp.@dnsmasq[0]"]["server"] == ["9.9.9.9", "149.112.112.112"])

# --- _uci_list_values ---
check("list dhcp.lan.dhcp_option",
      owctl._uci_list_values(SAMPLE, "dhcp.lan", "dhcp_option")
      == ["dhcp-option=6,1.1.1.1", "6,2001:db8::1"])
check("list @dnsmasq[0].server",
      owctl._uci_list_values(SAMPLE, "dhcp.@dnsmasq[0]", "server")
      == ["9.9.9.9", "149.112.112.112"])

# --- build_dhcp_apply_cmds ---
cmd = owctl.build_dhcp_apply_cmds("vlan_10", 100, 150, "12h")
check("dhcp uses leasetime (no underscore)", "leasetime='12h'" in cmd)
check("dhcp no lease_time", "lease_time=" not in cmd)
check("dhcp sets dhcpv4=server", "dhcpv4='server'" in cmd)
check("dhcp sets start", "start='100'" in cmd)
check("dhcp sets interface", "interface='vlan_10'" in cmd)
check("dhcp commits dhcp pkg", "uci commit dhcp" in cmd)
check("dhcp reloads a daemon", "reload" in cmd)
try:
    owctl.build_dhcp_apply_cmds("bad; rm -rf /", 1, 1, "1h")
    check("dhcp rejects bad iface name", False)
except Exception:
    check("dhcp rejects bad iface name", True)

# --- build_dns_cmds (odhcpd) ---
odhcpd_detect = "dhcp.lan.dhcp_option='dhcp-option=6,8.8.8.8' '6,2001:db8::1'\n"
cmd = owctl.build_dns_cmds("odhcpd", odhcpd_detect, ["1.1.1.1", "9.9.9.9"], [])
check("dns odhcpd adds 1.1.1.1", "dhcp-option=6,1.1.1.1" in cmd)
check("dns odhcpd adds 9.9.9.9", "dhcp-option=6,9.9.9.9" in cmd)
check("dns odhcpd PRESERVES RA-DNS", "uci set dhcp.lan.dhcp_option='6,2001:db8::1'" in cmd)
check("dns odhcpd drops old 8.8.8.8", "8.8.8.8" not in cmd)
check("dns odhcpd commits", "uci commit dhcp" in cmd)

# --- build_dns_cmds (dnsmasq) ---
dnsmasq_detect = "dhcp.@dnsmasq[0].server='9.9.9.9' '149.112.112.112'\n"
cmd = owctl.build_dns_cmds("dnsmasq", dnsmasq_detect, ["1.1.1.1"], [])
check("dns dnsmasq del 9.9.9.9", "del_list dhcp.@dnsmasq[0].server='9.9.9.9'" in cmd)
check("dns dnsmasq del 149", "del_list dhcp.@dnsmasq[0].server='149.112.112.112'" in cmd)
check("dns dnsmasq add 1.1.1.1", "add_list dhcp.@dnsmasq[0].server='1.1.1.1'" in cmd)
cmd = owctl.build_dns_cmds("dnsmasq", dnsmasq_detect, [], [])
check("dns dnsmasq empty = clear only",
      "del_list dhcp.@dnsmasq[0].server='9.9.9.9'" in cmd and "add_list" not in cmd)

# --- quoting ---
check("quote plain", owctl._uci_quote("a") == "'a'")
check("quote apostrophe", owctl._uci_quote("O'Brien") == "'O'\\''Brien'")

# --- build_dhcp_cmds: full per-VLAN surface (new) ---
FULL = {
    "start": 200, "limit": 50, "lease_time": "1h", "dhcpv4": "server",
    "netmask": "255.255.255.0", "broadcast": "192.168.10.255", "local": True,
    "no_resolve": True, "notransfer": False, "no_default": False,
    "options": ["dhcp-option=6,1.1.1.1", "domain=home.lan", "ignore=6"],
    "static_leases": [{"name": "printer", "mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.10.50"}],
    "ipv6": {"dhcpv6": "server", "ra": True, "ra_management": "3",
             "ra_service": True, "ra_default_lifetime": "720"},
}
fc = owctl.build_dhcp_cmds("vlan_10", FULL)
for _name, _frag in [
    ("full: start", "start='200'"),
    ("full: limit", "limit='50'"),
    ("full: leasetime", "leasetime='1h'"),
    ("full: netmask", "netmask='255.255.255.0'"),
    ("full: broadcast", "broadcast='192.168.10.255'"),
    ("full: local on", "uci set dhcp.vlan_10.local=1"),
    ("full: no_resolve on", "uci set dhcp.vlan_10.no_resolve=1"),
    ("full: notransfer off (del)", "uci del dhcp.vlan_10.notransfer"),
    ("full: no_default off (del)", "uci del dhcp.vlan_10.no_default"),
    ("full: opt dns", "add_list dhcp.vlan_10.dhcp_option='dhcp-option=6,1.1.1.1'"),
    ("full: opt domain", "add_list dhcp.vlan_10.dhcp_option='domain=home.lan'"),
    ("full: opt ignore=6", "add_list dhcp.vlan_10.dhcp_option='ignore=6'"),
    ("full: options replaced first", "uci del dhcp.vlan_10.dhcp_option"),
    ("full: lease dnsmasq", "add_list dhcp.vlan_10.dhcp_host='printer, AA:BB:CC:DD:EE:FF, 192.168.10.50'"),
    ("full: lease odhcpd mirror", "add_list dhcp.vlan_10.host='printer, AA:BB:CC:DD:EE:FF, 192.168.10.50'"),
    ("full: ipv6 dhcpv6", "dhcpv6='server'"),
    ("full: ipv6 ra on", "uci set dhcp.vlan_10.ra=1"),
    ("full: ipv6 ra_management", "ra_management='3'"),
    ("full: ipv6 ra_service on", "uci set dhcp.vlan_10.ra_service=1"),
    ("full: ipv6 ra_default_lifetime", "ra_default_lifetime='720'"),
]:
    check(_name, _frag in fc)
check("full: leases deleted before add", "uci del dhcp.vlan_10.dhcp_host" in fc and "uci del dhcp.vlan_10.host" in fc)
check("full: relay mode", "dhcpv4='relay'" in owctl.build_dhcp_cmds("vlan_10", {"dhcpv4": "relay"}))
check("full: empty cfg still valid section", "uci set dhcp.vlan_10=dhcp" in owctl.build_dhcp_cmds("vlan_10", {}))
check("full: leasetime defaults 12h", "leasetime='12h'" in owctl.build_dhcp_cmds("vlan_10", {}))

# --- readers: static leases + ipv6 (new, pure) ---
FULL_UCI = (
    "dhcp.vlan_10=dhcp\n"
    "dhcp.vlan_10.interface='vlan_10'\n"
    "dhcp.vlan_10.start=200\n"
    "dhcp.vlan_10.limit=50\n"
    "dhcp.vlan_10.leasetime=1h\n"
    "dhcp.vlan_10.dhcpv4=server\n"
    "dhcp.vlan_10.no_resolve=1\n"
    "dhcp.vlan_10.dhcp_option='dhcp-option=6,1.1.1.1' 'ignore=6'\n"
    "dhcp.vlan_10.dhcp_host='printer, AA:BB:CC:DD:EE:FF, 192.168.10.50'\n"
    "dhcp.vlan_10.dhcpv6=server\n"
    "dhcp.vlan_10.ra=1\n"
    "dhcp.vlan_10.ra_management=3\n"
    "dhcp.vlan_10.ra_service=1\n"
)
_full_sec = owctl._parse_uci_show(FULL_UCI)["dhcp.vlan_10"]
check("read: static lease parsed",
      owctl._parse_dhcp_host_list(_full_sec) ==
      [{"name": "printer", "mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.10.50"}])
_full_ip6 = owctl._parse_ipv6_section(_full_sec)
check("read: ipv6 dhcpv6", _full_ip6.get("dhcpv6") == "server")
check("read: ipv6 ra true", _full_ip6.get("ra") is True)
check("read: ipv6 ra_management", _full_ip6.get("ra_management") == "3")
check("read: ipv6 ra_service true", _full_ip6.get("ra_service") is True)
check("read: no leases on empty section", owctl._parse_dhcp_host_list({"interface": ["x"]}) == [])
check("read: ipv6 empty on plain section", owctl._parse_ipv6_section({"interface": ["x"]}) == {})
# odhcpd `host` fallback (no dhcp_host key present)
_od_sec = owctl._parse_uci_show("dhcp.vlan_20=dhcp\ndhcp.vlan_20.interface='vlan_20'\ndhcp.vlan_20.start=1\n")["dhcp.vlan_20"]
_od_sec["host"] = ["nas, 11:22:33:44:55:66, 192.168.20.9"]
check("read: odhcpd host fallback",
      owctl._parse_dhcp_host_list(_od_sec) == [{"name": "nas", "mac": "11:22:33:44:55:66", "ip": "192.168.20.9"}])

print(f"\n=== SUMMARY ===\n{passed}/{passed+failed} checks passed")
sys.exit(1 if failed else 0)
