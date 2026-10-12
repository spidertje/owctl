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

print(f"\n=== SUMMARY ===\n{passed}/{passed+failed} checks passed")
sys.exit(1 if failed else 0)
