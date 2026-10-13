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
"""checks_firewall.py — unit tests for the firewall uci parser (QoS/firewall step 2).

Pure parser tests: feed recorded `uci show firewall` output (OpenWrt 23.05
fw4 shapes, quoted + bare value forms, list options) and assert the parsed
structure. No SSH, no box.

Run: .venv/bin/python checks_firewall.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

tmp = tempfile.mkdtemp()
os.environ["OWCTL_DATA"] = tmp

import owctl  # noqa: E402

CHECKS = []


def check(name, cond, extra=""):
    CHECKS.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


# ── Fixture: realistic 23.05 config — 2 zones, 2 forwards (one named, one
#    auto-numbered), 2 inter-zone rules, one list option, a limit rule ──────
FW_FIXTURE = """\
firewall.defaults=defaults
firewall.defaults.input='ACCEPT'
firewall.defaults.output='ACCEPT'
firewall.defaults.forward='REJECT'
firewall.lan=zone
firewall.lan.name='lan'
firewall.lan.network='lan'
firewall.lan.input='ACCEPT'
firewall.lan.output='ACCEPT'
firewall.lan.forward='ACCEPT'
firewall.wan=zone
firewall.wan.name='wan'
firewall.wan.network='wan wan6'
firewall.wan.input='DROP'
firewall.wan.output='ACCEPT'
firewall.wan.forward='REJECT'
firewall.dnsmasq=redirect
firewall.dnsmasq.name='dnsmasq'
firewall.dnsmasq.src='wan'
firewall.dnsmasq.proto='tcp udp'
firewall.dnsmasq.src_dport='53'
firewall.dnsmasq.dest_ip='192.168.1.1'
firewall.dnsmasq.dest_port='53'
firewall.101=redirect
firewall.101.name='cam'
firewall.101.proto='tcp'
firewall.101.src_dport='8080'
firewall.101.dest_ip='192.168.1.50'
firewall.101.dest_port='80'
firewall.102=rule
firewall.102.name='allow cam lan'
firewall.102.src='lan'
firewall.102.dest='wan'
firewall.102.target='ACCEPT'
firewall.103=rule
firewall.103.name='block guest to lan'
firewall.103.src='guest'
firewall.103.dest='lan'
firewall.103.target='REJECT'
firewall.104=rule
firewall.104.name='limit ssh'
firewall.104.src='wan'
firewall.104.dest='lan'
firewall.104.target='ACCEPT'
firewall.104.limit='6'
firewall.104.limit_refresh='120'
"""

# ── Fixture: minimal config (defaults only) ─────────────────────────────────
FW_MINIMAL = """\
firewall.defaults=defaults
firewall.defaults.input='ACCEPT'
firewall.defaults.output='ACCEPT'
firewall.defaults.forward='REJECT'
"""

# ── Fixture: stderr noise (package absent) ──────────────────────────────────
FW_MISSING = """\
uci: Package 'firewall' is not defined
uci: Failed to load data file '/etc/config/firewall'
"""


def main():
    # ── zones ─────────────────────────────────────────────────────────────
    r = owctl.parse_firewall(FW_FIXTURE)
    check("fw: parsed dict", isinstance(r, dict), str(r))
    zones = r.get("zones", [])
    names = {z["name"] for z in zones}
    check("fw zones: lan + wan present", {"lan", "wan"} <= names, str(names))
    lan = next(z for z in zones if z["name"] == "lan")
    check("fw zone: input policy", lan["input"] == "ACCEPT", str(lan))
    check("fw zone: forward policy", lan["forward"] == "ACCEPT", str(lan))
    wan = next(z for z in zones if z["name"] == "wan")
    check("fw zone wan: input DROP", wan["input"] == "DROP", str(wan))
    check("fw zone wan: network list", wan["network"] == "wan wan6", str(wan))

    # ── defaults ──────────────────────────────────────────────────────────
    d = r.get("defaults", {})
    check("fw defaults: forward", d.get("forward") == "REJECT", str(d))

    # ── redirects ─────────────────────────────────────────────────────────
    reds = r.get("redirects", [])
    check("fw redirects: two", len(reds) == 2, str(len(reds)))
    cam = next(x for x in reds if x.get("name") == "cam")
    check("fw redirect: proto", cam["proto"] == "tcp", str(cam))
    check("fw redirect: src_dport", cam["src_dport"] == "8080", str(cam))
    check("fw redirect: dest_ip", cam["dest_ip"] == "192.168.1.50", str(cam))
    check("fw redirect: dest_port", cam["dest_port"] == "80", str(cam))
    dns = next(x for x in reds if x.get("name") == "dnsmasq")
    check("fw redirect: multi-proto list", dns["proto"] == "tcp udp", str(dns))

    # ── rules ─────────────────────────────────────────────────────────────
    rules = r.get("rules", [])
    check("fw rules: three", len(rules) == 3, str(len(rules)))
    allow = next(x for x in rules if x.get("name") == "allow cam lan")
    check("fw rule: src zone", allow["src"] == "lan", str(allow))
    check("fw rule: target", allow["target"] == "ACCEPT", str(allow))
    block = next(x for x in rules if x.get("name") == "block guest to lan")
    check("fw rule: REJECT target", block["target"] == "REJECT", str(block))
    lim = next(x for x in rules if x.get("name") == "limit ssh")
    check("fw rule: limit opt", lim.get("limit") == "6", str(lim))

    # ── helpers: lookups ──────────────────────────────────────────────────
    check("fw: find_redirect by name", owctl.firewall_find_redirect(r, "cam") == cam, "lookup")
    check("fw: find_redirect missing -> None", owctl.firewall_find_redirect(r, "nope") is None, "lookup")
    check("fw: find_rule by name", owctl.firewall_find_rule(r, "limit ssh") == lim, "lookup")
    check("fw: zone names list", sorted(owctl.firewall_zone_names(r)) == ["lan", "wan"], str(r.get("zones")))

    # ── edge cases ────────────────────────────────────────────────────────
    check("fw: empty input -> all empty",
          owctl.parse_firewall("") == {"zones": [], "redirects": [], "rules": [], "defaults": {}},
          str(owctl.parse_firewall("")))
    check("fw: stderr noise -> all empty",
          owctl.parse_firewall(FW_MISSING) == {"zones": [], "redirects": [], "rules": [], "defaults": {}},
          str(owctl.parse_firewall(FW_MISSING)))
    m = owctl.parse_firewall(FW_MINIMAL)
    check("fw: minimal -> no zones/redirects/rules",
          m["zones"] == [] and m["redirects"] == [] and m["rules"] == [], str(m))
    check("fw: minimal -> defaults kept", m["defaults"].get("forward") == "REJECT", str(m))

    # ── list options survive (add_list) ───────────────────────────────────
    # a section using add_list-style multi-value option
    lst = "firewall.lan=zone\nfirewall.lan.name='lan'\nfirewall.lan.network='lan'\n"
    r2 = owctl.parse_firewall(lst)
    z2 = next(z for z in r2["zones"])
    check("fw: network option string", z2["network"] == "lan", str(z2))

    print(f"\n=== SUMMARY ===\n{sum(1 for _, ok, _ in CHECKS if ok)}/{len(CHECKS)} checks passed")
    failed = [n for n, ok, _ in CHECKS if not ok]
    if failed:
        print("FAILURES:")
        for n in failed:
            print(" -", n)
        sys.exit(1)
    print("ALL FIREWALL PARSER CHECKS PASSED")


if __name__ == "__main__":
    main()
