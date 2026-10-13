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
"""checks_audit_qos.py — threat-engine rule: QoS disabled (step 6).

Drives audit_status() with synthetic status dicts. st["qos"] holds the
parse_sqm() result (a dict) when SQM/nft-qos is configured, None when the
package is absent, and is simply missing on LuCI-only boxes.

Contract:
  - qos dict with enabled=False  -> INFO finding
  - qos dict with enabled=True   -> no finding
  - qos is None / missing        -> no finding (don't nag)
  - WAN down                     -> no finding (shaping irrelevant)

Run: .venv/bin/python checks_audit_qos.py
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


def rule_ids(st):
    return {f["rule_id"] for f in owctl.audit_status(st)}


def base(**kw):
    s = {"telnet_on": False, "fw_in": "DROP", "fw_fwd": "DROP", "ntp": "true",
         "wan_up": True, "redirects": []}
    s.update(kw)
    return s


def main():
    # QoS configured but disabled -> INFO finding
    ids = rule_ids(base(qos={"enabled": False, "backend": "sqm"}))
    check("qos off: finding present", "qos_disabled" in ids, str(ids))
    f = next(f for f in owctl.audit_status(base(qos={"enabled": False})) if f["rule_id"] == "qos_disabled")
    check("qos off: severity INFO", f["severity"] == "INFO", f["severity"])

    # QoS enabled -> no finding
    check("qos on: no finding", "qos_disabled" not in rule_ids(base(qos={"enabled": True})), "")

    # Package absent (qos None) -> no finding
    check("qos none: no finding", "qos_disabled" not in rule_ids(base(qos=None)), "")

    # Not gathered at all (key missing, e.g. LuCI-only) -> no finding
    check("qos missing key: no finding", "qos_disabled" not in rule_ids(base()), "")

    # QoS off but WAN down -> no finding
    check("qos off + WAN down: no finding",
          "qos_disabled" not in rule_ids(base(qos={"enabled": False}, wan_up=False)), "")

    # Regression: existing firewall rule still fires alongside
    ids = rule_ids(base(fw_fwd="ACCEPT", qos={"enabled": False}))
    check("regression: fw_forward_accept still fires", "fw_forward_accept" in ids, str(ids))
    check("regression: qos finding coexists", "qos_disabled" in ids, str(ids))

    print(f"\n=== SUMMARY ===\n{sum(1 for _, ok, _ in CHECKS if ok)}/{len(CHECKS)} checks passed")
    failed = [n for n, ok, _ in CHECKS if not ok]
    if failed:
        print("FAILURES:")
        for n in failed:
            print(" -", n)
        sys.exit(1)
    print("ALL AUDIT QOS CHECKS PASSED")


if __name__ == "__main__":
    main()
