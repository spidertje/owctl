#!/usr/bin/env python3
"""checks_qos.py — unit tests for the QoS uci parsers (step 1 of QoS/firewall feature).

Pure parser tests: feed recorded `uci show` output (quoted AND unquoted value
forms, real OpenWrt 23.05 shapes) and assert the parsed dicts. No SSH, no box.

Run: .venv/bin/python checks_qos.py
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


# ── Fixture: luci-app-sqm on 23.05 (values as uci show renders them — bare
#    alphanumerics unquoted, dotted/special values single-quoted) ─────────────
SQM_FIXTURE = """\
sqm.wan=queue
sqm.wan.enabled=1
sqm.wan.interface='wan'
sqm.wan.upload='20000'
sqm.wan.download='100000'
sqm.wan.linklayer='ethernet'
sqm.wan.overhead='0'
sqm.wan.fq_codel='1'
sqm.wan.ecn='0'
"""

# ── Fixture: same config but every value single-quoted (other uci builds) ───
SQM_FIXTURE_ALL_QUOTED = """\
sqm.wan='queue'
sqm.wan.enabled='1'
sqm.wan.interface='wan'
sqm.wan.upload='20000'
sqm.wan.download='100000'
sqm.wan.linklayer='ethernet'
sqm.wan.overhead='0'
sqm.wan.fq_codel='1'
sqm.wan.ecn='0'
"""

# ── Fixture: two sections, only wan6 enabled; cake selected ─────────────────
SQM_TWO_SECTIONS = """\
sqm.wan=queue
sqm.wan.enabled='0'
sqm.wan.interface='wan'
sqm.wan.upload='0'
sqm.wan.download='0'
sqm.wan6=queue
sqm.wan6.enabled='1'
sqm.wan6.interface='wan6'
sqm.wan6.upload='5000'
sqm.wan6.download='25000'
sqm.wan6.cake='1'
sqm.wan6.ecn='1'
"""

# ── Fixture: nft-qos (23.05) — speeds live in the 'defaults' section ────────
NFTQOS_FIXTURE = """\
nft-qos.defaults=defaults
nft-qos.defaults.download='100000'
nft-qos.defaults.upload='10000'
nft-qos.defaults.interfaces='wan'
"""

# ── Fixture: stderr noise a real box emits when the package is missing ──────
SQM_MISSING = """\
uci: Package 'sqm' is not defined
uci: Failed to load data file '/etc/config/sqm'
"""


def main():
    # ── parse_uci_show: core grouping ─────────────────────────────────────
    parsed = owctl.parse_uci_show(SQM_FIXTURE)
    check("uci_show: single package found", set(parsed) == {"sqm"}, str(parsed))
    check("uci_show: named section is a dict", isinstance(parsed.get("sqm", {}).get("wan"), dict),
          str(type(parsed.get("sqm", {}).get("wan"))))
    sec = parsed.get("sqm", {}).get("wan", {})
    check("uci_show: section type captured", sec.get("type") == "queue", str(sec.get("type")))
    check("uci_show: unquoted value parsed", sec.get("enabled") == "1", str(sec.get("enabled")))
    check("uci_show: quoted value unquoted", sec.get("interface") == "wan", str(sec.get("interface")))

    # all-quoted fixture parses identically
    parsed_q = owctl.parse_uci_show(SQM_FIXTURE_ALL_QUOTED)
    check("uci_show: all-quoted fixture equals unquoted parse",
          parsed_q.get("sqm", {}).get("wan") == sec, f"{parsed_q}")

    # empty / missing output
    check("uci_show: empty input -> {}", owctl.parse_uci_show("") == {})
    check("uci_show: stderr-only input -> {}", owctl.parse_uci_show(SQM_MISSING) == {})

    # ── parse_sqm: luci-app-sqm ────────────────────────────────────────────
    r = owctl.parse_sqm(SQM_FIXTURE)
    check("sqm: parsed", r is not None, str(r))
    check("sqm: backend tagged", r and r["backend"] == "sqm", str(r))
    check("sqm: enabled true", r and r["enabled"] is True, str(r))
    check("sqm: interface", r and r["interface"] == "wan", str(r))
    check("sqm: download kbps", r and r["download_kbps"] == 100000, str(r))
    check("sqm: upload kbps", r and r["upload_kbps"] == 20000, str(r))
    check("sqm: qdisc fq_codel", r and r["qdisc"] == "fq_codel", str(r))
    check("sqm: ecn off", r and r["ecn"] is False, str(r))

    # ── parse_sqm: picks the enabled section when several exist ───────────
    r2 = owctl.parse_sqm(SQM_TWO_SECTIONS)
    check("sqm multi: picks enabled section", r2 and r2["interface"] == "wan6", str(r2))
    check("sqm multi: cake qdisc", r2 and r2["qdisc"] == "cake", str(r2))
    check("sqm multi: ecn on", r2 and r2["ecn"] is True, str(r2))
    check("sqm multi: speeds", r2 and r2["download_kbps"] == 25000 and r2["upload_kbps"] == 5000, str(r2))

    # ── parse_sqm: nft-qos backend ─────────────────────────────────────────
    r3 = owctl.parse_sqm(NFTQOS_FIXTURE)
    check("nft-qos: parsed", r3 is not None, str(r3))
    check("nft-qos: backend tagged", r3 and r3["backend"] == "nft-qos", str(r3))
    check("nft-qos: download", r3 and r3["download_kbps"] == 100000, str(r3))
    check("nft-qos: upload", r3 and r3["upload_kbps"] == 10000, str(r3))
    check("nft-qos: interface from list", r3 and r3["interface"] == "wan", str(r3))
    check("nft-qos: qdisc unknown -> None", r3 and r3["qdisc"] is None, str(r3))

    # ── parse_sqm: not configured ─────────────────────────────────────────
    check("sqm: empty input -> None", owctl.parse_sqm("") is None)
    check("sqm: stderr noise -> None", owctl.parse_sqm(SQM_MISSING) is None)
    check("sqm: wrong package -> None",
          owctl.parse_sqm("firewall.defaults=defaults\nfirewall.defaults.default_input='DROP'\n") is None)

    # ── edge: escaped quote inside a value ─────────────────────────────────
    esc = owctl.parse_uci_show("sqm.wan=queue\nsqm.wan.interface='a\\'b'\n")
    check("uci_show: escaped quote unescaped",
          esc.get("sqm", {}).get("wan", {}).get("interface") == "a'b", str(esc))

    print(f"\n=== SUMMARY ===\n{sum(1 for _, ok, _ in CHECKS if ok)}/{len(CHECKS)} checks passed")
    failed = [n for n, ok, _ in CHECKS if not ok]
    if failed:
        print("FAILURES:")
        for n in failed:
            print(" -", n)
        sys.exit(1)
    print("ALL QOS PARSER CHECKS PASSED")


if __name__ == "__main__":
    main()
