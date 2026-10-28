#!/usr/bin/env python3
"""checks_channel_parse.py — non-numeric wireless channel regression guard.

Contract (audit P1, MED): `int(chan.split()[0])` raised ValueError on a
non-numeric (or empty) channel. Because _build_status is called unguarded in
ssh_gather, ONE malformed wifi AP crashed the entire gather for that device —
no firmware, no audit, no findings.

The fix guards the parse: band is None when the channel can't be int'd, and
the AP is still recorded. This check feeds _build_status wireless sections
with numeric, non-numeric, and empty channels and asserts no exception + the
band is set only for the numeric one.
"""
import os
import sys
import tempfile

_tmp = tempfile.mkdtemp(prefix="owctl-chan-")
os.environ["OWCTL_DATA"] = os.path.join(_tmp, "data")
os.environ.setdefault("OWCTL_ALLOW_OPEN", "1")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import owctl  # noqa: E402

PASS = FAIL = 0


def check(label, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {label}")
    else:
        FAIL += 1
        print(f"FAIL {label} :: {detail}")


dev = {"name": "chan", "host": "chan", "access": "ssh"}

# A status dict with a mix of valid + malformed channels. The wireless section
# is tab-separated: ESSID \t Channel: <n> \t Encryption: <enc>
wireless_lines = [
    '"Home" \t Channel: 6 \t Encryption: psk2',   # numeric -> 2.4GHz
    '"Home" \t Channel: 36 \t Encryption: psk2',  # numeric -> 5GHz
    '"Auto" \t Channel: auto \t Encryption: psk2',  # non-numeric -> band None
    '"Empty" \t Channel: \t Encryption: psk2',     # empty -> band None
    '"Weird" \t Channel: 5g-auto \t Encryption: psk2',  # non-numeric -> None
]
s = {
    "release": "OpenWrt 23.05.4",
    "model": "mock",
    "date": "2026-01-01 00:00:00",
    "uptime": "100",
    "load": "0.1 0.2 0.3",
    "mem": "MemTotal=1000000 MemFree=500000",
    "disk": "used=10%",
    "clients": "3",
    "wan": '"ipaddr": ["1.2.3.4"]',
    "fw": "in=DROP fwd=DROP out=ACCEPT",
    "qos": "",
    "dropbear": "pwauth=no port=22",
    "listeners": "22 80",
    "ntp": "1",
    "redirects": "",
    "upgradable": "",
    "interfaces": "lo 127.0.0.1/8",
    "meshd": "",
    "wireless": "\n".join(wireless_lines),
    "stations": "",
    "neighbors": "",
    "dhcp": "",
    "installed": "",
    "obsolete": "",
    "config": "",
    "traffic": "",
    "thermal": "45000",
    "syslog": "",
    "vlans": "",
    "routing": "",
    "bgp_present": "",
}

# The old code raised ValueError here; the fixed code must not.
crashed = False
err = None
st = None
try:
    st = owctl._build_status(dev, "ssh", s)
except Exception as e:
    crashed = True
    err = repr(e)

check("_build_status does NOT crash on non-numeric channel", not crashed,
      f"raised: {err}")
if st is not None:
    wifi = st.get("wifi", [])
    check("all 5 APs still recorded", len(wifi) == 5, f"got {len(wifi)}")
    by_chan = {w["channel"]: w for w in wifi}
    check("channel 6 -> band 2.4GHz", by_chan.get("6", {}).get("band") == "2.4GHz",
          f"{by_chan.get('6')}")
    check("channel 36 -> band 5GHz", by_chan.get("36", {}).get("band") == "5GHz",
          f"{by_chan.get('36')}")
    check("channel 'auto' -> band None (no crash)",
          by_chan.get("auto", {}).get("band") is None, f"{by_chan.get('auto')}")
    check("channel '' -> band None (no crash)",
          by_chan.get("", {}).get("band") is None, f"{by_chan.get('')}")
    check("channel '5g-auto' -> band None (no crash)",
          by_chan.get("5g-auto", {}).get("band") is None, f"{by_chan.get('5g-auto')}")

print(f"\n=== SUMMARY ===\n{PASS}/{PASS + FAIL} checks passed")
sys.exit(0 if FAIL == 0 else 1)
