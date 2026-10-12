"""Verification harness for wifi-clone command builder + wifi-iface parser.

Covers the two regressions fixed in this pass:
  1. _parse_wifi_ifaces must not let a radio attribute (e.g. radio0.type) clobber
     a wifi-iface's `device` field when the radio is declared BEFORE its iface
     (the common real-world `uci show` order).
  2. build_wifi_clone_cmds must quote values and NOT emit commit/reload
     (the endpoint batches those once per target).

Self-contained: throwaway OWCTL_DATA, reloads the app. Exits non-zero on failure.
"""
import os, sys
os.environ["OWCTL_DATA"] = "/tmp/owctl-wifi-clone-test-" + str(os.getpid())
os.makedirs(os.environ["OWCTL_DATA"], exist_ok=True)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib, owctl
importlib.reload(owctl)

passed = failed = 0
def check(name, cond):
    global passed, failed
    if cond: passed += 1; print("PASS", name)
    else: failed += 1; print("FAIL", name)

# --- Regression: radio declared BEFORE its iface (realistic order).
#     radio0.type must NOT land on the iface's `device` field. ---
REALISTIC = (
    "wireless.radio0=wifi-device\n"
    "wireless.radio0.type='mac80211'\n"
    "wireless.radio0.band='2g'\n"
    "wireless.radio0.channel='8'\n"
    "wireless.default_radio0=wifi-iface\n"
    "wireless.default_radio0.device='radio0'\n"
    "wireless.default_radio0.mode='ap'\n"
    "wireless.default_radio0.ssid='HomeNet'\n"
    "wireless.default_radio0.encryption='psk2'\n"
    "wireless.default_radio0.key='O''Brien'\n"
    "wireless.radio1=wifi-device\n"
    "wireless.radio1.band='5g'\n"
    "wireless.default_radio1=wifi-iface\n"
    "wireless.default_radio1.device='radio1'\n"
    "wireless.default_radio1.ssid='HomeNet-5G'\n"
    "wireless.default_radio1.encryption='none'\n"
)
ifaces = owctl._parse_wifi_ifaces(REALISTIC)
by_ssid = {i["ssid"]: i for i in ifaces}
check("iface device not clobbered by radio.type", by_ssid.get("HomeNet", {}).get("device") == "radio0")
check("2g band resolved", by_ssid.get("HomeNet", {}).get("band") == "2g")
check("5g band resolved", by_ssid.get("HomeNet-5G", {}).get("band") == "5g")
check("ssid kept", by_ssid.get("HomeNet", {}).get("ssid") == "HomeNet")
check("key captured (escaped in source)", by_ssid.get("HomeNet", {}).get("key") in ("O'Brien", "O''Brien"))

# --- build_wifi_clone_cmds: quoting, no commit, stable slug ---
slug, cmd = owctl.build_wifi_clone_cmds(
    {"ssid": "Home Net", "device": "radio0", "encryption": "psk2", "network": "lan", "key": "p@ss"}, "radio0")
check("slug from ssid", slug == "clone_Home_Net")
check("cmd sets wifi-iface", "uci set wireless.clone_Home_Net=wifi-iface" in cmd)
check("cmd sets ssid", "ssid='Home Net'" in cmd)
check("cmd quotes key", "key='p@ss'" in cmd)
check("cmd sets encryption", "encryption='psk2'" in cmd)
check("cmd sets network", "network='lan'" in cmd)
check("cmd has NO commit", "uci commit" not in cmd)
check("cmd has NO reload", "wifi reload" not in cmd)

# quote a value containing a single quote must not break out
slug2, cmd2 = owctl.build_wifi_clone_cmds({"ssid": "O'Brien", "device": "radio0", "key": "k'x"}, "radio0")
check("quoted ssid in cmd", "ssid='O'\\''Brien'" in cmd2)
check("quoted key in cmd", "key='k'\\''x'" in cmd2)

# empty ssid -> falls back to a generic section (original behavior), still valid uci
slug3, cmd3 = owctl.build_wifi_clone_cmds({"ssid": "", "device": "radio0"}, "radio0")
check("empty ssid -> clone_iface fallback", slug3 == "clone_iface" and "ssid=''" in cmd3)

print(f"\n=== SUMMARY ===\n{passed}/{passed+failed} checks passed")
sys.exit(1 if failed else 0)
