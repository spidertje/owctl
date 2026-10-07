import os
import sys
import tempfile
import shutil
import re

# Setup temp environment for owctl
tmpdir = tempfile.mkdtemp()
os.environ["OWCTL_DATA"] = tmpdir

# Import owctl
sys.path.insert(0, os.getcwd())
import owctl

def test_audit():
    print("Running audit rule checks...")
    checks = 0
    passed = 0

    def assert_rule(st, rule_id, expected_sev):
        nonlocal checks, passed
        checks += 1
        findings = owctl.audit_status(st)
        rule = next((f for f in findings if f["rule_id"] == rule_id), None)
        if expected_sev is None:
            if rule is None:
                passed += 1
            else:
                print(f"FAIL: Rule {rule_id} should not have fired, but fired with {rule['severity']}")
        else:
            if rule and rule["severity"] == expected_sev:
                passed += 1
            elif rule:
                print(f"FAIL: Rule {rule_id} expected {expected_sev}, got {rule['severity']}")
            else:
                print(f"FAIL: Rule {rule_id} expected {expected_sev}, but did not fire")

    # 1. Disk usage
    assert_rule({"disk_used_pct": 90, "disk": "used=90%"}, "disk_full", "HIGH")
    assert_rule({"disk_used_pct": 95, "disk": "used=95%"}, "disk_full", "HIGH")
    assert_rule({"disk_used_pct": 80, "disk": "used=80%"}, "disk_full", "MEDIUM")
    assert_rule({"disk_used_pct": 89, "disk": "used=89%"}, "disk_full", "MEDIUM")
    assert_rule({"disk_used_pct": 79, "disk": "used=79%"}, "disk_full", None)
    assert_rule({}, "disk_full", None)

    # 2. Thermal
    assert_rule({"cpu_temp_c": 85.0}, "cpu_hot", "MEDIUM")
    assert_rule({"cpu_temp_c": 90.0}, "cpu_hot", "MEDIUM")
    assert_rule({"cpu_temp_c": 75.0}, "cpu_hot", "LOW")
    assert_rule({"cpu_temp_c": 84.9}, "cpu_hot", "LOW")
    assert_rule({"cpu_temp_c": 74.0}, "cpu_hot", None)
    assert_rule({}, "cpu_hot", None)

    # 3. WPA2-PSK (no 802.1X)
    # rule: contains 'psk' but not 'psk2'/'psk3'
    assert_rule({"wifi": [{"essid": "test", "encryption": "WPA-PSK (CCMP)"}]}, "wpa2_psk", "LOW")
    assert_rule({"wifi": [{"essid": "test", "encryption": "psk"}]}, "wpa2_psk", "LOW")
    assert_rule({"wifi": [{"essid": "test", "encryption": "psk2"}]}, "wpa2_psk", None)
    assert_rule({"wifi": [{"essid": "test", "encryption": "WPA2 PSK"}]}, "wpa2_psk", "LOW")
    assert_rule({"wifi": [{"essid": "test", "encryption": "psk3"}]}, "wpa2_psk", None)
    assert_rule({"wifi": [{"essid": "test", "encryption": "mixed psk psk2"}]}, "wpa2_psk", None)

    # 4. WiFi Open
    # CRITICAL if any AP encryption is 'open'/''/'none', HIGH if 'none' string present.
    # My interpretation: CRITICAL for open/'', HIGH for none (unless open also present)
    assert_rule({"wifi": [{"essid": "test", "encryption": "open"}]}, "wifi_open", "CRITICAL")
    assert_rule({"wifi": [{"essid": "test", "encryption": ""}]}, "wifi_open", "CRITICAL")
    assert_rule({"wifi": [{"essid": "test", "encryption": "none"}]}, "wifi_open", "HIGH")
    assert_rule({"wifi": [{"essid": "test", "encryption": "open"}, {"essid": "test2", "encryption": "none"}]}, "wifi_open", "CRITICAL")
    assert_rule({"wifi": [{"essid": "test", "encryption": "psk2"}]}, "wifi_open", None)

    print(f"SUMMARY: {passed}/{checks} checks passed")
    if passed != checks:
        sys.exit(1)

def test_parsing():
    print("Running parsing checks...")
    
    # Disk parsing
    s = {"disk": "287M used=45% free=120M"}
    st = owctl._build_status({"host": "h", "name": "n"}, "ssh", s)
    if st.get("disk_used_pct") != 45:
        print(f"FAIL: disk_used_pct expected 45, got {st.get('disk_used_pct')}")
        sys.exit(1)
        
    # Thermal parsing
    s = {"thermal": "45000\n"}
    st = owctl._build_status({"host": "h", "name": "n"}, "ssh", s)
    if st.get("cpu_temp_c") != 45.0:
        print(f"FAIL: cpu_temp_c expected 45.0, got {st.get('cpu_temp_c')}")
        sys.exit(1)

    s = {"thermal": ""}
    st = owctl._build_status({"host": "h", "name": "n"}, "ssh", s)
    if st.get("cpu_temp_c") is not None:
        print(f"FAIL: cpu_temp_c expected None for empty input, got {st.get('cpu_temp_c')}")
        sys.exit(1)

    print("Parsing checks passed")

if __name__ == "__main__":
    try:
        test_parsing()
        test_audit()
    finally:
        shutil.rmtree(tmpdir)
