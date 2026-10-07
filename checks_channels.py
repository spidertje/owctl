#!/usr/bin/env python3
"""Verify ntfy, pushover, discord alert channels in owctl."""

import json
import os
import sys
import tempfile
import urllib.request
from contextlib import contextmanager
from unittest.mock import MagicMock

# Setup isolated data dir
tmpdir = tempfile.mkdtemp(prefix="owctl_test_")
os.environ["OWCTL_DATA"] = tmpdir

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import owctl  # noqa: E402

RECORDED = []  # list of (url, data, headers)


class FakeResponse:
    def __init__(self, body=b'{}'):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


class FakeOpener:
    def __init__(self, should_fail=False, fail_msg="network error"):
        self.should_fail = should_fail
        self.fail_msg = fail_msg

    def __call__(self, req, timeout=None):
        if self.should_fail:
            raise Exception(self.fail_msg)
        RECORDED.append((req.get_full_url(), req.data, dict(req.headers)))
        return FakeResponse()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


@contextmanager
def patch_urlopen(opener):
    original = urllib.request.urlopen
    urllib.request.urlopen = opener
    try:
        yield
    finally:
        urllib.request.urlopen = original


def run_checks():
    passed = 0
    total = 0

    def assert_check(name, cond):
        nonlocal passed, total
        total += 1
        if cond:
            passed += 1
            print(f"PASS  {name}")
        else:
            print(f"FAIL  {name}")
        return cond

    # --- ntfy ---
    RECORDED.clear()
    owctl.set_alert_cfg({
        "min_severity": "LOW",
        "channels": {
            "ntfy": {"enabled": True, "server": "https://ntfy.example.com", "topic": "alerts"}
        }
    })
    with patch_urlopen(FakeOpener()):
        used = owctl.fire_alert({"name": "r1", "host": "10.0.0.1"},
                                {"severity": "HIGH", "rule_id": "test", "message": "test msg"})
    assert_check("ntfy: channel fires when enabled + topic", "ntfy" in used)
    assert_check("ntfy: correct endpoint", len(RECORDED) == 1 and "https://ntfy.example.com/alerts" in RECORDED[0][0])
    assert_check("ntfy: raw text payload", RECORDED[0][1] == b"[HIGH] r1 (10.0.0.1): test msg")
    assert_check("ntfy: Title header", RECORDED[0][2].get("Title") == "owctl [HIGH] r1")
    assert_check("ntfy: Content-Type text/plain", RECORDED[0][2].get("Content-Type", "").lower() == "text/plain" or RECORDED[0][2].get("Content-type", "").lower() == "text/plain")

    # ntfy default server
    RECORDED.clear()
    owctl.set_alert_cfg({"min_severity": "LOW", "channels": {"ntfy": {"enabled": True, "topic": "t"}}})
    with patch_urlopen(FakeOpener()):
        owctl.fire_alert({"name": "r1", "host": "10.0.0.1"}, {"severity": "LOW", "rule_id": "x", "message": "m"})
    assert_check("ntfy: default server used", len(RECORDED) == 1 and "https://ntfy.sh/t" in RECORDED[0][0])

    # ntfy disabled -> no attempt
    RECORDED.clear()
    owctl.set_alert_cfg({"min_severity": "LOW", "channels": {"ntfy": {"enabled": False, "topic": "t"}}})
    with patch_urlopen(FakeOpener()):
        used = owctl.fire_alert({"name": "r1", "host": "10.0.0.1"}, {"severity": "LOW", "rule_id": "x", "message": "m"})
    assert_check("ntfy: disabled not attempted", "ntfy" not in used and len(RECORDED) == 0)

    # ntfy missing topic -> no attempt
    RECORDED.clear()
    owctl.set_alert_cfg({"min_severity": "LOW", "channels": {"ntfy": {"enabled": True}}})
    with patch_urlopen(FakeOpener()):
        used = owctl.fire_alert({"name": "r1", "host": "10.0.0.1"}, {"severity": "LOW", "rule_id": "x", "message": "m"})
    assert_check("ntfy: missing topic not attempted", "ntfy" not in used and len(RECORDED) == 0)

    # ntfy failure -> records FAIL
    RECORDED.clear()
    owctl.set_alert_cfg({"min_severity": "LOW", "channels": {"ntfy": {"enabled": True, "topic": "t"}}})
    with patch_urlopen(FakeOpener(should_fail=True, fail_msg="timeout")):
        used = owctl.fire_alert({"name": "r1", "host": "10.0.0.1"}, {"severity": "LOW", "rule_id": "x", "message": "m"})
    assert_check("ntfy: failure recorded", any(u.startswith("ntfy:FAIL") for u in used))

    # --- pushover ---
    RECORDED.clear()
    owctl.set_alert_cfg({
        "min_severity": "LOW",
        "channels": {"pushover": {"enabled": True, "token": "APP_TOKEN", "user_key": "USER_KEY"}}
    })
    with patch_urlopen(FakeOpener()):
        used = owctl.fire_alert({"name": "r1", "host": "10.0.0.1"},
                                {"severity": "MEDIUM", "rule_id": "test", "message": "test msg"})
    assert_check("pushover: channel fires", "pushover" in used)
    assert_check("pushover: correct endpoint", len(RECORDED) == 1 and RECORDED[0][0] == "https://api.pushover.net/1/messages.json")
    payload = RECORDED[0][1].decode()
    from urllib.parse import parse_qs
    parsed = parse_qs(payload)
    assert_check("pushover: has token", parsed.get("token") == ["APP_TOKEN"])
    assert_check("pushover: has user_key", parsed.get("user") == ["USER_KEY"])
    assert_check("pushover: has message", "test msg" in parsed.get("message", [""])[0])
    assert_check("pushover: has title", parsed.get("title") == ["owctl MEDIUM"])
    ct = RECORDED[0][2].get("Content-Type", "").lower() or RECORDED[0][2].get("Content-type", "").lower()
    assert_check("pushover: form content-type", ct == "application/x-www-form-urlencoded")

    # pushover disabled
    RECORDED.clear()
    owctl.set_alert_cfg({"min_severity": "LOW", "channels": {"pushover": {"enabled": False, "token": "t", "user_key": "u"}}})
    with patch_urlopen(FakeOpener()):
        used = owctl.fire_alert({"name": "r1", "host": "10.0.0.1"}, {"severity": "LOW", "rule_id": "x", "message": "m"})
    assert_check("pushover: disabled not attempted", "pushover" not in used and len(RECORDED) == 0)

    # pushover missing token
    RECORDED.clear()
    owctl.set_alert_cfg({"min_severity": "LOW", "channels": {"pushover": {"enabled": True, "user_key": "u"}}})
    with patch_urlopen(FakeOpener()):
        used = owctl.fire_alert({"name": "r1", "host": "10.0.0.1"}, {"severity": "LOW", "rule_id": "x", "message": "m"})
    assert_check("pushover: missing token not attempted", "pushover" not in used and len(RECORDED) == 0)

    # pushover failure
    RECORDED.clear()
    owctl.set_alert_cfg({"min_severity": "LOW", "channels": {"pushover": {"enabled": True, "token": "t", "user_key": "u"}}})
    with patch_urlopen(FakeOpener(should_fail=True, fail_msg="bad")):
        used = owctl.fire_alert({"name": "r1", "host": "10.0.0.1"}, {"severity": "LOW", "rule_id": "x", "message": "m"})
    assert_check("pushover: failure recorded", any(u.startswith("pushover:FAIL") for u in used))

    # --- discord ---
    RECORDED.clear()
    owctl.set_alert_cfg({
        "min_severity": "LOW",
        "channels": {"discord": {"enabled": True, "webhook_url": "https://discord.com/api/webhooks/123/abc"}}
    })
    with patch_urlopen(FakeOpener()):
        used = owctl.fire_alert({"name": "r1", "host": "10.0.0.1"},
                                {"severity": "CRITICAL", "rule_id": "test", "message": "test msg"})
    assert_check("discord: channel fires", "discord" in used)
    assert_check("discord: correct endpoint", len(RECORDED) == 1 and "discord.com/api/webhooks" in RECORDED[0][0])
    payload = json.loads(RECORDED[0][1].decode())
    assert_check("discord: JSON content field", payload.get("content") == "[CRITICAL] r1 (10.0.0.1): test msg")
    ct = RECORDED[0][2].get("Content-Type", "").lower() or RECORDED[0][2].get("Content-type", "").lower()
    assert_check("discord: application/json", ct == "application/json")

    # discord disabled
    RECORDED.clear()
    owctl.set_alert_cfg({"min_severity": "LOW", "channels": {"discord": {"enabled": False, "webhook_url": "https://discord.com/api/webhooks/x"}}})
    with patch_urlopen(FakeOpener()):
        used = owctl.fire_alert({"name": "r1", "host": "10.0.0.1"}, {"severity": "LOW", "rule_id": "x", "message": "m"})
    assert_check("discord: disabled not attempted", "discord" not in used and len(RECORDED) == 0)

    # discord missing webhook_url
    RECORDED.clear()
    owctl.set_alert_cfg({"min_severity": "LOW", "channels": {"discord": {"enabled": True}}})
    with patch_urlopen(FakeOpener()):
        used = owctl.fire_alert({"name": "r1", "host": "10.0.0.1"}, {"severity": "LOW", "rule_id": "x", "message": "m"})
    assert_check("discord: missing url not attempted", "discord" not in used and len(RECORDED) == 0)

    # discord invalid webhook (not https)
    RECORDED.clear()
    owctl.set_alert_cfg({"min_severity": "LOW", "channels": {"discord": {"enabled": True, "webhook_url": "http://not-https"}}})
    with patch_urlopen(FakeOpener()):
        used = owctl.fire_alert({"name": "r1", "host": "10.0.0.1"}, {"severity": "LOW", "rule_id": "x", "message": "m"})
    assert_check("discord: non-https skipped", "discord" not in used and len(RECORDED) == 0)

    # discord failure
    RECORDED.clear()
    owctl.set_alert_cfg({"min_severity": "LOW", "channels": {"discord": {"enabled": True, "webhook_url": "https://discord.com/api/webhooks/123/abc"}}})
    with patch_urlopen(FakeOpener(should_fail=True, fail_msg="discord down")):
        used = owctl.fire_alert({"name": "r1", "host": "10.0.0.1"}, {"severity": "LOW", "rule_id": "x", "message": "m"})
    assert_check("discord: failure recorded", any(u.startswith("discord:FAIL") for u in used))

    print(f"\n{passed}/{total} checks passed")
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    run_checks()