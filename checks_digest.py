#!/usr/bin/env python3
"""Checks for build_digest / send_digest / weekly trigger / /api/digest."""
import os
import smtplib
import sys
import tempfile
import time
import unittest.mock as mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

DATA = tempfile.mkdtemp(prefix="owctl-digest-test-")
os.environ["OWCTL_DATA"] = DATA
import owctl  # noqa: E402

owctl.DB_PATH = os.path.join(DATA, "test.db")
owctl.init_db()

ok = 0
fail = 0


def check(name, cond, extra=""):
    global ok, fail
    if cond:
        ok += 1
    else:
        fail += 1
        print(f"FAIL {name}" + (f"  [{extra}]" if extra else ""))


now = owctl.now()
# seed 2 devices
d1 = owctl.execute("INSERT INTO devices(name,host,status,health_score) VALUES(?,?,?,?)",
                   ("gw-edge", "10.0.0.1", "online", 92))
d2 = owctl.execute("INSERT INTO devices(name,host,status,health_score) VALUES(?,?,?,?)",
                   ("ap-floor2", "10.0.0.5", "offline", 40))
# 1 active finding on gw-edge
owctl.execute("INSERT INTO active_findings(device_id,rule_id,severity,message,detail,rec,ts) VALUES(?,?,?,?,?,?,?)",
              (d1, "stale_fw", "MEDIUM", "firmware outdated", "base-files 23.05.4-1", "upgrade", now))
# 1 finding in last 7 days on ap-floor2
owctl.execute("INSERT INTO findings(ts,device_id,device_name,rule_id,severity,message,detail,rec) VALUES(?,?,?,?,?,?,?,?)",
              (now, d2, "ap-floor2", "cpu_high", "HIGH", "CPU > 95%", "load 1.2", "reboot"))

# (c) build_digest
subject, body = owctl.build_digest()
check("subject non-empty", bool(subject), subject)
check("body contains gw-edge", "gw-edge" in body)
check("body contains ap-floor2", "ap-floor2" in body)
check("body contains '7 days' header", "=== New in last 7 days ===" in body)

# (d) send_digest with email configured — capture send_message
smtp_sent = {}

class FakeSMTP:
    def __init__(self, host, port, timeout):
        self.host = host
        self.sent_msgs = []
    def __enter__(self):
        return self
    def __exit__(self, *a):
        pass
    def starttls(self):
        pass
    def login(self, u, p):
        pass
    def send_message(self, msg):
        smtp_sent["msg"] = msg
        self.sent_msgs.append(str(msg))

with mock.patch("owctl.smtplib.SMTP", FakeSMTP):
    owctl.set_alert_cfg({
        "min_severity": "MEDIUM",
        "channels": {
            "dashboard": True,
            "email": {"enabled": True, "smtp_host": "127.0.0.1", "smtp_port": 25,
                      "use_tls": True, "user": "a", "password": "b",
                      "from": "ow@lan", "to": "ops@lan"},
            "telegram": {"enabled": False},
            "webhook": {"enabled": False},
        },
    })
    r = owctl.send_digest()

check("send_digest sent:True", r.get("sent") is True, str(r))
check("send_message captured", "msg" in smtp_sent, "no send_message captured")
if "msg" in smtp_sent:
    m = str(smtp_sent["msg"])
    check("digest in email body", "gw-edge" in m and "ap-floor2" in m, m[:200])

# (e) email disabled -> sent:False
with mock.patch("owctl.smtplib.SMTP", FakeSMTP):
    owctl.set_alert_cfg({
        "min_severity": "MEDIUM",
        "channels": {
            "dashboard": True,
            "email": {"enabled": False, "smtp_host": "127.0.0.1", "smtp_port": 25,
                      "use_tls": True, "user": "", "password": "", "from": "", "to": ""},
            "telegram": {"enabled": False},
            "webhook": {"enabled": False},
        },
    })
    r2 = owctl.send_digest()
check("disabled email -> sent:False", r2.get("sent") is False, str(r2))
check("disabled reason", r2.get("reason") == "email channel not configured", str(r2))

# (f) dry_run does not touch smtplib
import asyncio
smtp_touched = {"n": 0}
orig = smtplib.SMTP
def counting(*a, **kw):
    smtp_touched["n"] += 1
    return orig(*a, **kw)
fake_req = mock.MagicMock()
async def mock_json(): return {"dry_run": True}
fake_req.json = mock_json
with mock.patch("owctl.smtplib.SMTP", counting):
    r3 = asyncio.run(owctl.api_digest(fake_req))
check("dry_run does not call SMTP", smtp_touched["n"] == 0, f"called {smtp_touched['n']} times")
check("dry_run returns body", "gw-edge" in r3.get("body", ""), str(r3))
check("dry_run subject", "OpenWrt Fleet Digest" in r3.get("subject", ""), str(r3))

print(f"\n{ok}/{ok+fail} checks passed")
if fail:
    sys.exit(1)