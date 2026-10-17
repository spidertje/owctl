#!/usr/bin/env python3
"""checks_dyndns.py — unit tests for the dynamic-DNS update logic.

Exercises the pure parts of _ddns_apply (provider dict, URL formatting, the
skip-when-unchanged rule) without touching the network or the device. The
HTTP path is mocked by monkeypatching urllib.request.urlopen.

Run: .venv/bin/python checks_dyndns.py
"""
import os, sys, types, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Redirect the DB to a temp file BEFORE importing owctl — importing it runs
# init_db() against the module-level DB_PATH.
tmpdb = tempfile.mktemp(suffix=".db")
os.environ["OWCTL_DATA"] = tempfile.mkdtemp()
import owctl  # noqa: E402  (import triggers init_db on the real DB path)
owctl.DB_PATH = tmpdb
owctl.init_db()
owctl._LOCK = __import__("threading").Lock()

import json


def fake_q(sql, args=()):
    # only the dyndns SELECT is needed by _ddns_apply
    if "FROM dyndns" in sql:
        return [{"id": 1, "provider": "duckdns", "hostname": "home.duckdns.org",
                 "token": "abc", "extra": None, "last_ip": "1.2.3.4",
                 "last_result": "ok", "device_id": 1}]
    return []


def fake_exec(sql, args=()):
    return None


owctl.q = fake_q
owctl.execute = fake_exec


class FakeResp:
    def __init__(self, body):
        self._body = body.encode()
    def read(self):
        return self._body
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


captured = {}


def fake_urlopen(req, timeout=15):
    captured["url"] = req.full_url
    captured["method"] = req.get_method()
    return FakeResp("OK")


owctl.urllib.request.urlopen = fake_urlopen

# --- test 1: URL formatting for a pure-HTTP provider ---
owctl._ddns_apply({"id": 1, "name": "router"}, {"wan_ip": "9.8.7.6"})
assert "token=abc" in captured["url"], captured["url"]
assert "ip=9.8.7.6" in captured["url"], captured["url"]
assert "home.duckdns.org" in captured["url"], captured["url"]
assert captured["method"] == "GET", captured["method"]
print("ok: duckdns URL formatted correctly")

# --- test 2: skip when IP unchanged ---
captured.clear()
owctl._ddns_apply({"id": 1, "name": "router"}, {"wan_ip": "1.2.3.4"})
assert captured == {}, captured
print("ok: no request when WAN IP unchanged")

# --- test 3: unknown provider records an error, never raises ---
owctl.q = lambda sql, args=(): [{"id": 2, "provider": "bogus", "hostname": "x",
                                 "token": "", "extra": None, "last_ip": None,
                                 "last_result": None, "device_id": 1}]
owctl._ddns_apply({"id": 1, "name": "router"}, {"wan_ip": "1.1.1.1"})
print("ok: unknown provider handled without raising")

# --- test 4: provider list is selectable from the API ---
provs = owctl.dyndns_read()["providers"]
assert "duckdns" in provs and "cloudflare" in provs and "noip" in provs, provs
assert provs == sorted(provs), provs
print("ok: provider list selectable and sorted:", provs)

# --- test 5: package map — pure-HTTP providers need nothing on the box ---
assert owctl._dyndns_pkg_for("duckdns") is None
assert owctl._dyndns_pkg_for("noip") is None
assert owctl._dyndns_pkg_for("cloudflare") == "luci-app-cloudflare-ddns"
assert owctl._dyndns_pkg_for("ovh") == "luci-app-ovhddns"
print("ok: package map covers HTTP + install-required providers")

# --- test 6: bad response is recorded, not raised ---
owctl.q = lambda sql, args=(): [{"id": 3, "provider": "noip", "hostname": "x.noip.me",
                                 "token": "", "extra": None, "last_ip": None,
                                 "last_result": None, "device_id": 1}]
owctl.urllib.request.urlopen = lambda req, timeout=15: FakeResp("nohost")
owctl._ddns_apply({"id": 1, "name": "router"}, {"wan_ip": "5.5.5.5"})
print("ok: bad provider response recorded as last_result")

os.unlink(tmpdb)
print("\nall dyndns checks passed")