#!/usr/bin/env python3
"""checks_push_key.py — push_ssh_key home-directory regression guard.

Contract (audit P1, MED): push_ssh_key wrote the public key to
/home/root/.ssh, but OpenWrt's root home is /root (per /etc/passwd), and any
non-root SSH user has its own home. The key landed in a directory dropbear
never consulted, so the follow-up key-only auth check failed on a real device.

The fix resolves the user's real home from $HOME (set by dropbear from
/etc/passwd) with a /root fallback. This check captures the exact command
push_ssh_key sends and asserts it targets $HOME//root, NOT the dead /home/root.
"""
import os
import sys
import tempfile

_tmp = tempfile.mkdtemp(prefix="owctl-pushkey-")
os.environ["OWCTL_DATA"] = os.path.join(_tmp, "data")
os.environ.setdefault("OWCTL_ALLOW_OPEN", "1")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import owctl  # noqa: E402

owctl.init_db()

PASS = FAIL = 0


def check(label, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {label}")
    else:
        FAIL += 1
        print(f"FAIL {label} :: {detail}")


dev = owctl.q("SELECT * FROM devices WHERE host='pushkey'")
if not dev:
    owctl.execute("INSERT INTO devices(name, host, access, ssh_user, ssh_password, added_at) "
                  "VALUES(?,?,?,?,?,?)", ("pushkey", "pushkey", "ssh", "root", "x", owctl.now()))
dev = owctl.q("SELECT * FROM devices WHERE host='pushkey'")[0]

# --- Capture the command push_ssh_key sends. Stub the SSH layer so it runs
# --- offline: _ssh_connect returns a dummy, _exec_capture records the cmd and
# --- reports success, ssh_test reports the key-only auth check passed.
captured = {}


class _DummyClient:
    def close(self):
        pass


def _fake_connect(d):
    return _DummyClient()


def _fake_exec(client, cmd, timeout=300):
    captured["cmd"] = cmd
    return b"", b"", 0


def _fake_ssh_test(d):
    return {"ok": True, "detail": "stubbed key auth ok"}


owctl._ssh_connect = _fake_connect
owctl._exec_capture = _fake_exec
owctl.ssh_test = _fake_ssh_test

r = owctl.push_ssh_key(dict(dev))
cmd = captured.get("cmd", "")

check("push_ssh_key reported success", r.get("ok") is True, str(r)[:120])
check("command targets the session's real home ($HOME)",
      "${HOME:-/root}" in cmd or "${HOME" in cmd, f"cmd={cmd}")
check("command uses /root fallback, not the dead /home/root",
      "/root" in cmd and "/home/root" not in cmd, f"cmd={cmd}")
check("authorized_keys written under $H/.ssh",
      "$H/.ssh/authorized_keys" in cmd, f"cmd={cmd}")
check("directory perms 700 + file perms 600 set",
      "chmod 700" in cmd and "chmod 600" in cmd, f"cmd={cmd}")

print(f"\n=== SUMMARY ===\n{PASS}/{PASS + FAIL} checks passed")
sys.exit(0 if FAIL == 0 else 1)
