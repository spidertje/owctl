#!/usr/bin/env python3
"""checks_guest_wifi_injection.py — guest-WiFi shell-injection regression guard.

Contract (audit P0): the SSID/password are interpolated into a shell script
run on the device. Before the fix, a `'` in the SSID or password could break
out of the `uci set ... .ssid='...'` line and execute arbitrary commands on
the device. After the fix, user-controlled values are single-quoted (and the
section name slug-ified), so embedded metacharacters are inert.

Proof, not just shape: we capture the exact command do_guest_wifi() emits and
execute it under a real `sh -c` with `uci`/`wifi` stubbed to no-ops. An
injected `$(touch <marker>)` in the SSID/password must NOT create the marker.

Self-contained: throwaway OWCTL_DATA, reloads the app. Exits non-zero on failure.
Run: .venv/bin/python checks_guest_wifi_injection.py
"""
import os
os.environ["OWCTL_DATA"] = "/tmp/owctl-gwifi-inj-" + str(os.getpid())
os.makedirs(os.environ["OWCTL_DATA"], exist_ok=True)
os.environ["OWCTL_ALLOW_OPEN"] = "1"
import importlib, sys, subprocess, tempfile, textwrap
import owctl
importlib.reload(owctl)

passed = failed = 0
def check(name, cond, extra=""):
    global passed, failed
    if cond: passed += 1; print("PASS", name)
    else: failed += 1; print("FAIL", name, (f"[{extra}]" if extra else ""))

# Fake SSH client that captures every exec_command, and answers the
# "does this device have wireless?" probe with a wifi-iface line.
CAP = {"cmds": []}
class _Out:
    def __init__(self, data):
        self._d = data
        self.channel = _Chan()
    def read(self, *a):
        return self._d
class _Chan:
    def recv_exit_status(self):
        return 0
class _Fake:
    def close(self):
        pass
    def exec_command(self, cmd, timeout=300):
        CAP["cmds"].append(cmd)
        # the wireless-capability probe -> say yes; the uci script -> empty
        return (None, _Out(b"wireless.guest_x=wifi-iface\n"), _Out(b""))

owctl._ssh_connect = lambda dev: _Fake()
dev = {"id": 1, "name": "gwbox", "host": "192.0.2.1", "access": "ssh"}

def build(ssid, password, vlan=None):
    CAP["cmds"].clear()
    owctl.do_guest_wifi(dev, ssid, password, vlan_id=vlan, apply=False)
    return CAP["cmds"][-1]  # the last emitted command is the uci script

def run_under_sh(cmd):
    """Execute the emitted uci script under a real `sh -c`, with `uci`/`wifi`
    stubbed: `uci` logs its full argv, `wifi` no-ops. Returns (exit, err, log).
    A hostile `$(touch <marker>)` in the SSID/password would create the marker
    file (== BAD) if it were executed; if it is safely quoted, it lands in the
    uci argv as literal text and no file is created."""
    bindir = tempfile.mkdtemp(prefix="gwstub-")
    logdir = tempfile.mkdtemp(prefix="gwlog-")
    logfile = os.path.join(logdir, "uci.log")
    with open(os.path.join(bindir, "uci"), "w") as f:
        f.write("#!/bin/sh\nprintf '%s\\n' \"$@\" >> " + logfile + "\nexit 0\n")
    with open(os.path.join(bindir, "wifi"), "w") as f:
        f.write("#!/bin/sh\nexit 0\n")
    for name in ("uci", "wifi"):
        os.chmod(os.path.join(bindir, name), 0o755)
    env = dict(os.environ, PATH=bindir + ":" + os.environ.get("PATH", ""))
    r = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True, env=env, timeout=20)
    log = open(logfile).read() if os.path.exists(logfile) else ""
    return r.returncode, (r.stderr or r.stdout).strip()[:300], log

def syntax_ok(cmd):
    """Properly syntax-check a command string (dash reads -n from a file)."""
    f = tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False)
    f.write(cmd); f.close()
    r = subprocess.run(["sh", "-n", f.name], capture_output=True, text=True, timeout=20)
    os.unlink(f.name)
    return r.returncode, (r.stderr or r.stdout).strip()[:300]

# --- 1. benign SSID/password still produce a valid, quoted uci script ---
cmd = build("Guest Net", "correct horse", vlan=2)
check("emits wifi-iface section", "uci set wireless.guest_guest_net=wifi-iface" in cmd, cmd[:160])
check("ssid is single-quoted", "ssid='Guest Net'" in cmd, cmd[:160])
check("key is single-quoted", "key='correct horse'" in cmd, cmd[:160])
check("vlan network wired", "network='vlan_2'" in cmd, cmd[:160])
check("commits wireless", "uci commit wireless" in cmd)

# --- 2. the injection: payload must be inert under a real shell ---
marker1 = "gw_pwn_ssid_" + str(os.getpid())
marker2 = "gw_pwn_pw_" + str(os.getpid())
hostile_ssid = "EVIL'$(touch /tmp/" + marker1 + ")`touch /tmp/" + marker1 + "`"
hostile_pw = "p4ss'$(touch /tmp/" + marker2 + ")`touch /tmp/" + marker2 + "`;"
cmd2 = build(hostile_ssid, hostile_pw)

# syntax must remain valid even with metacharacters in the values
rc, err = syntax_ok(cmd2)
check("hostile command is syntactically valid sh", rc == 0, err[:200])

# run it for real with a logging `uci`: the payload must NOT execute, and the
# hostile text must survive into the uci argv as data (proof it was quoted).
rc2, err2, log = run_under_sh(cmd2)
check("hostile script executes cleanly (uci stubs)", rc2 == 0, err2[:200])
check("SSID injection payload NOT executed (no marker)", not os.path.exists("/tmp/" + marker1))
check("password injection payload NOT executed (no marker)", not os.path.exists("/tmp/" + marker2))
check("SSID payload passed to uci as data (quoted)", ("touch /tmp/" + marker1) in log)
check("password payload passed to uci as data (quoted)", ("touch /tmp/" + marker2) in log)

# even with the hostile value, the script must still be well-formed uci (the
# ssid/key fields present and the section name slug-ified, not broken)
check("ssid field still set", ".ssid=" in cmd2)
check("key field still set", ".key=" in cmd2)
check("section name is slug-safe", "uci set wireless.guest_" in cmd2)

print(f"\n=== SUMMARY ===\n{passed}/{passed+failed} checks passed")
print("ALL GUEST-WIFI INJECTION CHECKS PASSED" if failed == 0 else "SOME CHECKS FAILED")
os.system(f"rm -rf {os.environ['OWCTL_DATA']}")
sys.exit(1 if failed else 0)
