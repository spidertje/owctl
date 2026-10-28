#!/usr/bin/env python3
"""checks_ssh_hostkey.py — SSH trust-on-first-use / host-key MITM guard.

Contract (audit P0): _ssh_connect used to call paramiko.AutoAddPolicy(), which
silently accepted ANY host key — a MITM presenting a fabricated key was trusted.
After the fix, the first key seen for a host is pinned to <DATA_DIR>/ssh_known_hosts
and every later connection is verified against it; a changed/rotated key (or MITM)
is rejected with a host-key mismatch, not silently accepted.

Host-key verification happens at the transport layer, BEFORE auth, so this test
does not need the mock to accept a password:
  - connect with key A  -> host key ACCEPTED (the only failure, if any, is auth)
                           and the key is pinned to disk.
  - connect with key B  -> host key REJECTED with "does not match the pinned key"
                           (proves a replaced key is not silently trusted).
  - connect with key A  -> host key ACCEPTED again (pin is per-key, not "reject all").

Self-contained. Exits non-zero on failure. Run: .venv/bin/python checks_ssh_hostkey.py
"""
import os
os.environ["OWCTL_DATA"] = "/tmp/owctl-sshhk-" + str(os.getpid())
os.makedirs(os.environ["OWCTL_DATA"], exist_ok=True)
os.environ.pop("OWCTL_SSH_TRUST_ANY", None)  # ensure the real pinning path runs
import importlib, socket, sys, threading, time
import paramiko
import owctl
importlib.reload(owctl)

passed = failed = 0
def check(name, cond, extra=""):
    global passed, failed
    if cond: passed += 1; print("PASS", name)
    else: failed += 1; print("FAIL", name, (f"[{extra}]" if extra else ""))

PORT = 22311
pinfile = os.path.join(os.environ["OWCTL_DATA"], "ssh_known_hosts")
if os.path.exists(pinfile):
    os.remove(pinfile)

class Server:
    def __init__(self, hostkey):
        self._key = hostkey
        self.ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ss.bind(("127.0.0.1", PORT)); self.ss.listen(4); self.ss.settimeout(0.4)
        self._stop = False
        threading.Thread(target=self._loop, daemon=True).start()
    def _loop(self):
        while not self._stop:
            try:
                chan, _ = self.ss.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._conn, args=(chan,), daemon=True).start()
    def _conn(self, c):
        try:
            t = paramiko.Transport(c)
            t.add_server_key(self._key)
            t.start_server(server=paramiko.ServerInterface())
            while t.is_active() and not self._stop:
                time.sleep(0.1)
            t.close()
        except Exception:
            pass
    def stop(self):
        self._stop = True
        try:
            self.ss.close()
        except OSError:
            pass

def make_server(hostkey):
    return Server(hostkey)

def wait_port(port, tries=40):
    for _ in range(tries):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close(); return True
        except Exception:
            time.sleep(0.1)
    return False

def try_connect():
    dev = {"host": "127.0.0.1", "name": "hk", "access": "ssh",
           "ssh_port": PORT, "ssh_user": "root", "ssh_password": "x"}
    try:
        c = owctl._ssh_connect(dev)
        c.close()
        return "connected"
    except Exception as e:
        return "ERR: " + str(e)

def key_accepted(msg):
    # host-key ACCEPTED iff the failure (if any) is NOT a key mismatch
    return ("does not match the pinned key" not in msg)

def wait_port_free(port, tries=40):
    for _ in range(tries):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
        except Exception:
            return True
        time.sleep(0.1)
    return False

keyA = paramiko.RSAKey.generate(2048)
keyB = paramiko.RSAKey.generate(2048)

# --- 1. first connect to key A -> host key accepted AND pinned ---
s1 = make_server(keyA)
assert wait_port(PORT), "server A never came up"
m1 = try_connect()
check("connect #1: key A accepted (not a key mismatch)", key_accepted(m1), m1[:160])
check("key A pinned to disk", os.path.exists(pinfile))
pin = open(pinfile).read() if os.path.exists(pinfile) else ""
check("pin references 127.0.0.1:22311", ("127.0.0.1" in pin) and (":22311" in pin), pin[:80])
s1.stop(); wait_port_free(PORT)

# --- 2. SAME host:port now presents key B -> host key REJECTED ---
s2 = make_server(keyB)
assert wait_port(PORT), "server B never came up"
m2 = try_connect()
check("connect #2: key B REJECTED", ("does not match the pinned key" in m2), m2[:160])
check("rejection names the pin file", ("ssh_known_hosts" in m2), m2[:160])
s2.stop(); wait_port_free(PORT)

# --- 3. key A is STILL accepted (pin is per-key) ---
s3 = make_server(keyA)
assert wait_port(PORT), "server A2 never came up"
m3 = try_connect()
check("connect #3: key A still accepted after pin", key_accepted(m3), m3[:160])
s3.stop()

print(f"\n=== SUMMARY ===\n{passed}/{passed+failed} checks passed")
print("ALL SSH-HOSTKEY CHECKS PASSED" if failed == 0 else "SOME CHECKS FAILED")
os.system(f"rm -rf {os.environ['OWCTL_DATA']}")
sys.exit(1 if failed else 0)
