#!/usr/bin/env python3
"""End-to-end test of owctl against a mock OpenWrt device (SSH + LuCI).

Stands up an in-process paramiko SSH server (password auth + real SFTP rooted
at a temp dir) and an HTTP server emulating LuCI (404 at /cgi-bin/luci/rpc,
JSON-RPC at /rpc). Then drives the REAL owctl code paths:
luci_gather, ssh_gather, ssh_test, push_ssh_key, do_backup, _exec_capture,
audit_status.

Run: .venv/bin/python test_e2e.py
"""
import base64
import json
import os
import socket
import sys
import tempfile
import threading
import time
import urllib.request

import paramiko
import paramiko.sftp_server as sftp_server
from paramiko.sftp import SFTP_EOF, SFTP_OK
from paramiko.sftp_attr import SFTPAttributes
from paramiko.sftp_handle import SFTPHandle
from paramiko.sftp_si import SFTPServerInterface

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import owctl  # noqa: E402

RESULTS = []
SERVER_KEY = None
ROOT = None


def check(name, cond, extra=""):
    RESULTS.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


GATHER_OUTPUT = """##release##
OpenWrt 23.05.4 (goldman) r24046-85e4097894
##model##
##date##
2026-09-26 09:30:00
##uptime##
86400
##load##
0.05 0.01 0.00
##mem##
MemTotal=511788 MemFree=200000
##disk##
287M used=45% free=120M
##clients##
7
##wan##
{"up":true,"ipv4-addr":["192.168.55.2"]}
##fw##
in=ACCEPT fwd=DROP out=ACCEPT
##dropbear##
pwauth=on port=22
##listeners##
22 80 443 23
##ntp##
true
##redirects##
0 web 8080
##upgradable##
base-files 23.05.4-1 23.05.5-1
luci 23.053.2-1 23.053.3-1
##end##
"""

MOCK_BACKUP = "# openwrt config export (mock)\nconfig system\n\toption hostname mock\n"


# ----------------------------------------------------------------- mock SFTP
class MockFile(SFTPHandle):
    def __init__(self, path, flags, root):
        super().__init__(flags)
        self.root = root
        full = os.path.join(root, path.lstrip("/"))
        if os.path.dirname(full):
            os.makedirs(os.path.dirname(full), exist_ok=True)
        mode = "rb"
        if flags & 1:  # O_WRONLY
            mode = "ab" if (flags & 512) else "wb"
        elif flags & 512:  # O_APPEND
            mode = "ab"
        self.f = open(full, mode)
        self.mode = mode
        self.full = full

    def read(self, offset, length):
        try:
            self.f.seek(offset)
            data = self.f.read(length)
        except OSError:
            return SFTP_EOF
        if not data:
            return SFTP_EOF
        return data

    def write(self, offset, data):
        if "b" in self.mode:
            self.f.seek(offset)
            self.f.write(data)
            self.f.flush()
            return SFTP_OK
        return SFTP_OK

    def stat(self):
        st = os.stat(self.full)
        a = SFTPAttributes()
        a.st_size = st.st_size
        a.st_mode = st.st_mode
        a.st_uid = st.st_uid
        a.st_gid = st.st_gid
        return a

    def chattr(self, attr):
        if attr._flags & attr.FLAG_PERMISSIONS:
            os.chmod(self.full, attr.st_mode)
        return SFTP_OK


class MockSFTP(SFTPServerInterface):
    def __init__(self, server):
        super().__init__(server)
        self.root = ROOT

    def _p(self, path):
        return os.path.join(self.root, path.lstrip("/"))

    def open(self, path, flags, attr):
        return MockFile(path, flags, self.root)

    def stat(self, path):
        try:
            st = os.stat(self._p(path))
        except OSError:
            return 2  # SFTP_NO_SUCH_FILE
        a = SFTPAttributes()
        a.st_size = st.st_size
        a.st_mode = st.st_mode
        a.st_uid = st.st_uid
        a.st_gid = st.st_gid
        return a

    def lstat(self, path):
        return self.stat(path)

    def mkdir(self, path, attr):
        try:
            os.makedirs(self._p(path), exist_ok=True)
            return 0  # SFTP_OK
        except OSError:
            return 2

    def rmdir(self, path):
        try:
            os.rmdir(self._p(path))
            return 0
        except OSError:
            return 2

    def remove(self, path):
        try:
            os.remove(self._p(path))
            return 0
        except OSError:
            return 2

    def rename(self, oldpath, newpath):
        try:
            os.rename(self._p(oldpath), self._p(newpath))
            return 0
        except OSError:
            return 2

    def chattr(self, path, attr):
        try:
            if attr._flags & attr.FLAG_PERMISSIONS:
                os.chmod(self._p(path), attr.st_mode)
            return 0
        except OSError:
            return 2


# ------------------------------------------------------------------ mock SSH
class MockSSHServer(paramiko.ServerInterface):
    def __init__(self):
        self.commands = []

    def check_auth_password(self, username, password):
        if username == "root" and password == "secret":
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_SUCCESSFUL  # emulates: our key is installed

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):
        cmd = command.decode(errors="replace") if isinstance(command, bytes) else str(command)
        self.commands.append(cmd)
        if "BACKUP_OK" in cmd:
            # emulate: uci export wrote the backup file; create it where SFTP can serve it
            import re as _re
            m = _re.search(r"> (\S+)", cmd)
            if m:
                target = os.path.join(ROOT, m.group(1).lstrip("/"))
                os.makedirs(os.path.dirname(target) or ROOT, exist_ok=True)
                with open(target, "w") as fh:
                    fh.write(MOCK_BACKUP)
            channel.sendall(b"BACKUP_OK\n")
        elif "echo x" in cmd:
            channel.sendall(b"x" * 200000)
        elif "/etc/openwrt_release" in cmd:
            channel.sendall(GATHER_OUTPUT.encode())
        else:
            channel.sendall(b"ok\n")
        channel.send_exit_status(0)
        # Signal EOF (not close) so the client can drain data + exit status.
        channel.shutdown_write()
        return True


def start_ssh_server(port):
    ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ss.bind(("127.0.0.1", port))
    ss.listen(10)
    ss.settimeout(1.0)

    def serve():
        while True:
            try:
                chan, _ = ss.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=serve_conn, args=(chan,), daemon=True).start()

    def serve_conn(chan):
        t = paramiko.Transport(chan)
        t.add_server_key(SERVER_KEY)
        t.start_server(server=MockSSHServer())
        t.set_subsystem_handler("sftp", sftp_server.SFTPServer, MockSFTP)
        while t.is_active():
            time.sleep(0.2)

    threading.Thread(target=serve, daemon=True).start()
    return ss


# ------------------------------------------------------------------ mock LuCI
class MockLuCI(threading.Thread):
    def __init__(self, port):
        super().__init__(daemon=True)
        self.port = port

    def run(self):
        import http.server

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, code, obj):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                req = json.loads(self.rfile.read(length) or b"{}")
                if self.path != "/rpc":
                    return self._reply(404, {"error": "not found"})
                auth = self.headers.get("Authorization", "")
                if auth != "Basic " + base64.b64encode(b"root:luapass").decode():
                    return self._reply(401, {"error": "auth required"})
                obj, method = req["params"][2], req["params"][1]
                payloads = {
                    "luci.sys.sysinfo": {
                        "firmware": "23.05.4", "model": "Mock Router",
                        "hostname": "mock", "board": "Mock Co. Mock Board",
                    },
                    "luci.sys.status": {
                        "uptime": 86400, "load": "0.05 0.01 0.00",
                        "mem": {"total": 511788, "free": 200000},
                        "net": {"wan": {"up": True, "ipv4": [{"address": "192.168.55.2"}]}},
                    },
                    "luci.devices": {"clients": 7, "devices": {}},
                    "luci.sys.sysupgrade": {"available": True, "latest_version": "24.10.0"},
                    "luci.opkg.upgradable": [
                        {"pkg": "base-files", "installed": "23.05.4-1", "available": "23.05.5-1"},
                    ],
                    "luci.config.get": (
                        {"firewall": {
                            "defaults": [{"input": "ACCEPT", "forward": "DROP", "output": "ACCEPT"}],
                            "redirect": [{"name": "web", "dest_port": "8080"}],
                        }} if obj == "firewall" else {}
                    ),
                }.get(method)
                if payloads is None:
                    return self._reply(200, {"code": 500, "error": "unknown method"})
                return self._reply(200, {"code": 0, "payload": payloads})

        import http.server as _hs
        srv = _hs.ThreadingHTTPServer(("127.0.0.1", self.port), H)
        srv.serve_forever()


def wait_port(port, tries=30):
    for _ in range(tries):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except Exception:
            time.sleep(0.2)
    return False


def main():
    global SERVER_KEY, ROOT
    scratch = tempfile.mkdtemp(prefix="owctl-test-")
    ROOT = scratch
    SERVER_KEY = paramiko.RSAKey.generate(2048)
    SERVER_KEY.write_private_key_file(os.path.join(scratch, "testkey"))

    # point owctl at the scratch dir (server key + backups)
    owctl.DATA_DIR = scratch
    owctl.BACKUP_DIR = scratch

    ssh_port, luci_port = 22222, 8091
    start_ssh_server(ssh_port)
    MockLuCI(luci_port).start()
    assert wait_port(ssh_port), "mock SSH port never came up"
    assert wait_port(luci_port), "mock LuCI port never came up"

    # ---------------- LuCI path (your 404) ----------------
    dev = {"host": "127.0.0.1", "name": "mock", "access": "luci",
           "luci_user": "root", "luci_pass": "luapass", "luci_port": luci_port}
    try:
        st = owctl.luci_gather(dev)
        check("luci: firmware parsed", st.get("firmware") == "OpenWrt 23.05.4", str(st)[:200])
        check("luci: wan_up true", st.get("wan_up") is True)
        check("luci: wan_ip", st.get("wan_ip") == "192.168.55.2")
        check("luci: clients", st.get("clients") == 7)
        check("luci: upgradable", st.get("upgradable", [{}])[0].get("pkg") == "base-files")
        check("luci: fw_in ACCEPT", st.get("fw_in") == "ACCEPT")
        check("luci: sysupgrade_available", st.get("sysupgrade_available") is True)
        check("luci: redirects", st.get("redirects", [{}])[0].get("name") == "web")
    except Exception as e:
        check("luci: gather works", False, repr(e))

    # prove the old endpoint 404s on the same server (root cause confirmed)
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{luci_port}/cgi-bin/luci/rpc", data=b"{}",
            headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=3)
        check("luci: old /cgi-bin/luci/rpc 404s (root cause)", False, "no 404")
    except urllib.error.HTTPError as e:
        check("luci: old /cgi-bin/luci/rpc 404s (root cause)", e.code == 404, str(e.code))
    except Exception as e:
        check("luci: old /cgi-bin/luci/rpc 404s (root cause)", False, repr(e))

    # LuCI auth failure -> clear error
    bad = owctl.luci_test(dict(dev, luci_pass="wrong"))
    check("luci: bad creds -> ok=False + detail", bad.get("ok") is False and bad.get("detail"), str(bad)[:150])

    # ---------------- SSH path (your 502) ----------------
    dev_ssh = {"host": "127.0.0.1", "name": "mock", "access": "ssh",
               "ssh_port": ssh_port, "ssh_user": "root", "ssh_password": "secret"}
    st2 = None
    try:
        st2 = owctl.ssh_gather(dev_ssh)
        check("ssh: firmware", "OpenWrt 23.05.4" in st2.get("firmware", ""))
        check("ssh: telnet_on (23 in listeners)", st2.get("telnet_on") is True)
        check("ssh: clients", st2.get("clients") == 7)
        check("ssh: upgradable count", len(st2.get("upgradable", [])) == 2)
        check("ssh: redirects", st2.get("redirects", [{}])[0].get("name") == "web")
        check("ssh: fw_in", st2.get("fw_in") == "ACCEPT")
        check("ssh: wan_up", st2.get("wan_up") is True)
        check("ssh: uptime", st2.get("uptime_s") == 86400)
    except Exception as e:
        check("ssh: gather works", False, repr(e))

    good = owctl.ssh_test(dev_ssh)
    check("ssh: test ok", good.get("ok") is True, str(good)[:150])
    bad = owctl.ssh_test(dict(dev_ssh, ssh_password="wrong"))
    check("ssh: bad pw -> ok=False", bad.get("ok") is False, str(bad)[:150])
    check("ssh: bad pw -> clear message", "authentication failed" in bad.get("detail", "").lower(),
          bad.get("detail", ""))
    unreach = owctl.ssh_test({"host": "127.0.0.1", "name": "m", "access": "ssh",
                              "ssh_port": 22299, "ssh_user": "root", "ssh_password": "x"})
    check("ssh: unreachable -> clear message",
          ("timed out" in unreach.get("detail", "").lower()
           or "refused" in unreach.get("detail", "").lower()
           or "no route" in unreach.get("detail", "").lower()
           or "check the address" in unreach.get("detail", "").lower()), unreach.get("detail", ""))

    # ---------------- audit rules ----------------
    f = {x["rule_id"]: x["severity"] for x in owctl.audit_status(st2 or {})}
    check("audit: telnet HIGH", f.get("telnet") == "HIGH")
    check("audit: ssh_password_auth MEDIUM (pwauth=on)", f.get("ssh_password_auth") == "MEDIUM")
    check("audit: fw_input_accept HIGH", f.get("fw_input_accept") == "HIGH")
    check("audit: outdated_packages MEDIUM", f.get("outdated_packages") == "MEDIUM")
    check("audit: no fw_forward (fwd=DROP)", "fw_forward_accept" not in f)

    # ---------------- push_ssh_key ----------------
    import sqlite3
    conn = sqlite3.connect(owctl.DB_PATH)
    conn.execute("INSERT OR REPLACE INTO devices(id,name,host,access) VALUES(999,'mock','127.0.0.1','ssh')")
    conn.commit()
    conn.close()
    try:
        r = owctl.push_ssh_key(dict(dev_ssh, id=999))
        check("push-key: public key present", "public_key" in r and "ssh-rsa" in r["public_key"], str(r)[:150])
        check("push-key: key-only auth verified", r.get("ok") is True, str(r)[:150])
        keypath = os.path.join(scratch, "ssh_key")
        check("push-key: server key generated", os.path.exists(keypath))
    except Exception as e:
        check("push-key", False, repr(e))

    # ---------------- backup ----------------
    try:
        local = owctl.do_backup(dict(dev_ssh, id=999))
        content = open(local).read()
        check("backup: file created with config", "hostname mock" in content, local)
        rows = owctl.q("SELECT * FROM backups WHERE device_id=999")
        check("backup: recorded in DB", len(rows) >= 1)
    except Exception as e:
        check("backup", False, repr(e))

    # ---------------- _exec_capture no deadlock ----------------
    try:
        c = owctl._ssh_connect(dev_ssh)
        big, err, status = owctl._exec_capture(c, "echo x" * 1, timeout=30)
        # the mock echoes exactly 200000 x's for any 'echo x' command
        check("exec_capture: 200KB stdout, no deadlock", len(big) >= 200000 and status == 0,
              f"len={len(big)} status={status}")
        c.close()
    except Exception as e:
        check("exec_capture", False, repr(e))

    print("\n=== SUMMARY ===")
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print(f"{passed}/{len(RESULTS)} checks passed")
    if passed != len(RESULTS):
        print("FAILURES:")
        for n, ok, extra in RESULTS:
            if not ok:
                print(" -", n, extra)
        sys.exit(1)
    print("ALL E2E CHECKS PASSED")


if __name__ == "__main__":
    main()
