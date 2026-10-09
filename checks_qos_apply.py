#!/usr/bin/env python3
"""checks_qos_apply.py — tests for QoS + firewall apply functions (step 3).

Drives the REAL owctl apply code paths against an in-process paramiko SSH
server (password auth, key accepted, records every executed command). Verifies:
the exact uci command sequence (set -> commit -> restart), install-when-missing,
validation (proto/zone/port), error propagation on non-zero exit, and the
SSH-required guard.

Run: .venv/bin/python checks_qos_apply.py
"""
import os
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

tmp = tempfile.mkdtemp()
os.environ["OWCTL_DATA"] = tmp

import paramiko  # noqa: E402
import owctl  # noqa: E402
from fastapi import HTTPException  # noqa: E402

CHECKS = []


def check(name, cond, extra=""):
    CHECKS.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


SERVER_KEY = None
COMMANDS = []


class MockSSHServer(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):
        cmd = command.decode(errors="replace") if isinstance(command, bytes) else str(command)
        COMMANDS.append(cmd)
        if "FAILSQM" in cmd or "FAILFW" in cmd:
            channel.sendall(b"boom\n")
            channel.send_exit_status(1)
        else:
            channel.sendall(b"ok\n")
            channel.send_exit_status(0)
        channel.shutdown_write()
        return True


def start_ssh_server(port):
    ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ss.bind(("127.0.0.1", port))
    ss.listen(50)
    ss.settimeout(3600)  # long-lived accept loop for the test's duration

    def serve():
        while True:
            try:
                chan, _ = ss.accept()
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                break
            threading.Thread(target=serve_conn, args=(chan,), daemon=True).start()

    def serve_conn(chan):
        t = paramiko.Transport(chan)
        t.add_server_key(SERVER_KEY)
        t.start_server(server=MockSSHServer())
        while t.is_active():
            time.sleep(0.2)

    threading.Thread(target=serve, daemon=True).start()
    return ss


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_port(port, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def main():
    global SERVER_KEY
    owctl.init_db()
    SERVER_KEY = paramiko.RSAKey.generate(2048)
    keypath = os.path.join(tmp, "testkey")
    SERVER_KEY.write_private_key_file(keypath)

    port = free_port()
    start_ssh_server(port)
    assert wait_port(port, 10), "mock SSH port never came up"

    dev = {"id": 1, "name": "r1", "host": "127.0.0.1", "access": "ssh",
           "ssh_port": port, "ssh_user": "root", "key_path": keypath, "ssh_password": None}
    dev_luci = dict(dev, access="luci", luci_password="x")

    def run(fn, *a, **kw):
        """Reset command log, run fn, return (result, commands)."""
        COMMANDS.clear()
        try:
            r = fn(*a, **kw)
            return r, list(COMMANDS), None
        except Exception as e:
            return None, list(COMMANDS), e

    def last_cmd():
        return COMMANDS[-1] if COMMANDS else ""

    def has(fragment):
        return any(fragment in c for c in COMMANDS)

    # ── ensure_pkg ────────────────────────────────────────────────────────
    r, cmds, e = run(owctl.ensure_pkg, dev, "luci-app-sqm")
    check("ensure_pkg: ok", r == "installed" and e is None, repr(e))
    check("ensure_pkg: opkg update first", "opkg update" in last_cmd(), last_cmd()[:80])
    check("ensure_pkg: install -y", "opkg install -y luci-app-sqm" in last_cmd(), last_cmd()[:80])

    # ── do_qos: happy path ────────────────────────────────────────────────
    r, cmds, e = run(owctl.do_qos, dev, {"enabled": True, "interface": "wan",
                                         "download_kbps": 100000, "upload_kbps": 20000,
                                         "qdisc": "fq_codel", "ecn": False})
    check("qos: no exception", e is None, repr(e))
    check("qos: sets interface", "uci set sqm.wan.interface='wan'" in last_cmd(), last_cmd()[:120])
    check("qos: sets download", "uci set sqm.wan.download='100000'" in last_cmd(), "")
    check("qos: sets upload", "uci set sqm.wan.upload='20000'" in last_cmd(), "")
    check("qos: enabled=1", "uci set sqm.wan.enabled=1" in last_cmd(), "")
    check("qos: fq_codel selected", "uci set sqm.wan.fq_codel=1" in last_cmd(), "")
    check("qos: ecn=0", "uci set sqm.wan.ecn=0" in last_cmd(), "")
    check("qos: cake cleared", "uci set sqm.wan.cake=0" in last_cmd(), "")
    check("qos: commits sqm", "uci commit sqm" in last_cmd(), "")
    check("qos: restarts service", "sqm restart" in last_cmd(), "")
    order = [last_cmd().find("uci set"), last_cmd().find("uci commit sqm"),
             last_cmd().find("sqm restart")]
    check("qos: set before commit before restart", all(x >= 0 for x in order) and order[0] < order[1] < order[2],
          str(order))

    # ── do_qos: disabled ──────────────────────────────────────────────────
    r, cmds, e = run(owctl.do_qos, dev, {"enabled": False, "interface": "wan",
                                         "download_kbps": 0, "upload_kbps": 0,
                                         "qdisc": None, "ecn": False})
    check("qos off: enabled=0", "uci set sqm.wan.enabled=0" in last_cmd(), last_cmd()[:120])
    check("qos off: still restarts", "sqm restart" in last_cmd(), "")

    # ── do_qos: install_if_missing ────────────────────────────────────────
    r, cmds, e = run(owctl.do_qos, dev, {"enabled": True, "interface": "wan",
                                         "download_kbps": 1000, "upload_kbps": 1000,
                                         "qdisc": "fq_codel", "ecn": False},
                     install_if_missing=True)
    check("qos install: pkg installed", any("opkg install -y luci-app-sqm" in c for c in cmds), str(cmds))
    check("qos install: then uci", has("uci set sqm.wan.interface='wan'"), "")

    # ── do_qos: failure propagates ────────────────────────────────────────
    # point device host at a marker: use a separate port server is overkill —
    # instead simulate by failing via interface name injection is unsafe.
    # Use a device whose exec will hit the FAILSQM branch:
    dev_fail = dict(dev, name="fail")
    # temporarily monkeypatch the interface so the command contains FAILSQM
    r, cmds, e = run(owctl.do_qos, dev, {"enabled": True, "interface": "FAILSQM",
                                         "download_kbps": 1, "upload_kbps": 1,
                                         "qdisc": None, "ecn": False})
    check("qos fail: raises RuntimeError", isinstance(e, RuntimeError), repr(e))
    check("qos fail: message has exit code", e is not None and "exit" in str(e), str(e))

    # ── guard: luci device rejected ───────────────────────────────────────
    r, cmds, e = run(owctl.do_qos, dev_luci, {"enabled": True, "interface": "wan",
                                              "download_kbps": 1, "upload_kbps": 1,
                                              "qdisc": None, "ecn": False})
    check("qos guard: luci -> 400", isinstance(e, HTTPException) and e.status_code == 400, repr(e))

    # ── do_fw_forward: new rule ───────────────────────────────────────────
    rule = {"name": "cam", "proto": "tcp", "src_dport": 8080,
            "dest_ip": "192.168.1.50", "dest_port": 80}
    r, cmds, e = run(owctl.do_fw_forward, dev, rule)
    check("fw fwd: ok", e is None, repr(e))
    check("fw fwd: section declared (slug id)", "uci set firewall.cam=redirect" in last_cmd(), last_cmd()[:120])
    check("fw fwd: name", "name='cam'" in last_cmd(), "")
    check("fw fwd: proto", "proto='tcp'" in last_cmd(), "")
    check("fw fwd: src_dport", "src_dport='8080'" in last_cmd(), "")
    check("fw fwd: dest_ip", "dest_ip='192.168.1.50'" in last_cmd(), "")
    check("fw fwd: dest_port", "dest_port='80'" in last_cmd(), "")
    check("fw fwd: commit", "uci commit firewall" in last_cmd(), "")
    check("fw fwd: fw4 restart", "fw4 restart" in last_cmd(), "")
    order = [last_cmd().find("uci set firewall."), last_cmd().find("uci commit firewall"),
             last_cmd().find("fw4 restart")]
    check("fw fwd: set before commit before restart", all(x >= 0 for x in order) and order[0] < order[1] < order[2], str(order))

    # ── do_fw_forward: tcpudp + default dest_port ────────────────────────
    rule2 = {"name": "camu", "proto": "tcpudp", "src_dport": 53, "dest_ip": "192.168.1.1", "dest_port": None}
    r, cmds, e = run(owctl.do_fw_forward, dev, rule2)
    check("fw fwd tcpudp: proto list", "proto='tcp udp'" in last_cmd(), last_cmd()[:200])
    check("fw fwd tcpudp: default dest_port", "dest_port='53'" in last_cmd(), "")

    # ── do_fw_forward: validation ─────────────────────────────────────────
    r, cmds, e = run(owctl.do_fw_forward, dev, {"name": "bad", "proto": "icmp",
                                                "src_dport": 80, "dest_ip": "10.0.0.1", "dest_port": 80})
    check("fw fwd: bad proto rejected", isinstance(e, HTTPException) and e.status_code == 400, repr(e))
    r, cmds, e = run(owctl.do_fw_forward, dev, {"name": "bad", "proto": "tcp",
                                                "src_dport": 99999, "dest_ip": "10.0.0.1", "dest_port": 80})
    check("fw fwd: bad port rejected", isinstance(e, HTTPException) and e.status_code == 400, repr(e))
    r, cmds, e = run(owctl.do_fw_forward, dev_luci, rule)
    check("fw fwd: luci -> 400", isinstance(e, HTTPException) and e.status_code == 400, repr(e))

    # ── do_fw_rule: inter-zone ────────────────────────────────────────────
    zr = {"name": "allow cam", "src": "lan", "dest": "wan", "target": "ACCEPT"}
    r, cmds, e = run(owctl.do_fw_rule, dev, zr)
    check("fw rule: ok", e is None, repr(e))
    check("fw rule: section declared (slug id)", "uci set firewall.allow_cam=rule" in last_cmd(), last_cmd()[:120])
    check("fw rule: src", "src='lan'" in last_cmd(), "")
    check("fw rule: dest", "dest='wan'" in last_cmd(), "")
    check("fw rule: target", "target='ACCEPT'" in last_cmd(), "")
    check("fw rule: fw4 restart", "fw4 restart" in last_cmd(), "")

    # ── do_zone_policy ────────────────────────────────────────────────────
    r, cmds, e = run(owctl.do_zone_policy, dev, "guest", {"forward": "REJECT"})
    check("zone: ok", e is None, repr(e))
    check("zone: sets forward", "uci set firewall.guest.forward='REJECT'" in last_cmd(), last_cmd()[:160])
    check("zone: commit + restart", "uci commit firewall" in last_cmd() and "fw4 restart" in last_cmd(), "")

    # ── delete_fw_rule / delete_fw_forward ────────────────────────────────
    r, cmds, e = run(owctl.delete_fw_rule, dev, "allow cam")
    check("del rule: ok", e is None, repr(e))
    check("del rule: uci delete by slug", "uci delete firewall.allow_cam" in last_cmd(), last_cmd()[:160])
    check("del rule: commit + restart", "uci commit firewall" in last_cmd() and "fw4 restart" in last_cmd(), "")

    r, cmds, e = run(owctl.delete_fw_forward, dev, "cam")
    check("del fwd: ok", e is None, repr(e))
    check("del fwd: uci delete by name", "uci delete" in last_cmd() and "cam" in last_cmd(), last_cmd()[:160])

    # ── action logging ────────────────────────────────────────────────────
    owctl.execute("SELECT 1")
    rows = owctl.q("SELECT action FROM owctl_actions ORDER BY id DESC LIMIT 3")
    actions = [r["action"] for r in rows]
    check("actions: logged", any(a in ("qos", "firewall") for a in actions), str(actions))

    print(f"\n=== SUMMARY ===\n{sum(1 for _, ok, _ in CHECKS if ok)}/{len(CHECKS)} checks passed")
    failed = [n for n, ok, _ in CHECKS if not ok]
    if failed:
        print("FAILURES:")
        for n in failed:
            print(" -", n)
        sys.exit(1)
    print("ALL QOS/FIREWALL APPLY CHECKS PASSED")


if __name__ == "__main__":
    main()
