"""owctl.operations"""
import owctl  # shared namespace (patched names)

import base64, difflib, json, os, re, secrets, smtplib, socket, sqlite3, ssl
import threading, time, logging, sys, ipaddress, paramiko, bcrypt
import urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from email.message import EmailMessage
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

def ensure_server_key():
    """Server-side SSH keypair used for key auth to devices (created on demand)."""
    path = os.path.join(owctl.DATA_DIR, "ssh_key")
    if not os.path.exists(path):
        import paramiko
        paramiko.RSAKey.generate(3072).write_private_key_file(path)
    return path


def _key_pub_line():
    import paramiko
    k = paramiko.RSAKey.from_private_key_file(ensure_server_key())
    return f"{k.get_name()} {k.get_base64()} owctl"


def ssh_test(dev):
    """Verify we can reach + authenticate to the device and read a banner."""
    try:
        c = owctl._ssh_connect(dev)
    except Exception as e:
        return {"ok": False, "detail": str(e)}
    try:
        out, err, status = owctl._exec_capture(
            c, "cat /etc/openwrt_release 2>/dev/null | head -1; uptime", timeout=30)
        return {"ok": True, "detail": (out.strip() or err.strip() or "connected")[:200]}
    except Exception as e:
        return {"ok": False, "detail": str(e)}
    finally:
        c.close()


def luci_test(dev):
    try:
        si = owctl._luci_rpc(dev, "luci.sys.sysinfo") or {}
        detail = f"{si.get('model', '')} {si.get('firmware', '')}".strip()
        return {"ok": True, "detail": (detail or "connected")[:200]}
    except Exception as e:
        return {"ok": False, "detail": str(e)}


def push_ssh_key(dev):
    """Install the owctl public key on the device, then verify key-only auth.

    Uses a plain SSH exec command rather than SFTP: many OpenWrt builds ship
    without the sftp subsystem (paramiko then raises 'EOF' on the first SFTP
    call), so writing authorized_keys over the exec channel is more robust.
    """
    pub = _key_pub_line()
    key_path = ensure_server_key()
    c = owctl._ssh_connect(dev)
    try:
        # base64-encode the key so the command contains no shell metacharacters
        # (no quoting/escaping pitfalls, works on ash/dash/busybox sh). Decode
        # remotely, de-dup, and set correct permissions.
        import base64
        b64 = base64.b64encode(pub.encode()).decode()
        # Resolve the SSH user's real home from the session ($HOME, set by
        # dropbear from /etc/passwd to the account's actual home — /root for
        # root, $HOME for any non-root user). The old code hardcoded
        # /home/root, which does not exist on OpenWrt (root's home is /root),
        # so the key landed in a directory dropbear never consulted and the
        # follow-up key-only auth check failed on a real device. $HOME is
        # correct for every user; /root is a safe fallback if it's unset.
        cmd = (
            "set -e; H=\"${HOME:-/root}\"; "
            "mkdir -p \"$H/.ssh\" && chmod 700 \"$H/.ssh\"; "
            "grep -qF '" + pub + "' \"$H/.ssh/authorized_keys\" 2>/dev/null || "
            "printf '%s' '" + b64 + "' | base64 -d >> \"$H/.ssh/authorized_keys\"; "
            "chmod 600 \"$H/.ssh/authorized_keys\""
        )
        out, err, status = owctl._exec_capture(c, cmd, timeout=60)
        if status != 0:
            enriched = owctl.enrich_device_error(dev, (err or out).strip(), "push_ssh_key")
            raise RuntimeError(enriched)
    finally:
        c.close()
    owctl.execute("UPDATE devices SET key_path=? WHERE id=?", (key_path, dev["id"]))
    probe = dict(dev)
    probe["key_path"] = key_path
    probe["ssh_password"] = ""
    vt = ssh_test(probe)
    owctl.log_action(dev, 'push_ssh_key', 'key pushed', ok=vt["ok"], error=vt["detail"] if not vt["ok"] else '')
    return {"ok": vt["ok"], "public_key": pub, "detail": vt["detail"], "key_saved": True}


def do_backup(dev):
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    slug = re.sub(r"\W+", "_", dev["name"])
    if dev["access"] == "ssh":
        c = owctl._ssh_connect(dev)
        try:
            # ponytail: read config directly via SSH to avoid SFTP/EOF issues
            cmd = "uci export; true"  # force success even if uci returns non-zero
            stdin, stdout, stderr = c.exec_command(cmd, timeout=60)
            content = stdout.read().decode(errors="replace")
            if not content.strip():
                raise RuntimeError("uci export returned empty config")
            local = os.path.join(owctl.BACKUP_DIR, f"{slug}-{ts}.conf")
            with open(local, "w") as fh:
                fh.write(content)
            kind = "uci-export"
        finally:
            c.close()
    elif dev["access"] == "luci":
        cfg = owctl._luci_rpc(dev, "luci.config.get", "", [])
        local = os.path.join(owctl.BACKUP_DIR, f"{slug}-{ts}.json")
        with open(local, "w") as fh:
            json.dump(cfg, fh, indent=2)
        kind = "luci-config"
    else:
        raise HTTPException(400, "device has no management access configured")
    size = os.path.getsize(local)
    owctl.execute("INSERT INTO backups(ts, device_id, device_name, kind, path, size) VALUES(?,?,?,?,?,?)",
            (owctl.now(), dev["id"], dev["name"], kind, local, size))
    owctl.log_action(dev, 'backup', f'kind={kind} path={os.path.basename(local)}', ok=True)
    return local


def _resolve_backup_path(path):
    """Confine a user-supplied restore path to the backups directory so it can't
    read/push an arbitrary server file. Resolves symlinks and `..` so neither
    `/etc/shadow`, `../etc/passwd`, nor a symlink can escape BACKUP_DIR.
    Relative paths are anchored at BACKUP_DIR. Returns the safe absolute path;
    raises 400 (escapes the dir) or 404 (missing/not a file)."""
    if not path:
        raise HTTPException(400, "backup path required")
    root = os.path.realpath(owctl.BACKUP_DIR)
    candidate = path if os.path.isabs(path) else os.path.join(root, path)
    real = os.path.realpath(candidate)
    if real != root and not real.startswith(root + os.sep):
        raise HTTPException(400, "backup path must live under the backups directory")
    if not os.path.isfile(real):
        raise HTTPException(404, "backup file not found")
    return real


def do_restore(dev, backup_path):
    """Restore device config from a backup file. Only for SSH-accessible devices.
    The file must live under the backups directory (see _resolve_backup_path)."""
    if dev["access"] != "ssh":
        raise HTTPException(400, "restore requires SSH access on this device")
    backup_path = _resolve_backup_path(backup_path)
    with open(backup_path, "r") as fh:
        content = fh.read()
    if not content.strip():
        raise HTTPException(400, "backup file is empty")
    c = owctl._ssh_connect(dev)
    try:
        remote = f"/tmp/owctl-restore-{os.path.basename(backup_path)}"
        # ponytail: write file via stdin pipe (avoid large command strings)
        stdin, stdout, stderr = c.exec_command(f"cat > {remote}", timeout=120)
        with open(backup_path, "rb") as fh:
            data = fh.read()
        stdin.write(data)
        stdin.close()
        stdout.read()
        # Import and commit
        stdin, stdout, stderr = c.exec_command(f"uci import < {remote} && uci commit", timeout=60)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        status = stdout.channel.recv_exit_status()
        c.exec_command(f"rm -f {remote}")
        if status != 0:
            raise RuntimeError(f"uci import failed (exit={status}): {(err or out)[:200]}")
        owctl.log_action(dev, 'restore', f'file={os.path.basename(backup_path)}', ok=True)
        return {"restored": True, "file": backup_path, "output": out[:500]}
    except Exception as e:
        c.close()
        raise RuntimeError(f"restore failed: {e}") from e


def _valid_vlan_id(v):
    """Coerce a user-supplied vlan_id to an int VLAN id in 1..4094 or raise 400.

    do_vlan/do_vlan_delete/do_vlan_port interpolate vlan_id into uci shell
    scripts — this is the injection choke point: only an int survives.
    """
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        raise HTTPException(400, "vlan_id must be an integer (1-4094)")
    if not 1 <= n <= 4094:
        raise HTTPException(400, "vlan_id must be in 1-4094")
    return n


def do_vlan(dev, vlan_id, name, subnet, dhcp, devices, router_id, apply: bool = True):
    """Apply VLAN config to a device. router_id is the device that will act as router.
    apply=False commits the network/dhcp/firewall sections without restarting the
    daemons (LuCI 'Save'); apply=True (default) also restarts them so the VLAN is live."""
    if dev["access"] != "ssh":
        raise HTTPException(400, "VLAN config requires SSH access")
    # Injection choke point: everything below interpolates vlan_id into uci
    # shell text, so normalize to the int form once, here.
    vlan_id = _valid_vlan_id(vlan_id)
    c = owctl._ssh_connect(dev)
    try:
        is_router = dev["id"] == router_id
        if is_router:
            # Router: create routed interface + firewall zone. L3 (ipaddr +
            # netmask) is derived from the CIDR subnet via _parse_subnet — the
            # same pure helper the DHCP path uses — so any /8../30 works.
            l3 = owctl._parse_subnet(subnet) if subnet else None
            if not l3:
                raise HTTPException(400, f"invalid subnet for VLAN {vlan_id} (expected a.b.c.d/prefix)")
            ip, mask_full = l3
            cmd = f"""uci set network.vlan_{vlan_id}=interface
uci set network.vlan_{vlan_id}.proto='static'
uci set network.vlan_{vlan_id}.ipaddr='{ip}'
uci set network.vlan_{vlan_id}.netmask='{mask_full}'
uci set network.vlan_{vlan_id}.ifname='br-lan.{vlan_id}'
uci set network.vlan_{vlan_id}.vlan='{vlan_id}'
"""
            if dhcp:
                cmd += f"""uci set dhcp.vlan_{vlan_id}=dhcp
uci set dhcp.vlan_{vlan_id}.interface='vlan_{vlan_id}'
uci set dhcp.vlan_{vlan_id}.start='100'
uci set dhcp.vlan_{vlan_id}.limit='150'
uci set dhcp.vlan_{vlan_id}.lease_time='12h'
"""
            cmd += f"""uci set zone.vlan_{vlan_id}=zone
uci set zone.vlan_{vlan_id}.name='vlan_{vlan_id}'
uci set zone.vlan_{vlan_id}.network='vlan_{vlan_id}'
uci set zone.vlan_{vlan_id}.input='ACCEPT'
uci set zone.vlan_{vlan_id}.output='ACCEPT'
uci set zone.vlan_{vlan_id}.forward='REJECT'
"""
            cmd += "uci commit network\n"
            if dhcp:
                cmd += "uci commit dhcp\n"
            cmd += "uci commit firewall\n"
            if apply:
                # Make the committed VLAN live (fixes the old no-restart gap).
                cmd += (owctl._PENDING_RESTARTS["vlan"] + "\n")
        else:
            # Switch: tag ports with VLAN
            cmd = f"""uci set network.vlan_{vlan_id}=switch
uci set network.vlan_{vlan_id}.vlan='{vlan_id}'
uci set network.vlan_{vlan_id}.device='switch0'
uci commit network
"""
            if apply:
                cmd += (owctl._PENDING_RESTARTS["vlan"] + "\n")
        stdin, stdout, stderr = c.exec_command(cmd, timeout=30)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        status = stdout.channel.recv_exit_status()
        if status != 0:
            raise RuntimeError(f"VLAN config failed on {dev['name']}: {(err or out)[:200]}")
        owctl.set_pending(dev, "vlan", apply)
        owctl.record_vlan_membership(vlan_id, dev["id"], "router" if is_router else "switch")
        owctl.log_action(dev, 'vlan', f'vlan_id={vlan_id} role={"router" if is_router else "switch"}', ok=True)
        return {"device": dev["name"], "role": "router" if is_router else "switch", "ok": True}
    finally:
        c.close()


def vlan_delete_cmds(vlan_id):
    """Pure: the uci script that tears down a VLAN's sections on one device.

    Removes the `network.vlan_<id>` section (interface/switch), every
    `dhcp.<x>` section whose `.interface` points at `vlan_<id>`, and the
    `firewall.vlan_<id>` zone, then commits the three packages. The `switch`
    package is deliberately left alone — port assignments are managed via
    switch-ports and may be shared. Deleting absent sections is a no-op."""
    vid = int(vlan_id)
    return (
        f"uci delete network.vlan_{vid} 2>/dev/null || true\n"
        "uci commit network 2>/dev/null || true\n"
        "for s in $(uci show dhcp 2>/dev/null | "
        "grep -oE 'dhcp\\.[A-Za-z0-9_]+' | sort -u); do "
        f"if [ \"$(uci -q get $s.interface 2>/dev/null)\" = 'vlan_{vid}' ]; then "
        "uci delete $s 2>/dev/null || true; fi; done\n"
        "uci commit dhcp 2>/dev/null || true\n"
        f"uci delete firewall.vlan_{vid} 2>/dev/null || true\n"
        "uci commit firewall 2>/dev/null || true\n"
    )


def do_vlan_delete(dev, vlan_id, apply: bool = True):
    """Remove a VLAN's config from one device (network/dhcp/firewall sections).
    apply=False commits deletions without restarting (LuCI 'Save')."""
    vlan_id = _valid_vlan_id(vlan_id)
    if dev["access"] != "ssh":
        raise HTTPException(400, "VLAN delete requires SSH access")
    vid = int(vlan_id)
    if not (1 <= vid <= 4094):
        raise HTTPException(400, f"invalid VLAN id {vid}")
    cmd = vlan_delete_cmds(vid)
    if apply:
        cmd += owctl._PENDING_RESTARTS["vlan"] + "\n"
    c = owctl._ssh_connect(dev)
    try:
        out, err, status = owctl._exec_capture(c, cmd, timeout=60)
        if status != 0:
            raise RuntimeError(f"VLAN delete failed on {dev['name']}: {(err or out).strip()[:200]}")
        owctl.log_action(dev, "vlan_delete", f"vlan_id={vid}", ok=True)
        return {"device": dev["name"], "ok": True}
    finally:
        c.close()


def delete_vlan_membership(vlan_id, device_id=None):
    """Clear the membership ledger for a VLAN (optionally one device only).
    Never raises."""
    try:
        if device_id is not None:
            owctl.execute("DELETE FROM vlans_devices WHERE vlan_id=? AND device_id=?",
                    (str(vlan_id), device_id))
        else:
            owctl.execute("DELETE FROM vlans_devices WHERE vlan_id=?", (str(vlan_id),))
    except Exception:
        pass


def do_rebaseline(dev, packages, sysupgrade=False):
    """Bring one device back to baseline: refresh feeds, upgrade the listed
    packages (each made idempotent so an absent one doesn't fail the batch),
    optionally run sysupgrade -n (no-reboot) for a firmware align.
    Returns the command output (truncated). Raises on a hard failure."""
    if dev["access"] != "ssh":
        raise HTTPException(400, "re-baseline requires SSH access on this device")
    safe = []
    for p in packages or []:
        p = str(p)
        if not re.fullmatch(r"[A-Za-z0-9_.+-]+", p):
            raise HTTPException(400, f"invalid package name {p!r}")
        safe.append(p)
    parts = ["opkg update 2>/dev/null || true"]
    for p in safe:
        parts.append(f"opkg upgrade -y {p} 2>/dev/null || opkg install -y {p} 2>/dev/null || true")
    cmd = "\n".join(parts) + "\n"
    if sysupgrade:
        cmd += "sysupgrade -n 2>/dev/null || opkg upgrade -y base 2>/dev/null || true\n"
    c = owctl._ssh_connect(dev)
    try:
        out, err, status = owctl._exec_capture(c, cmd, timeout=3600)
        result = (out.strip() + "\n--- stderr ---\n" + (err or "").strip()).strip()
        if status not in (0,):
            raise RuntimeError(f"re-baseline exited {status} on {dev['name']}")
    finally:
        c.close()
    owctl.log_action(dev, "rebaseline",
               f"packages={','.join(safe) or 'none'} sysupgrade={bool(sysupgrade)}", ok=True)
    return result[:30000]
