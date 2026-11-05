"""owctl.ssh"""
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

GATHER_SCRIPT = r"""
echo '##release##'; cat /etc/openwrt_release 2>/dev/null | tr '\n' ' '; echo
echo '##model##'; sed -n 's/.*"hostname"[^"]*"\([^"]*\)".*/\1/p' /etc/board.json 2>/dev/null
echo '##date##'; date -u '+%Y-%m-%d %H:%M:%S'
echo '##uptime##'; awk '{print int($1)}' /proc/uptime
echo '##load##'; cut -d' ' -f1-3 /proc/loadavg
echo '##mem##'; grep -E 'MemTotal|MemFree' /proc/meminfo | awk '{sub(/:/,"",\$1); printf "%s=%s ", \$1, \$2}; echo'
echo '##disk##'; df -h /overlay 2>/dev/null | awk 'NR==2 {print $2" used="$5" free="$4}'
echo '##clients##'; iwinfo 2>/dev/null | grep 'Associated STAs' | awk '{s+=$3} END{print s+0}'
echo '##wan##'; ubus call network.status wan 2>/dev/null | head -c 300
echo '##fw##'; printf 'in=%s fwd=%s out=%s\n' "$(uci -q get firewall.@defaults[0].input)" "$(uci -q get firewall.@defaults[0].forward)" "$(uci -q get firewall.@defaults[0].output)"
echo '##qos##'; uci show sqm 2>/dev/null; uci show nft-qos 2>/dev/null
echo '##dropbear##'; printf 'pwauth=%s port=%s\n' "$(uci -q get dropbear.@dropbear[0].PasswordAuth)" "$(uci -q get dropbear.@dropbear[0].Port)"
echo '##listeners##'; netstat -tln 2>/dev/null | awk 'NR>1 {n=split($4,a,":"); if (a[n]~/^[0-9]+$/) print a[n]}' | sort -un | tr '\n' ' '; echo
echo '##ntp##'; uci -q get system.ntp.enabled
echo '##redirects##'; i=0; while uci -q get "firewall.@redirect[$i].name" >/dev/null 2>&1; do printf '%s %s %s\n' "$i" "$(uci -q get "firewall.@redirect[$i].name")" "$(uci -q get "firewall.@redirect[$i].dest_port")"; i=$((i+1)); done
echo '##upgradable##'; opkg list-upgradable 2>/dev/null
echo '##interfaces##'; ifconfig 2>/dev/null | awk '/^[a-z]/&&!/Loopback/{name=$1} /inet addr:/{split($2,a,":"); printf "%s %s\n", name, a[2]}'
echo '##meshd##'; if [ -x /usr/sbin/meshd ]; then echo 'meshd'; elif [ -x /usr/bin/batmand ]; then echo 'batmand'; elif uci -q show wireless | grep -qi 'mesh\|802.11s\|batadv'; then echo 'uci'; else echo ''; fi
echo '##wireless##'; iwinfo 2>/dev/null | awk '/ESSID:/{essid=$0; gsub(/.*ESSID: *"/, "", essid); gsub(/".*/, "", essid)} /Mode:.*Channel:/{chan=$0; gsub(/.*Channel: */, "", chan); gsub(/ .*/, "", chan)} /Encryption:/{enc=$0; gsub(/.*Encryption: */, "", enc); printf "%s\t%s\t%s\n", essid, chan, enc}'; echo
echo '##stations##'; iwinfo 2>/dev/null | awk '/ESSID:/{essid=$0; gsub(/.*ESSID: *"/, "", essid); gsub(/".*/, "", essid)} /Associated STAs:/{stas=$0; gsub(/.*Associated STAs: */, "", stas); gsub(/ .*/, "", stas); if (essid) print essid"\t"stas}'; echo
echo '##neighbors##'; ip neigh show 2>/dev/null | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/{print $1"\t"$3"\t"$5}'
echo '##dhcp##'; cat /tmp/dhcp.leases 2>/dev/null
echo '##installed##'; opkg list-installed 2>/dev/null
echo '##obsolete##'; comm -23 <(opkg list-installed 2>/dev/null | awk '{print $1}' | sort) <(opkg list 2>/dev/null | awk '{print $1}' | sort) | tr '\n' ' '; echo
echo '##config##'; sha256sum /etc/config/* 2>/dev/null | awk '{print $2"="$1}'
echo '##traffic##'; awk 'NR>2{gsub(/:/,"",$1); printf "%s %s %s\n", $1, $2, $10}' /proc/net/dev
echo '##thermal##'; cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null
echo '##syslog##'; logread 2>/dev/null | tail -50
echo '##vlans##'; uci show network 2>/dev/null | grep -E 'switch|vlan' | awk '{print $0}'
echo '##routing##'; ip route show 2>/dev/null
echo '##bgp_present##'; opkg list-installed bird 2>/dev/null | head -1
echo '##end##'
"""


def _parse_sections(raw):
    sections, cur = {}, None
    for line in raw.splitlines():
        m = re.match(r'^##(\w+)##$', line.strip())
        if m:
            cur = m.group(1)
            sections[cur] = []
        elif cur is not None:
            sections[cur].append(line)
    # Join multi-line sections with a NEWLINE (not a space): sections that hold
    # one record per line (upgradable packages, port redirects) must keep their
    # line structure so _build_status can splitlines() them back into records.
    return {k: "\n".join(v).strip() for k, v in sections.items()}


def _ssh_known_hosts_path():
    """On-disk pin for device host keys (trust-on-first-use). Kept under DATA_DIR
    so it survives restarts — the whole point of pinning is that a *later* process
    still verifies the host against the key it saw the first time."""
    return os.path.join(owctl.DATA_DIR, "ssh_known_hosts")


class _TrustOnFirstUse(paramiko.MissingHostKeyPolicy):
    """Accept-and-pin on first sight; paramiko verifies every later connection.

    Replaces AutoAddPolicy() (which silently trusted any key — a MITM's fabricated
    host key was accepted). On a first-seen host we add its key to the client's
    host-key set and persist it; on every later connection paramiko itself checks
    the presented key against that set and raises BadHostKeyException on a
    mismatch (rotated / replaced / MITM'd key). Re-trust a legitimately rotated
    key by deleting its line from the pin file (or set OWCTL_SSH_TRUST_ANY=1 to
    revert to accept-all for ephemeral test hosts)."""
    def __init__(self, pin_path):
        self.pin_path = pin_path
    def missing_host_key(self, client, hostname, key):
        client.get_host_keys().add(hostname, key.get_name(), key)
        try:
            os.makedirs(os.path.dirname(self.pin_path) or ".", exist_ok=True)
            client.save_host_keys(self.pin_path)
        except Exception:
            pass  # pinning is best-effort; still connect on first sight


def _ssh_connect(dev):
    import paramiko
    import socket as _socket
    from paramiko.ssh_exception import AuthenticationException as SSHAuthError
    c = paramiko.SSHClient()
    pin = _ssh_known_hosts_path()
    if os.environ.get("OWCTL_SSH_TRUST_ANY") == "1":
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # test/ephemeral hosts
    else:
        if os.path.exists(pin):
            try:
                c.load_host_keys(pin)  # pinned keys become paramiko's verify set
            except Exception:
                pass  # unreadable/corrupt pin -> start fresh rather than break SSH
        c.set_missing_host_key_policy(_TrustOnFirstUse(pin))
    kw = dict(hostname=dev["host"], port=int(dev.get("ssh_port") or 22),
              username=dev.get("ssh_user") or "root", timeout=15,
              banner_timeout=20, auth_timeout=20,
              allow_agent=False, look_for_keys=False)
    if dev.get("key_path"):
        kw["key_filename"] = dev["key_path"]
    elif dev.get("ssh_password"):
        kw["password"] = owctl._stored_device_cred(dev["ssh_password"])
    else:
        kw["key_filename"] = owctl.ensure_server_key()
    try:
        c.connect(**kw)
    except paramiko.BadHostKeyException as e:
        raise RuntimeError(
            f"SSH host key for {dev['host']} does not match the pinned key — "
            f"possible MITM, or the device's key changed. Verify the device and "
            f"remove its entry from {pin} to re-trust: {e}") from e
    except SSHAuthError as e:
        if dev.get("ssh_password"):
            raise RuntimeError(f"SSH authentication failed for {dev.get('ssh_user')}@{dev['host']} "
                               f"— check the password") from e
        raise RuntimeError(f"SSH key rejected by {dev['host']} — set a password on the device "
                           f"or install our key first (Push SSH key)") from e
    except _socket.timeout as e:
        raise RuntimeError(f"SSH connect to {dev['host']}:{kw['port']} timed out — is the device up?") from e
    except _socket.gaierror as e:
        raise RuntimeError(f"SSH: cannot resolve host {dev['host']}") from e
    except _socket.error as e:
        raise RuntimeError(f"SSH connect to {dev['host']}:{kw['port']} failed — check the address/port: {e}") from e
    return c


def _exec_capture(client, cmd, timeout=300):
    """Run cmd on an open client, draining stdout+stderr in parallel (no pipe deadlock).
    Returns (stdout, stderr, exit_status)."""
    chan = client.get_transport().open_session()
    chan.exec_command(cmd)
    out_q, err_q = [], []

    def drain(f, q):
        try:
            while True:
                b = f.read(65536)
                if not b:
                    break
                q.append(b)
        except Exception:
            pass

    t1 = threading.Thread(target=drain, args=(chan.makefile("rb"), out_q), daemon=True)
    t2 = threading.Thread(target=drain, args=(chan.makefile_stderr("rb"), err_q), daemon=True)
    t1.start()
    t2.start()
    t1.join(timeout)
    t2.join(timeout)
    try:
        status = chan.recv_exit_status()
    except Exception:
        status = -1
    chan.close()
    return b"".join(out_q).decode(errors="replace"), b"".join(err_q).decode(errors="replace"), status


def enrich_device_error(dev, err_text: str, failed_cmd: str) -> str:
    """
    Enrich a device-side exec error with actionable context.

    Detects common failure signatures in err_text and composes a detail string
    containing: which command failed, on which device (host), firmware when
    available, and a hint. Falls back to the original err_text if no known
    signature is detected. Never raises.
    """
    # Handle bytes input
    if isinstance(err_text, bytes):
        err_text = err_text.decode(errors="replace")
    if not err_text:
        return err_text or failed_cmd or "unknown error"

    # Extract firmware string from device status if available
    firmware = ""
    if isinstance(dev, dict):
        # dev may be a raw sqlite row with firmware/firmware_info keys
        fw_info = dev.get("firmware_info") or {}
        if isinstance(fw_info, dict):
            desc = fw_info.get("description") or ""
            ver = fw_info.get("version") or ""
            rev = fw_info.get("revision") or ""
            parts = [p for p in [desc, ver, rev] if p]
            firmware = " ".join(parts) if parts else ""
        elif dev.get("firmware"):
            firmware = dev.get("firmware")

    host = dev.get("host") if isinstance(dev, dict) else ""
    name = dev.get("name") if isinstance(dev, dict) else ""

    # Extract the binary/command that was not found
    # Common patterns: "ash: base64: not found", "/bin/ash: base64: not found", "command not found: base64"
    cmd_token = None
    lower_err = err_text.lower()

    # Pattern: "... binary_name: not found" or "... command not found: binary_name"
    import re
    # Match 'ash: base64: not found' or 'base64: not found' or 'command not found: base64'
    m = re.search(r'(?:^|[:\s])([a-zA-Z0-9_.+-]+):\s*not found', err_text)
    if m:
        cmd_token = m.group(1)
    else:
        m = re.search(r'command not found:\s*([a-zA-Z0-9_.+-]+)', err_text, re.IGNORECASE)
        if m:
            cmd_token = m.group(1)

    # Compose enriched detail
    parts = []
    action = "command failed"
    if "push" in failed_cmd.lower() or "key" in failed_cmd.lower():
        action = "push-key failed"
    elif "backup" in failed_cmd.lower():
        action = "backup failed"
    elif "restore" in failed_cmd.lower():
        action = "restore failed"
    elif "vlan" in failed_cmd.lower():
        action = "VLAN operation failed"
    elif "routing" in failed_cmd.lower():
        action = "routing operation failed"
    elif "switch" in failed_cmd.lower():
        action = "switch operation failed"
    elif "wifi" in failed_cmd.lower() or "wireless" in failed_cmd.lower():
        action = "WiFi operation failed"
    elif "mesh" in failed_cmd.lower():
        action = "mesh operation failed"
    elif "upgrade" in failed_cmd.lower():
        action = "upgrade failed"
    elif "reboot" in failed_cmd.lower():
        action = "reboot failed"

    if cmd_token:
        hint = f"Hint: opkg install {cmd_token}"
        if firmware:
            parts.append(f"{action}: command not found on {host} ({firmware}): {cmd_token}. {hint}")
        else:
            parts.append(f"{action}: command not found on {host}: {cmd_token}. {hint}")
    elif "permission denied" in lower_err:
        if firmware:
            parts.append(f"{action} on {host} ({firmware}): Permission denied")
        else:
            parts.append(f"{action} on {host}: Permission denied")
    elif "connection refused" in lower_err:
        if firmware:
            parts.append(f"{action} on {host} ({firmware}): Connection refused")
        else:
            parts.append(f"{action} on {host}: Connection refused")
    elif "no such file or directory" in lower_err:
        # Could be missing file or missing command
        if firmware:
            parts.append(f"{action} on {host} ({firmware}): No such file or directory")
        else:
            parts.append(f"{action} on {host}: No such file or directory")
    elif "timeout" in lower_err or "timed out" in lower_err:
        if firmware:
            parts.append(f"{action} on {host} ({firmware}): Timeout")
        else:
            parts.append(f"{action} on {host}: Timeout")
    else:
        # No recognized signature — fall back to original behavior
        return err_text

    return " ".join(parts)


def _build_status(dev, backend, s):
    st = {"backend": backend, "online": True, "host": dev["host"], "name": dev["name"]}
    st["firmware"] = s.get("release", "")
    st["firmware_info"] = owctl.parse_openwrt_release(s.get("release", ""))
    st["model"] = s.get("model", "")
    st["device_date"] = s.get("date", "")
    st["uptime_s"] = int(s.get("uptime") or 0)
    st["load"] = s.get("load", "").split()
    mem = dict(re.findall(r'(\w+)=(\d+)', s.get("mem", "")))
    st["mem_total_kb"] = int(mem.get("MemTotal", 0))
    st["mem_free_kb"] = int(mem.get("MemFree", 0))
    st["disk"] = s.get("disk", "")
    m_disk = re.search(r'used=(\d+)%', st["disk"])
    st["disk_used_pct"] = int(m_disk.group(1)) if m_disk else None
    thermal = s.get("thermal", "").strip()
    st["cpu_temp_c"] = float(thermal) / 1000 if thermal and thermal.isdigit() else None
    st["clients"] = int(s.get("clients") or 0)
    wan = s.get("wan", "")
    st["wan_up"] = None if not wan.strip() else ('"up":true' in wan or '"up": true' in wan)
    m = re.search(r'"ipaddr":\s*\[\s*"([^"]+)"', wan)
    st["wan_ip"] = m.group(1) if m else ""
    st.update({("fw_" + k): v for k, v in dict(re.findall(r'(in|fwd|out)=(\S+)', s.get("fw", ""))).items()})
    # QoS (SQM / nft-qos) config — parsed via parse_sqm; None when the package is absent.
    st["qos"] = owctl.parse_sqm(s.get("qos", ""))
    dbv = dict(re.findall(r'(pwauth|port)=(\S+)', s.get("dropbear", "")))
    st["dropbear_pwauth"] = dbv.get("pwauth", "")
    st["listeners"] = [int(x) for x in s.get("listeners", "").split()]
    st["telnet_on"] = 23 in st["listeners"]
    st["ntp"] = s.get("ntp", "")
    reds = []
    for line in s.get("redirects", "").splitlines():
        p = line.split()
        if len(p) >= 3:
            reds.append({"name": p[1], "dest_port": p[2]})
    st["redirects"] = reds
    upg = []
    for line in s.get("upgradable", "").splitlines():
        p = line.split()
        if len(p) >= 3:
            upg.append({"pkg": p[0], "installed": p[1], "available": p[2]})
    st["upgradable"] = upg
    # Parse interfaces: lines like "lo 127.0.0.1/8" or "wan1 100.111.198.228/10"
    iface_map = {}
    iface_ip = []
    for line in s.get("interfaces", "").splitlines():
        p = line.split()
        if len(p) >= 2:
            name, cidr = p[0], p[1]
            ip = cidr.split("/")[0]
            iface_map[name] = {"name": name, "ip": ip, "cidr": cidr}
            iface_ip.append(ip)
    st["interfaces"] = iface_map
    st["ips"] = iface_ip
    # Parse wireless: ESSID Channel Encryption (tab-separated triplets)
    ap_list = []
    for line in s.get("wireless", "").splitlines():
        parts = [x.strip() for x in line.split("\t")]
        if len(parts) < 3:
            continue
        essid = parts[0].replace("ESSID:", "").strip('"')
        chan = parts[1].replace("Channel:", "").strip()
        enc = parts[2].replace("Encryption:", "").strip()
        # Determine band from channel. A channel can be non-numeric (device
        # reported 'auto'/'unknown') or empty — int() would raise ValueError
        # and, because _build_status is called unguarded in ssh_gather, crash
        # the ENTIRE gather for this device. Skip the band (None) when the
        # channel can't be parsed rather than failing the whole status.
        band = None
        _first = chan.split()
        if _first:
            try:
                band = "2.4GHz" if int(_first[0]) <= 14 else "5GHz"
            except (ValueError, TypeError):
                band = None
        ap_list.append({
            "essid": essid, "channel": chan,
            "band": band, "encryption": enc if enc else "open"})
    st["wifi"] = ap_list
    st["wifi_capable"] = len(ap_list) > 0
    # Parse stations: ESSID\tclient_count
    st["stations"] = {}
    for line in s.get("stations", "").splitlines():
        p = line.split("\t")
        if len(p) >= 2:
            st["stations"][p[0]] = int(p[1])
    # Parse neighbors: IP\tIFACE\tMAC
    nb = []
    for line in s.get("neighbors", "").splitlines():
        p = line.split("\t")
        if len(p) >= 3:
            nb.append({"ip": p[0], "iface": p[1], "mac": p[2]})
    st["neighbors"] = nb
    # Parse DHCP leases: timestamp MAC IP hostname expiry
    dhcp = []
    for line in s.get("dhcp", "").splitlines():
        p = line.split()
        if len(p) >= 4:
            dhcp.append({"mac": p[1], "ip": p[2], "hostname": p[3] if len(p) > 3 else ""})
    st["dhcp"] = dhcp
    # Installed packages (opkg list-installed: name version desc per line)
    installed = []
    for line in s.get("installed", "").splitlines():
        p = line.split()
        if len(p) >= 2:
            installed.append({"pkg": p[0], "version": p[1]})
    st["installed"] = installed
    # Obsolete packages: installed but not in any feed (no longer available)
    st["obsolete"] = [x.strip() for x in s.get("obsolete", "").split() if x.strip()]
    # Mesh daemon: 802.11s / batman / meshd presence
    meshd = s.get("meshd", "").strip().lower()
    st["meshd"] = meshd or None

    # Parse config hashes: /etc/config/file hash
    st["config_hashes"] = {}
    for line in s.get("config", "").splitlines():
        if "=" in line:
            path, h = line.split("=", 1)
            st["config_hashes"][path] = h[:12]  # store short hash
    # Parse traffic counters: iface rx_bytes tx_bytes
    st["traffic"] = {}
    for line in s.get("traffic", "").splitlines():
        p = line.split()
        if len(p) >= 3:
            st["traffic"][p[0]] = {"rx": int(p[1]), "tx": int(p[2])}
    # Parse syslog: timestamp facility message
    syslog = []
    for line in s.get("syslog", "").splitlines():
        p = line.split(None, 4)
        if len(p) >= 4:
            syslog.append({"ts": " ".join(p[:3]), "message": p[4] if len(p) > 4 else ""})
    st["syslog"] = syslog
    # Parse VLAN config
    st["vlans"] = []
    for line in s.get("vlans", "").splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("config vlan"):
            parts = line.split()
            vlan_id = parts[2].strip("'\"")
            st["vlans"].append({"type": "vlan", "id": vlan_id, "raw": line})
        elif line.startswith("config switch"):
            st["vlans"].append({"type": "switch", "raw": line})
    return st


def ssh_gather(dev):
    c = _ssh_connect(dev)
    try:
        raw, err, status = _exec_capture(c, GATHER_SCRIPT, timeout=180)
    finally:
        c.close()
    if "##end##" not in raw:
        tail = (err.strip() or raw.strip())[-400:]
        raise RuntimeError(f"gather script did not complete on device (exit={status}); tail: {tail}")
    st = _build_status(dev, "ssh", _parse_sections(raw))
    # Detect config changes and attach to status
    changed = owctl.check_config_changes(dev, st)
    if changed:
        st["config_changed"] = ", ".join(changed[:5])
    return st


def gather(dev):
    if dev["access"] == "ssh":
        return ssh_gather(dev)
    if dev["access"] == "luci":
        return owctl.luci_gather(dev)
    raise RuntimeError("device has no management access configured")


DDNS_PROVIDERS = {
    "duckdns":     dict(url="https://duckdns.org/update?domains={host}&token={token}&ip={ip}", ok="OK"),
    "noip":        dict(url="https://api.noip.com/nic/update?hostname={host}&myip={ip}", ok="good"),
    "dynu":        dict(url="https://api.dynu.com/nic/update?hostname={host}&myip={ip}&token={token}", ok="good"),
    "freedns":     dict(url="https://freedns.afraid.org/dynamic/update.php?hostname={host}&auth_token={token}&myip={ip}", ok="good"),
    "noip_duck":   dict(url="https://duckdns.org/update?token={token}&domain={host}&ip={ip}", ok="OK"),
    "cloudflare":  dict(url="https://api.cloudflare.com/client/v4/zones/{zone}/dns_records/{rec}",
                         ok="success", json_body=True),
    "ovh":         dict(url="https://eu.api.ovh.com/1.0/ddns/record?hostname={host}&ip={ip}",
                         ok="ok", json_body=True),
    "godaddy":     dict(url="https://api.godaddy.com/v1/domains/{host}/records/A/{rec}",
                         ok="recordSet", json_body=True),
    "namecheap":   dict(url="https://dynamic.namecheap.com/getip?host={host}&domain={dom}&password={token}",
                         ok="good"),
    "hurricane":   dict(url="https://dns.he.net/dns?hostname={host}&myip={ip}&password={token}", ok="good"),
    "ddns_oray":   dict(url="https://ddns.oray.com/checkip?hostname={host}&token={token}&myip={ip}", ok="good"),
}
