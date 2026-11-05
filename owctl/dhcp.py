"""owctl.dhcp"""
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

def parse_dhcp_leases(raw):
    """Pure parser for /tmp/dhcp.leases: lines are
    'expire mac ip [hostname]' -> [{mac, ip, hostname}]."""
    out = []
    for line in (raw or "").splitlines():
        p = line.split()
        if len(p) >= 3 and owctl.parse_mac(p[1]):
            out.append({"mac": p[1].lower(), "ip": p[2],
                        "hostname": p[3] if len(p) > 3 else ""})
    return out


def read_arp_neighbors(dev):
    """ARP table from a device: [{ip, iface, mac}] (like the gather's
    'ip neigh show' line). Returns [] on failure — the picker degrades to
    leases-only rather than erroring."""
    if dev["access"] != "ssh":
        return []
    try:
        c = owctl._ssh_connect(dev)
        try:
            out, _e, _s = owctl._exec_capture(
                c, "ip neigh show 2>/dev/null | awk '/^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/{print $1\"\\t\"$3\"\\t\"$5}'",
                timeout=20)
        finally:
            c.close()
        res = []
        for line in out.splitlines():
            p = line.split("\t")
            if len(p) >= 3 and owctl.parse_mac(p[2]):
                res.append({"ip": p[0], "iface": p[1], "mac": p[2].lower()})
        return res
    except Exception:
        return []


def build_lease_cmds(iface: str, leases, apply: bool = True) -> str:
    """Pure: uci script that REPLACES the static-lease list of one dhcp
    section (mirrored under dnsmasq `dhcp_host` + odhcpd `host`, matching
    build_dhcp_cmds) and commits. Scoped to leases only — pool/options/ipv6
    fields of the section are untouched, so a single-lease upsert can't clobber
    them. apply=True also reloads whichever DHCP daemon is present."""
    iface = str(iface).strip()
    if not re.match(r"^[A-Za-z0-9_]+$", iface):
        raise HTTPException(400, "invalid interface name")
    s = f"dhcp.{iface}"
    lines = [
        f"uci del {s}.dhcp_host 2>/dev/null || true",
        f"uci del {s}.host 2>/dev/null || true",
    ]
    for h in (leases or []):
        name = str(h.get("name") or "").strip()
        mac = owctl.parse_mac(h.get("mac"))
        ip = str(h.get("ip") or "").strip()
        if not (name and mac and ip):
            raise HTTPException(400, f"static lease missing name/mac/ip: {h!r}")
        text = f"{name}, {mac}, {ip}"
        lines.append(f"uci add_list {s}.dhcp_host={owctl._uci_quote(text)}")
        lines.append(f"uci add_list {s}.host={owctl._uci_quote(text)}")
    lines.append("uci commit dhcp")
    if apply:
        lines.append("/etc/init.d/dnsmasq reload 2>/dev/null || /etc/init.d/odhcpd reload 2>/dev/null || true")
    return "\n".join(lines) + "\n"


def _saved_dhcp_rows(device_id):
    rows = owctl.q("SELECT * FROM dhcp WHERE device_id=? ORDER BY vlan_id", (device_id,))
    out = []
    for r in rows:
        def _load(key):
            try:
                return json.loads(r[key]) if r[key] else None
            except Exception:
                return None
        out.append({
            "vlan_id": r["vlan_id"], "iface": r["iface"], "start": r["start"], "limit": r["limit"],
            "lease_time": r["lease_time"], "enabled": bool(r["enabled"]),
            "options": _load("options"), "static_leases": _load("static_leases"),
            "subnet": (r.get("subnet") or "").strip() or None,
            "ifname": (r.get("ifname") or "").strip() or None,
        })
    return out


def _parse_uci_show(out):
    """Parse `uci show <pkg>` output into {section: {key: [values]}}. Handles list values a='x' 'y'.
    Keeps full section names (e.g., 'dhcp.lan') for reliable detection.
    Values are split via `_uci_values`, which handles quoted, bare, and list forms."""
    sections = {}
    for line in out.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        path, rest = line.split("=", 1)
        sec, _, key = path.rpartition(".")
        vals = owctl._uci_values(rest)
        if sec and key:
            sections.setdefault(sec, {}).setdefault(key, []).extend(vals)
    return sections


def _read_live_dhcp(dev):
    """Read live DHCP pool sections from UCI (odhcpd or dnsmasq), one dict per
    VLAN/interface. Returns the full per-VLAN surface: pool, network overrides,
    behavior flags, the DHCP options list (``options``), static leases
    (``static_leases``, parsed from the dnsmasq ``dhcp_host`` or odhcpd ``host``
    list), the odhcpd IPv6 keys (``ipv6``), and the subnet (``subnet`` as
    ``ipaddr/prefix`` + ``ifname``) resolved from the ``network`` package.
    ``enabled`` is derived from whether the section still looks like an active
    server (has a start address or ``dhcpv4=server``/relay)."""
    c = owctl._ssh_connect(dev)
    try:
        out, _err, _st = owctl._exec_capture(
            c, "uci show dhcp 2>/dev/null; echo; uci show network 2>/dev/null; true", timeout=30)
        sections = _parse_uci_show(out)
        # Resolve each interface's subnet from the network package. The builder
        # writes it to network.<iface>, so read it back from there; if that
        # section only carries an ifname, follow it to network.<ifname>.
        def _subnet_for(iface):
            attrs = sections.get("network." + iface) or {}
            ip = (attrs.get("ipaddr") or [None])[0]
            nm = (attrs.get("netmask") or [None])[0]
            ifname = (attrs.get("ifname") or [None])[0]
            if not (ip and nm) and ifname:
                a2 = sections.get("network." + ifname) or {}
                ip = ip or (a2.get("ipaddr") or [None])[0]
                nm = nm or (a2.get("netmask") or [None])[0]
            if ip and nm:
                try:
                    prefix = ipaddress.IPv4Network(f"0.0.0.0/{nm}").prefixlen if "." in str(nm) else int(nm)
                except (ValueError, TypeError):
                    prefix = nm
                return {"subnet": f"{ip}/{prefix}", "ifname": (ifname or "").strip() or None}
            return {"subnet": None, "ifname": (ifname or "").strip() or None}

        dhcp = []
        for name, attrs in sections.items():
            if not name.startswith("dhcp."):
                continue
            if name.startswith("dhcp.@host") or name.startswith("dhcp.@dnsmasq") or name.startswith("dhcp.@odhcpd"):
                continue
            iface = (attrs.get("interface") or [None])[0]
            if not iface:
                continue
            # A top-level ignore=1 means "don't serve this interface" (non-standard
            # but historically honored). Our options editor expresses ignored
            # client option *types* as `ignore=N` INSIDE the dhcp_option list, which
            # does not set this key, so it does not affect this check.
            if attrs.get("ignore", ["0"])[0] == "1":
                continue
            has_start = bool(attrs.get("start"))
            v4 = (attrs.get("dhcpv4") or [""])[0]
            leases = _parse_dhcp_host_list(attrs)
            ip6 = _parse_ipv6_section(attrs)
            if not has_start and v4 not in ("server", "relay") and not leases and not any(ip6.values()):
                continue  # not an active pool (e.g. a bare section)
            lease = (attrs.get("leasetime") or attrs.get("lease_time") or ["12h"])[0]

            def _first(key):
                return (attrs.get(key) or [None])[0]

            def _on(key):
                return _first(key) is not None  # a flag is "on" if the key is set

            sub = _subnet_for(iface)
            _vm = re.match(r"vlan_(\d+)$", name)
            dhcp.append({
                "vlan_id": int(_vm.group(1)) if _vm else None,
                "iface": iface,
                "enabled": bool(has_start or v4 in ("server", "relay")),
                "start": int(attrs["start"][0]) if has_start and attrs["start"][0].isdigit() else 100,
                "limit": int(attrs["limit"][0]) if attrs.get("limit") and attrs["limit"][0].isdigit() else 150,
                "lease_time": lease,
                "dhcpv4": v4 or "server",
                "netmask": _first("netmask"),
                "broadcast": _first("broadcast"),
                "local": _on("local"),
                "no_resolve": _on("no_resolve"),
                "notransfer": _on("notransfer"),
                "no_default": _on("no_default"),
                "options": list(attrs.get("dhcp_option") or []),
                "static_leases": leases,
                "ipv6": ip6,
                "subnet": sub["subnet"],
                "ifname": sub["ifname"],
            })
        return dhcp
    finally:
        c.close()


def _parse_dhcp_host_list(attrs):
    """Parse dnsmasq ``dhcp_host`` / odhcpd ``host`` list entries of the form
    ``'name, AA:BB:CC:DD:EE:FF, 192.168.10.50'`` into ``{name, mac, ip}``."""
    raw = list(attrs.get("dhcp_host") or attrs.get("host") or [])
    leases = []
    for entry in raw:
        parts = [p.strip() for p in str(entry).split(",")]
        if len(parts) >= 3:
            leases.append({"name": parts[0], "mac": parts[1], "ip": parts[2]})
        elif len(parts) >= 2:
            leases.append({"name": parts[0], "mac": parts[1], "ip": ""})
    return leases


def _parse_ipv6_section(attrs):
    """Read odhcpd IPv6 keys from a section. Missing keys stay absent so the
    dashboard can tell "not set" from "set" without guessing defaults."""
    def _first(key):
        return (attrs.get(key) or [None])[0]

    ip6 = {}
    if _first("dhcpv6"):
        ip6["dhcpv6"] = _first("dhcpv6")
    if _first("ra") is not None:
        ip6["ra"] = _first("ra") == "1"
    if _first("ra_management"):
        ip6["ra_management"] = _first("ra_management")
    if _first("ra_service") is not None:
        ip6["ra_service"] = _first("ra_service") == "1"
    if _first("ra_default_lifetime") is not None:
        ip6["ra_default_lifetime"] = _first("ra_default_lifetime")
    if _first("ra_lifetime") is not None:
        ip6["ra_lifetime"] = _first("ra_lifetime")
    return ip6
