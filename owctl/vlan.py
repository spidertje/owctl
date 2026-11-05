"""owctl.vlan"""
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

def parse_vlan_ids(output):
    """Extract VLAN ids from `uci show network` output. Pure + testable.

    Matches both switch VLAN sections (`... .vlan='2'`) and bridge-tag
    interfaces (`... .vlan='10'` on a network section). Returns a sorted,
    de-duplicated list of positive ints.
    """
    ids = set()
    for m in re.finditer(r"\.vlan='?(\d+)'?", output or ""):
        try:
            v = int(m.group(1))
            if v > 0:
                ids.add(v)
        except ValueError:
            pass
    return sorted(ids)


def parse_switch_vlans(output):
    """Pure parser: map VLAN id -> {ports:[str], tag:int|None} from `uci show switch`.

    OpenWrt switch-port VLANs live in the `switch` package, not `network`:
    ``switch.switch0.vlan2='2'`` and ``switch.switch0.vlan2.ports='1 2'``
    (tag is a value suffix, e.g. ``1t``, or its own ``tag`` option).
    """
    vlans = {}
    for line in (output or "").splitlines():
        line = line.strip()
        m = re.match(r"^switch\.\w+\.vlan(\d+)='?(\d+)'?$", line)
        if m:
            vlans.setdefault(m.group(1), {"ports": [], "tag": None})
            continue
        m = re.match(r"^switch\.\w+\.vlan(\d+)\.ports='?([^']*)'?$", line)
        if m and m.group(1) in vlans:
            ports = (m.group(2) or "").split()
            for p in ports:
                if p.endswith("t") and p[:-1].isdigit():
                    vlans[m.group(1)]["tag"] = int(p[:-1])
                vlans[m.group(1)]["ports"].append(p)
            continue
        m = re.match(r"^switch\.\w+\.vlan(\d+)\.tag='?(\d+)'?$", line)
        if m and m.group(1) in vlans:
            vlans[m.group(1)]["tag"] = int(m.group(2))
    return vlans


def netmask_to_prefix(mask):
    """'255.255.255.0' -> 24. Returns None on garbage input."""
    try:
        parts = [int(x) for x in (mask or "").split(".")]
        if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
            return None
        bits = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
        return bin(bits).count("1")
    except Exception:
        return None


def parse_vlan_details(network_out, dhcp_out=""):
    """Pure parser: map VLAN id -> {'subnet': 'a.b.c.0/N'|None, 'dhcp': bool}.

    A VLAN-bound interface is a `network.<x>=interface` section carrying
    `.vlan='<id>'`. Its subnet is derived from `.ipaddr` + `.netmask` when
    present (ip network address + netmask prefix). dhcp=True when a
    `dhcp.<y>.interface='<x>'` section references it.
    """
    sections = {}
    for line in (network_out or "").splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^network\.([A-Za-z0-9_]+)=(\w+)$", line)
        if m:
            if m.group(2) == "interface":
                sections.setdefault(m.group(1), {})
            continue
        m = re.match(r"^network\.([A-Za-z0-9_]+)\.(\w+)='?([^']*)'?$", line)
        if m and m.group(1) in sections:
            sections[m.group(1)][m.group(2)] = m.group(3)
    dhcp_ifaces = set()
    for line in (dhcp_out or "").splitlines():
        m = re.match(r"^dhcp\.[A-Za-z0-9_]+\.interface='?([^' ]*)'?$", line.strip())
        if m:
            dhcp_ifaces.add(m.group(1))
    details = {}
    for name, a in sections.items():
        vid = (a.get("vlan") or "").strip()
        if not vid.isdigit():
            continue
        vid = int(vid)
        if vid <= 0:
            continue
        subnet = None
        ip = (a.get("ipaddr") or "").strip().strip("'")
        mask = (a.get("netmask") or "").strip().strip("'")
        if ip and mask:
            pref = netmask_to_prefix(mask)
            if pref:
                import ipaddress
                try:
                    subnet = str(ipaddress.ip_network(f"{ip}/{pref}", strict=False))
                except Exception:
                    subnet = None
        details[vid] = {"subnet": subnet, "dhcp": name in dhcp_ifaces}
    return details


def discover_vlans(dev):
    """Read configured VLANs + their subnet/dhcp from a device over SSH.

    Runs `uci show network` and `uci show dhcp`, then maps each VLAN id to
    {'subnet','dhcp'}. Returns {'name','host','vlans':[int],
    'details':{int:{'subnet','dhcp'}}, 'error':None} or {'error': str}.
    """
    if dev["access"] != "ssh":
        return {"name": dev.get("name"), "host": dev["host"], "vlans": [],
                "details": {}, "error": "luci-only device skipped"}
    try:
        c = owctl._ssh_connect(dev)
        try:
            net, _e1, _s1 = owctl._exec_capture(c, "uci show network 2>/dev/null", timeout=30)
            dhc, _e2, _s2 = owctl._exec_capture(c, "uci show dhcp 2>/dev/null", timeout=30)
        finally:
            c.close()
        details = parse_vlan_details(net, dhc)
        all_ids = sorted(set(parse_vlan_ids(net)) | set(details.keys()))
        return {"name": dev.get("name"), "host": dev["host"],
                "vlans": all_ids, "details": details, "error": None}
    except Exception as e:
        return {"name": dev.get("name"), "host": dev["host"], "vlans": [],
                "details": {}, "error": str(e)}


def read_vlan_state(dev, vlan_id):
    """Read the live state of one VLAN on a device (edit prefill + verification).

    Reuses the pure parsers: `parse_vlan_details` for the routed interface's
    subnet + DHCP flag, `parse_firewall` for the zone policy. Returns
    {'name','host','subnet','dhcp','zone':{input,output,forward}|None,'error'}
    — 'error' only on SSH failure, not when the VLAN simply isn't configured.
    """
    if dev["access"] != "ssh":
        return {"name": dev.get("name"), "host": dev.get("host"), "error":
                "luci-only device skipped"}
    try:
        c = owctl._ssh_connect(dev)
        try:
            net, _e1, _s1 = owctl._exec_capture(c, "uci show network 2>/dev/null", timeout=30)
            dhc, _e2, _s2 = owctl._exec_capture(c, "uci show dhcp 2>/dev/null", timeout=30)
            fw, _e3, _s3 = owctl._exec_capture(c, "uci show firewall 2>/dev/null", timeout=30)
        finally:
            c.close()
        vid = str(vlan_id)
        det = parse_vlan_details(net, dhc).get(int(vlan_id)) or {}
        zone = None
        parsed_fw = owctl.parse_firewall(fw)
        want_name = f"vlan_{vid}"
        for z in parsed_fw.get("zones", []):
            if z.get("name") == want_name or z.get("network") == want_name:
                zone = {"input": z.get("input"), "output": z.get("output"),
                        "forward": z.get("forward")}
                break
        return {"name": dev.get("name"), "host": dev.get("host"),
                "vlan_id": vid, "subnet": det.get("subnet"),
                "dhcp": bool(det.get("dhcp")), "zone": zone, "error": None}
    except Exception as e:
        return {"name": dev.get("name"), "host": dev.get("host"),
                "vlan_id": str(vlan_id), "error": str(e)}


def _upsert_discovered_vlan(vlan_id, name, subnet, dhcp):
    """Insert a discovered VLAN without clobbering fields already set by an apply."""
    owctl.execute("INSERT INTO vlans(vlan_id, name, subnet, dhcp, created_at) VALUES(?,?,?,?,?) "
            "ON CONFLICT(vlan_id) DO UPDATE SET "
            "name=COALESCE(excluded.name, vlans.name), "
            "subnet=COALESCE(excluded.subnet, vlans.subnet), "
            "dhcp=COALESCE(excluded.dhcp, vlans.dhcp) ",
            (str(vlan_id), name, subnet, dhcp, owctl.now()))
