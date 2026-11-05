"""owctl.switch"""
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

def read_switch_ports(dev):
    """Read switch-port VLAN assignments from a device. Returns
    {'name','host','switches':{'switch0':{vid:{ports,tag}}},'error'} or
    {'error':str} when the box has no switch package (e.g. wifi-only AP)."""
    if dev["access"] != "ssh":
        return {"name": dev.get("name"), "host": dev.get("host"), "switches": {},
                "error": "luci-only device skipped"}
    try:
        c = owctl._ssh_connect(dev)
        try:
            out, _e, _s = owctl._exec_capture(c, "uci show switch 2>/dev/null; true", timeout=30)
        finally:
            c.close()
        if not out.strip():
            return {"name": dev.get("name"), "host": dev.get("host"),
                    "switches": {}, "error": None}
        parsed = owctl.parse_switch_vlans(out)
        devs = sorted(set(re.findall(r"^switch\.(\w+)\.", out, re.M)))
        if devs:
            # One physical switch per device is the normal case; attribute the
            # parsed VLANs to it (a box with several switches shares the map —
            # the VLAN ids are per-device unique in practice).
            return {"name": dev.get("name"), "host": dev.get("host"),
                    "switches": {devs[0]: parsed}, "error": None}
        return {"name": dev.get("name"), "host": dev.get("host"),
                "switches": {}, "error": None}
    except Exception as e:
        return {"name": dev.get("name"), "host": dev.get("host"),
                "switches": {}, "error": str(e)}


def parse_switch_port_map(output):
    """Pure parser: {port_index: {'name':str,'up':bool}} from a normalized
    listing where each port is one line: `port <index> <name> <0|1>`.

    `index` is the switch port number (matches the numeric tokens in the UCI
    `switch.*.vlan*.ports` field, e.g. '1' or '1t'), `name` is the human
    label from sysfs (e.g. 'lan1', 'wan'), the last field is link state
    (1 = up). Returns {} when no `port` lines are present.
    """
    ports = {}
    order = []
    for line in (output or "").splitlines():
        parts = line.strip().split()
        if len(parts) < 4 or parts[0] != "port":
            continue
        try:
            idx = int(parts[1])
        except ValueError:
            continue
        name = parts[2]
        up = parts[3] == "1"
        ports[idx] = {"name": name, "up": up}
        order.append(idx)
    return {i: ports[i] for i in sorted(set(order))}


def read_switch_port_map(dev):
    """Live per-port link state keyed by switch port index. Reads the port
    name + operstate from sysfs for every port on the device's first
    switch that has a ports directory. Returns {index:{name,up}} — possibly
    empty (wifi-only box or LuCI-only access); never raises."""
    if dev["access"] != "ssh":
        return {}
    try:
        c = owctl._ssh_connect(dev)
        try:
            out, _e, _s = owctl._exec_capture(
                c,
                "sw=\"\"; for s in /sys/class/switch/switch0 /sys/class/switch/switch*; do "
                "[ -d \"$s/ports\" ] && { sw=\"$s\"; break; }; done; "
                "[ -n \"$sw\" ] || { exit 0; }; "
                "for d in \"$sw\"/ports/*/; do "
                "[ -d \"$d\" ] || continue; "
                "i=$(basename \"$d\"); [ -n \"$i\" ] || continue; "
                "n=$(cat \"$d\"/name 2>/dev/null); [ -n \"$n\" ] || n=$i; "
                "st=$(cat \"$d\"/operstate 2>/dev/null); "
                "case \"$st\" in up) v=1;; *) v=0;; esac; "
                "echo \"port $i $n $v\"; "
                "done 2>/dev/null; true",
                timeout=30)
        finally:
            c.close()
        return parse_switch_port_map(out)
    except Exception:
        return {}


def build_switch_map(assignments, status):
    """Pure: join live port->VLAN assignments with live link state into a
    per-port map.

    assignments: {vid(str): {'ports':[token,...], 'tag':int|None}} (from
        parse_switch_vlans for one switch) — tokens are '1', '2', '1t'.
    status: {idx(int): {'name':str,'up':bool}} (from parse_switch_port_map).
    Returns {idx(int): {'name':str|None,'up':bool|None,
                         'vlans':[{'id':int,'tagged':bool},...]}} covering the
        union of port indices seen in either input, sorted by index. The join
        is by numeric port index (UCI token base), which is what makes it
        correct across name/index conventions.
    """
    ports = {}
    def _port(idx):
        return ports.setdefault(idx, {
            "name": (status.get(idx) or {}).get("name"),
            "up": (status.get(idx) or {}).get("up"),
            "vlans": []})
    # Map a human port name (e.g. 'lan1','wan') to its numeric index via the
    # status lookup, so named UCI tokens and numeric ones join correctly.
    name_to_idx = {}
    for idx, s in (status or {}).items():
        nm = (s or {}).get("name")
        if nm and nm not in name_to_idx:
            name_to_idx[nm] = idx
    for vid, info in (assignments or {}).items():
        try:
            vid_i = int(vid)
        except (TypeError, ValueError):
            continue
        for tok in (info or {}).get("ports", []):
            tok = str(tok).strip()
            if not tok:
                continue
            raw = tok[:-1] if tok.endswith("t") else tok
            if raw.isdigit():
                idx = int(raw)
            else:
                idx = name_to_idx.get(raw)
                if idx is None:
                    continue  # name not found in this box's ports — skip
            # OpenWrt switch convention: a port token with the 't' suffix is a
            # TAGGED member of the VLAN; a bare token is the untagged/native
            # member. The per-token suffix is the authoritative signal.
            tagged = tok.endswith("t")
            p = _port(idx)
            if not any(v["id"] == vid_i for v in p["vlans"]):
                p["vlans"].append({"id": vid_i, "tagged": tagged})
    for idx in (status or {}):
        _port(idx)
    out = {}
    for idx in sorted(ports):
        p = ports[idx]
        p["vlans"].sort(key=lambda v: v["id"])
        out[idx] = p
    return out


def do_vlan_port(dev, switch_dev, vlan_id, ports, tag=None, apply: bool = True):
    """Assign switch ports to a VLAN in the `switch` package (the real home of
    port tagging — `network` only carries the routed interface).

    ports: list of port tokens (e.g. ['1','2'] or ['1t']). tag: int port that
    carries the native tag (rewritten as 'Nt'). Idempotent per (vlan,port).
    apply=False commits without restarting (LuCI 'Save')."""
    if dev["access"] != "ssh":
        raise HTTPException(400, "switch port config requires SSH access")
    switch_dev = (switch_dev or "switch0").strip()
    if not re.fullmatch(r"[A-Za-z0-9_\-]+", switch_dev):
        raise HTTPException(400, f"invalid switch device name {switch_dev!r}")
    vid = int(vlan_id)
    if not (1 <= vid <= 4094):
        raise HTTPException(400, f"invalid VLAN id {vid}")
    clean = []
    for p in ports or []:
        p = str(p).strip()
        if not re.fullmatch(r"\d+t?", p) or not p[:-1].isdigit():
            raise HTTPException(400, f"invalid switch port {p!r}")
        clean.append(p)
    if tag is not None and str(tag) + "t" not in clean:
        clean = [p if p != str(tag) else p + "t" for p in clean]
    if not clean:
        raise HTTPException(400, "at least one port required")
    cmd = (
        f"uci set switch.{switch_dev}.vlan{vid}='{vid}'\n"
        f"uci set switch.{switch_dev}.vlan{vid}.ports='{ ' '.join(clean) }'\n"
        "uci commit switch\n"
    )
    if apply:
        cmd += "switch reset 2>/dev/null || /etc/init.d/network restart 2>/dev/null || true\n"
    c = owctl._ssh_connect(dev)
    try:
        out, err, status = owctl._exec_capture(c, cmd, timeout=60)
        if status != 0:
            raise RuntimeError(f"switch port config failed on {dev['name']}: {(err or out).strip()[:200]}")
        owctl.log_action(dev, "vlan_port", f"switch={switch_dev} vlan={vid} ports={clean}", ok=True)
        return {"device": dev["name"], "ok": True, "switch": switch_dev, "vlan": vid, "ports": clean}
    finally:
        c.close()
