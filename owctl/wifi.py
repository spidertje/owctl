"""owctl.wifi"""
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

def _parse_wifi_ifaces(show_out):
    """Parse `uci show wireless` into radios {name: band} and iface list.
    Pure + testable. Band comes from .band= (2g/5g/6g) or .hwmode= legacy.

    Radio sections and wifi-iface sections are tracked as separate sets so a
    radio attribute (e.g. `radio0.type`) is never mistaken for an iface option
    (which would otherwise clobber the iface's `device` field and lose its band)."""
    radios, ifaces = {}, []
    radio_names, iface_names = set(), set()
    for line in (show_out or "").splitlines():
        line = line.strip()
        m = re.match(r"wireless\.([A-Za-z0-9_]+)=wifi-device$", line)
        if m:
            name = m.group(1)
            radios.setdefault(name, {})
            radio_names.add(name)
            continue
        m = re.match(r"wireless\.([A-Za-z0-9_]+)=wifi-iface$", line)
        if m:
            iface_names.add(m.group(1))
            ifaces.append({"name": m.group(1), "device": None, "ssid": "", "encryption": "",
                           "has_key": False, "key": "", "network": "", "mode": ""})
            continue
        m = re.match(r"wireless\.([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)='?(.*?)'?$", line)
        if not m:
            continue
        name, key, val = m.group(1), m.group(2), m.group(3)
        if name in radio_names:
            if key in ("band", "hwmode", "channel", "htmode"):
                radios[name][key] = val
        elif name in iface_names:
            for i in ifaces:
                if i["name"] == name:
                    if key == "key":
                        i["has_key"] = bool(val)
                        i["key"] = val
                    elif key in ("device", "ssid", "encryption", "network", "mode"):
                        i[key] = val
                    break
    band = {}
    for r, a in radios.items():
        b = a.get("band") or {"11g": "2g", "11a": "5g", "11ad": "60g"}.get(a.get("hwmode", ""), "")
        band[r] = b
    for i in ifaces:
        i["band"] = band.get(i["device"] or "", "")
    return ifaces


def _wifi_radios(dev):
    """Return {radio_name: band} for a device (SSH)."""
    c = owctl._ssh_connect(dev)
    try:
        out, _e, _s = owctl._exec_capture(c, "uci show wireless 2>/dev/null", timeout=10)
        return {r: a.get("band") or a.get("hwmode", "")
                for r, a in _parse_wifi_radios(out).items()}
    finally:
        c.close()


def _parse_wifi_radios(show_out):
    radios = {}
    for line in (show_out or "").splitlines():
        line = line.strip()
        m = re.match(r"wireless\.([A-Za-z0-9_]+)=wifi-device$", line)
        if m:
            radios.setdefault(m.group(1), {})
            continue
        m = re.match(r"wireless\.([A-Za-z0-9_]+)\.(band|hwmode)='?(.*?)'?$", line)
        if m and m.group(1) in radios:
            radios[m.group(1)][m.group(2)] = m.group(3)
    return radios
