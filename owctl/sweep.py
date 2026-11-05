"""owctl.sweep"""
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

def parse_spec(spec):
    import ipaddress
    ips = []
    for part in re.split(r"[,\s]+", (spec or "").strip()):
        if not part:
            continue
        if "/" in part:
            for ip in ipaddress.ip_network(part, strict=False):
                if not ip.is_loopback:
                    ips.append(str(ip))
        elif re.fullmatch(r"[\d.]+-[\d.]+", part):
            a, b = part.split("-")
            a4, b4 = a.split("."), b.split(".")
            if len(a4) == len(b4) == 4 and a4[:3] == b4[:3]:
                for i in range(int(a4[3]), int(b4[3]) + 1):
                    ips.append(f"{a4[0]}.{a4[1]}.{a4[2]}.{i}")
        elif re.fullmatch(r"[\d.]+", part):
            ips.append(part)
    seen, out = set(), []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out[:4096]


def _probe(ip):
    res = {"host": ip, "ports": [], "hints": [], "likely_openwrt": False}
    for p in (22, 80, 443, 8080):
        try:
            with socket.create_connection((ip, p), timeout=1.0):
                res["ports"].append(p)
        except Exception:
            pass
    if 22 in res["ports"]:
        try:
            s = socket.create_connection((ip, 22), timeout=2)
            s.settimeout(2)
            banner = s.recv(120).decode(errors="replace").strip()
            s.close()
            res["hints"].append("ssh:" + (banner or "?"))
            if "openwrt" in banner.lower():
                res["likely_openwrt"] = True
        except Exception:
            pass
    http_port = 80 if 80 in res["ports"] else (443 if 443 in res["ports"] else None)
    if http_port:
        try:
            scheme = "http" if http_port == 80 else "https"
            req = urllib.request.Request(f"{scheme}://{ip}/", headers={"User-Agent": "owctl-sweep"})
            if owctl._unverified_tls_ok(ip):
                # private/loopback sweep targets keep unverified TLS (self-signed)
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            else:
                # public IP: verified chain required (fail closed on rejection)
                ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=3, context=ctx) as r:
                head = r.read(1024).decode(errors="replace").lower()
                res["hints"].append("http:" + (r.headers.get("Server") or "no-server-header"))
                if "luci" in head or "openwrt" in head:
                    res["likely_openwrt"] = True
        except Exception:
            pass
    return res


def run_sweep(spec):
    ips = parse_spec(spec)
    if not ips:
        raise RuntimeError("no valid addresses in sweep spec (try 192.168.1.0/24 or 192.168.1.1-192.168.1.250)")
    out = []
    with ThreadPoolExecutor(max_workers=64) as ex:
        futs = {ex.submit(_probe, ip): ip for ip in ips}
        for fu in as_completed(futs, timeout=max(60, len(ips))):
            try:
                r = fu.result(timeout=15)
                if r["ports"]:
                    out.append(r)
            except Exception:
                pass
    try:
        import ipaddress
        out.sort(key=lambda x: int(ipaddress.ip_address(x["host"])))
    except Exception:
        pass
    return {"requested": len(ips), "found": len(out),
            "openwrt": [c["host"] for c in out if c["likely_openwrt"]],
            "candidates": out}
