"""owctl.luci"""
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

def _luci_schemes(host):
    """Which LuCI scheme(s) to try for a host: probe 443 then 80, cache the result."""
    if host in owctl._LUCI_SCHEMES:
        return owctl._LUCI_SCHEMES[host]
    open_schemes = []
    for scheme, port in (("https", 443), ("http", 80)):
        try:
            with socket.create_connection((host, port), timeout=3):
                open_schemes.append(scheme)
        except Exception:
            pass
    owctl._LUCI_SCHEMES[host] = open_schemes or ["https", "http"]
    return owctl._LUCI_SCHEMES[host]


def _unverified_tls_ok(host) -> bool:
    """Whether unverified (self-signed) TLS is acceptable for an outbound
    connection to `host`.

    Loopback / private / link-local targets (the normal case — self-signed
    OpenWrt boxes on the LAN) keep CERT_NONE, because demanding a real
    certificate chain would break every stock device. A host that is a public
    IP literal, or that resolves to a public address, demands VERIFIED TLS
    (chain + hostname): owctl should not talk unverified-TLS to the open
    internet — that path is how a misconfigured (or DNS-rebound) host gets
    its device session MITM'd. Unresolvable hosts fail closed (verify).
    """
    def _ok_ip(ip):
        return ip.is_private or ip.is_loopback or ip.is_link_local
    try:
        return _ok_ip(ipaddress.ip_address(host))
    except ValueError:
        pass  # not an IP literal — check the resolved address(es)
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False  # unresolvable -> require verification (fail closed)
    for _fam, _ty, _proto, _canon, sa in infos:
        try:
            ip = ipaddress.ip_address(sa[0])
        except ValueError:
            return False
        if not _ok_ip(ip):
            return False
    return True


def _luci_rpc(dev, method, obj=None, args=None):
    """Call a LuCI RPC method. NOTE: the endpoint is /rpc (NOT /cgi-bin/luci/rpc)."""
    user = dev.get("luci_user") or "root"
    pw = owctl._stored_device_cred(dev.get("luci_pass") or "")
    port = dev.get("luci_port")
    base = f"{dev['host']}:{port}" if port else dev["host"]
    body = json.dumps({"method": "call", "params": ["luci.rpc", method, obj or "", args or []],
                       "id": 1}).encode()
    auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()
    last = None
    for scheme in _luci_schemes(base):
        req = urllib.request.Request(
            f"{scheme}://{base}/rpc", data=body, method="POST",
            headers={"Content-Type": "application/json", "Authorization": auth})
        try:
            if scheme == "https":
                host_only = (dev.get("host") or "").split(":")[0]
                if _unverified_tls_ok(host_only):
                    # self-signed LAN device — the normal case, keep unverified
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                else:
                    # public / unresolvable host — demand a verified chain
                    ctx = ssl.create_default_context()
                r = urllib.request.urlopen(req, timeout=15, context=ctx)
            else:
                r = urllib.request.urlopen(req, timeout=15)
            with r:
                data = json.loads(r.read().decode())
            if data.get("error"):
                raise RuntimeError(f"LuCI rpc {method}: {data['error']}")
            return data.get("payload")
        except Exception as e:
            last = e
    raise last or RuntimeError("LuCI unreachable")


def luci_gather(dev):
    st = {"backend": "luci", "online": True, "host": dev["host"], "name": dev["name"]}
    try:
        si = _luci_rpc(dev, "luci.sys.sysinfo") or {}
        st["model"] = si.get("model", "")
        st["firmware"] = f"OpenWrt {si.get('firmware', '')}"
        st["hostname"] = si.get("hostname", "")
    except Exception as e:
        raise RuntimeError(f"LuCI sysinfo failed: {e}")
    try:
        stt = _luci_rpc(dev, "luci.sys.status") or {}
        st["uptime_s"] = int(stt.get("uptime") or 0)
        st["load"] = (stt.get("load") or "").split()
        mem = stt.get("mem") or {}
        st["mem_total_kb"] = int(mem.get("total") or 0)
        st["mem_free_kb"] = int(mem.get("free") or 0)
        wan = (stt.get("net") or {}).get("wan") or {}
        st["wan_up"] = bool(wan.get("up"))
        v4 = wan.get("ipv4") or []
        st["wan_ip"] = (v4[0].get("address", "") if v4 else "")
    except Exception:
        pass
    try:
        st["clients"] = int((_luci_rpc(dev, "luci.devices") or {}).get("clients") or 0)
    except Exception:
        st["clients"] = None
    try:
        su = _luci_rpc(dev, "luci.sys.sysupgrade") or {}
        st["sysupgrade_available"] = bool(su.get("available"))
        st["latest"] = su.get("latest_version", "")
    except Exception:
        st["sysupgrade_available"] = None
    try:
        st["upgradable"] = [
            {"pkg": p.get("pkg"), "installed": p.get("installed"), "available": p.get("available")}
            for p in (_luci_rpc(dev, "luci.opkg.upgradable") or []) if isinstance(p, dict)
        ]
    except Exception:
        st["upgradable"] = []
    st["telnet_on"] = None
    st["ntp"] = ""
    st["listeners"] = []
    st["device_date"] = ""
    try:
        cfg = _luci_rpc(dev, "luci.config.get", "firewall", []) or {}
        fw = cfg.get("firewall", cfg) if isinstance(cfg, dict) else {}
        d = fw.get("defaults") if isinstance(fw, dict) else None
        d = d[0] if isinstance(d, list) and d else (d if isinstance(d, dict) else {})
        st["fw_in"] = d.get("input", "")
        st["fw_fwd"] = d.get("forward", "")
        st["fw_out"] = d.get("output", "")
        r = (fw or {}).get("redirect") or []
        if isinstance(r, dict):
            r = [r]
        reds = []
        for i, rr in enumerate(r):
            if isinstance(rr, dict) and rr.get("dest_port"):
                reds.append({"name": rr.get("name") or f"redirect[{i}]", "dest_port": rr.get("dest_port")})
        st["redirects"] = reds
    except Exception:
        st["fw_in"] = ""
        st["redirects"] = []
    return st


def luci_test(dev):
    try:
        si = _luci_rpc(dev, "luci.sys.sysinfo") or {}
        detail = f"{si.get('model', '')} {si.get('firmware', '')}".strip()
        return {"ok": True, "detail": (detail or "connected")[:200]}
    except Exception as e:
        return {"ok": False, "detail": str(e)}
