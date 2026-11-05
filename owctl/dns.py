"""owctl.dns"""
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

def _saved_dns_rows(device_id):
    rows = owctl.q("SELECT * FROM dns WHERE device_id=?", (device_id,))
    if rows:
        r = rows[0]
        return {
            "servers": (r["servers"] or "").split(",") if r["servers"] else [],
            "search_domains": (r["search_domains"] or "").split(",") if r["search_domains"] else [],
            "scope": r.get("scope") or "dhcp",
        }
    return {"servers": [], "search_domains": [], "scope": "dhcp"}


def _read_live_dns(dev):
    """Read live DNS config from UCI, split by scope.

    Returns ``{"dhcp": {...}, "router": {...}, "resolver": <backend>}`` so the
    dashboard can show the two independently. ``dhcp`` is the DNS delivered to
    clients (odhcpd option-6 or dnsmasq server list); ``router`` is the box's
    own resolver (``system.@dns[0]``), which is what ``/etc/resolv.conf`` is
    built from. Either side may be empty/absent — that is a valid state.
    """
    c = owctl._ssh_connect(dev)
    try:
        out, _err, _st = owctl._exec_capture(
            c, "uci show dhcp 2>/dev/null; echo; uci show system 2>/dev/null; true", timeout=30)
        sections = owctl._parse_uci_show(out)
        dhcp_servers = []
        dhcp_search = []
        resolver = None

        # odhcpd: DNS is delivered via DHCP option 6 (`dhcp-option=6,<ip>`).
        # Bare `6,<addr>` values are IPv6 RA-DNS and must NOT be read as IPv4 servers.
        for sec, attrs in sections.items():
            if sec == "dhcp.lan" or sec.startswith("dhcp.lan.") or re.match(r"^dhcp\.vlan_", sec):
                for v in attrs.get("dhcp_option", []):
                    if v.startswith("dhcp-option=6,"):
                        dhcp_servers.extend(x for x in v.split(",")[1:] if x)
                        resolver = "odhcpd"
                for d in attrs.get("search", []):
                    dhcp_search.append(d)

        # backend detection for the return value
        backend = "odhcpd" if re.search(r"^dhcp\.\w+\.dhcpv4='?server'?$", out, re.M) else "dnsmasq"
        # dnsmasq block (only inspect if no odhcpd resolver found, so stale
        # blocks don't leak through as the live resolver)
        if not resolver:
            for sec, attrs in sections.items():
                if sec.startswith("dhcp.@dnsmasq") and "server" in attrs:
                    dhcp_servers.extend(attrs["server"])
                    resolver = "dnsmasq"
                if sec.startswith("dhcp.@dnsmasq") and "search" in attrs:
                    dhcp_search.extend(attrs["search"])

        # Router's own resolver: system.@dns[0] is the source for
        # /etc/resolv.conf. Independent of the DHCP backend.
        router_servers = []
        router_search = []
        dns_sec = sections.get("system.@dns[0]")
        if isinstance(dns_sec, dict):
            router_servers = list(dns_sec.get("server") or [])
            router_search = list(dns_sec.get("search") or [])

        def _dedupe(items):
            seen, out = set(), []
            for s in items:
                s = str(s).strip()
                if s and s not in seen:
                    seen.add(s)
                    out.append(s)
            return out

        return {
            "dhcp": {"servers": _dedupe(dhcp_servers), "search_domains": _dedupe(dhcp_search)},
            "router": {"servers": _dedupe(router_servers), "search_domains": _dedupe(router_search)},
            "resolver": resolver or backend,
        }
    finally:
        c.close()
