"""owctl.qos"""
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

def _read_live_qos(dev):
    """Read the live QoS config from the box (sqm, then nft-qos). None when unconfigured."""
    c = owctl._ssh_connect(dev)
    try:
        out, _err, _st = owctl._exec_capture(c, "uci show sqm 2>/dev/null; true", timeout=30)
        res = owctl.parse_sqm(out)
        if res is None:
            out2, _e2, _s2 = owctl._exec_capture(c, "uci show nft-qos 2>/dev/null; true", timeout=30)
            res = owctl.parse_sqm(out2)
        return res
    finally:
        c.close()


def _read_live_firewall(dev):
    """Read the live firewall config from the box."""
    c = owctl._ssh_connect(dev)
    try:
        out, _err, _st = owctl._exec_capture(c, "uci show firewall 2>/dev/null; true", timeout=30)
        return owctl.parse_firewall(out)
    finally:
        c.close()


def _saved_qos_row(dev_id):
    rows = owctl.q("SELECT * FROM qos WHERE device_id=?", (dev_id,))
    if not rows:
        return None
    r = rows[0]
    return {"enabled": bool(r["enabled"]), "interface": r["interface"],
            "download_kbps": r["download_kbps"], "upload_kbps": r["upload_kbps"],
            "qdisc": r["qdisc"], "ecn": bool(r["ecn"]), "ts": r["ts"]}


def _saved_fw_rows(dev_id):
    rows = owctl.q("SELECT * FROM fw_rules WHERE device_id=? ORDER BY kind, name", (dev_id,))
    return {"forwards": [r for r in rows if r["kind"] == "forward"],
            "rules": [r for r in rows if r["kind"] == "rule"]}
