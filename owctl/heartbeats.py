"""owctl.heartbeats"""
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

def record_heartbeat(device_row, online_bool):
    """Insert a heartbeat row and maintain offline-event transitions.

    online->offline: open an offline_event (went_offline=now()).
    offline->online: close the most recent open event for that device
    (went_online=now(), offline_seconds = elapsed seconds).
    First observation for a device: heartbeat only, no event.
    Never raises.
    """
    try:
        did = device_row["id"]
        ts = owctl.now()
        owctl.execute("INSERT INTO device_heartbeats(device_id, ts, online) VALUES(?,?,?)",
                (did, ts, 1 if online_bool else 0))
        prev = owctl._HEARTBEAT_STATE.get(did)
        if prev is None:
            owctl._HEARTBEAT_STATE[did] = online_bool
            return
        if prev and not online_bool:
            # online -> offline transition
            owctl.execute(
                "INSERT INTO offline_events(device_id, device_name, went_offline) VALUES(?,?,?)",
                (did, device_row.get("name"), ts))
        elif not prev and online_bool:
            # offline -> online transition: close the most recent open event
            rows = owctl.q("SELECT id, went_offline FROM offline_events "
                     "WHERE device_id=? AND went_online IS NULL "
                     "ORDER BY id DESC LIMIT 1", (did,))
            if rows:
                ev = rows[0]
                try:
                    t_off = datetime.fromisoformat(ev["went_offline"])
                    secs = max(0, int((datetime.fromisoformat(ts.replace(" ", "T"))
                                       - t_off).total_seconds()))
                except Exception:
                    secs = None
                owctl.execute("UPDATE offline_events SET went_online=?, offline_seconds=? WHERE id=?",
                        (ts, secs, ev["id"]))
        owctl._HEARTBEAT_STATE[did] = online_bool
    except Exception as e:
        try:
            import logging
            logging.getLogger("owctl").warning("record_heartbeat failed: %s", e)
        except Exception:
            pass


def record_status_snapshot(dev_row, st):
    """Upsert one device_status row from the status dict `st` built by check_device.

    Keys read: st.get('clients'), st.get('uptime_s'), st.get('firmware');
    rx_bytes/tx_bytes = sum over (st.get('traffic') or {}).values() of the
    per-interface rx/tx counters when present. Only writes a column when its
    source is not None. Never raises — like record_heartbeat.
    """
    try:
        traffic = st.get("traffic") or {}
        rx_bytes = sum(int(v.get("rx", 0) or 0) for v in traffic.values() if isinstance(v, dict))
        tx_bytes = sum(int(v.get("tx", 0) or 0) for v in traffic.values() if isinstance(v, dict))
        wifi_capable = 1 if st.get("wifi_capable") else (0 if st.get("wifi_capable") is False else None)
        cols = ["device_id", "ts", "clients", "uptime_s", "firmware", "rx_bytes", "tx_bytes", "wifi_capable"]
        vals = [dev_row["id"], owctl.now(),
                st.get("clients"), st.get("uptime_s"), st.get("firmware"),
                rx_bytes if traffic else None, tx_bytes if traffic else None,
                wifi_capable]
        # Packages + mesh: JSON-encoded so the same row carries the full
        # software inventory. Only written when the gather script produced
        # data (None stays NULL, never an empty string).
        import json as _json
        installed = st.get("installed")
        obsolete = st.get("obsolete")
        meshd = st.get("meshd")
        upgradable = st.get("upgradable")
        if installed is not None or obsolete is not None or meshd is not None or upgradable is not None:
            cols += ["installed_pkgs", "obsolete_pkgs", "meshd", "upgradable_pkgs"]
            vals += [_json.dumps(installed or []), _json.dumps(obsolete or []), meshd,
                     _json.dumps(upgradable or [])]
        # firmware_info: JSON-encoded dict from parse_openwrt_release
        firmware_info = st.get("firmware_info")
        if firmware_info is not None and isinstance(firmware_info, dict) and firmware_info:
            cols += ["firmware_info"]
            vals += [_json.dumps(firmware_info)]
        # Null-safe: only write a column when its source is present.
        set_clause = ", ".join(
            f"{c}=excluded.{c}" for c, v in zip(cols, vals) if v is not None
        )
        if not set_clause:
            return
        placeholders = ", ".join("?" * len(cols))
        owctl.execute(
            f"INSERT INTO device_status({', '.join(cols)}) VALUES({placeholders}) "
            f"ON CONFLICT(device_id) DO UPDATE SET {set_clause}",
            tuple(vals))
    except Exception:
        pass
