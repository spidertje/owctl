"""owctl.db"""
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

def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


_LOCK = threading.Lock()


def db():
    # WAL: readers no longer block on the single writer (the global _LOCK is
    # owctl-internal; WAL also protects against concurrent sqlite access from
    # outside, e.g. a backup tool or a second reader). busy_timeout: a locked
    # DB waits instead of raising 'database is locked' (500 / crash at boot).
    c = sqlite3.connect(owctl.DB_PATH, check_same_thread=False, timeout=10)
    try:
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA busy_timeout=10000")
    except sqlite3.OperationalError:
        pass  # WAL can fail on some filesystems; the DB still works in rollback mode
    c.row_factory = sqlite3.Row
    return c


def q(sql, args=()):
    with _LOCK:
        c = db()
        rows = [dict(r) for r in c.execute(sql, args).fetchall()]
        c.commit()
        c.close()
        return rows


def execute(sql, args=()):
    with _LOCK:
        c = db()
        last = c.execute(sql, args).lastrowid
        c.commit()
        c.close()
        return last


def init_db():
    execute("""CREATE TABLE IF NOT EXISTS devices(
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, host TEXT UNIQUE, role TEXT,
        access TEXT, ssh_port INTEGER, ssh_user TEXT, ssh_password TEXT, key_path TEXT,
        luci_user TEXT, luci_pass TEXT, status TEXT DEFAULT 'unknown',
        last_checked TEXT, added_at TEXT, tags TEXT)""")
    try:
        execute("ALTER TABLE devices ADD COLUMN luci_port INTEGER")
    except sqlite3.OperationalError:
        pass
    try:
        execute("ALTER TABLE devices ADD COLUMN health_score INTEGER")
    except sqlite3.OperationalError:
        pass
    # Users + roles. ponytail: two roles only — admin (everything) and
    # observer (read-only). Per-device ACLs are overkill for a 2-box LAN;
    # upgrade by adding a `device_acl(user_id, device_id)` join table.
    execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'observer',
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        last_login TEXT)""")
    execute("""CREATE TABLE IF NOT EXISTS sessions(
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        created REAL NOT NULL,
        exp REAL NOT NULL)""")
    execute("""CREATE TABLE IF NOT EXISTS config_hashes(
        id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER, ts TEXT,
        hash TEXT, UNIQUE(device_id, ts))""")
    execute("""CREATE TABLE IF NOT EXISTS findings(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, device_id INTEGER, device_name TEXT,
        rule_id TEXT, severity TEXT, message TEXT, detail TEXT, rec TEXT)""")
    execute("""CREATE TABLE IF NOT EXISTS active_findings(
        device_id INTEGER, rule_id TEXT, severity TEXT, message TEXT, detail TEXT, rec TEXT, ts TEXT,
        PRIMARY KEY(device_id, rule_id))""")
    execute("""CREATE TABLE IF NOT EXISTS alert_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, device TEXT, severity TEXT, rule_id TEXT,
        message TEXT, channels TEXT)""")
    execute("""CREATE TABLE IF NOT EXISTS log_entries(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, device_id INTEGER, device_name TEXT,
        facility TEXT, severity TEXT, message TEXT)""")
    execute("""CREATE TABLE IF NOT EXISTS backups(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, device_id INTEGER, device_name TEXT,
        kind TEXT, path TEXT, size INTEGER)""")
    execute("""CREATE TABLE IF NOT EXISTS config_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER, ts TEXT, hash TEXT)""")
    execute("""CREATE TABLE IF NOT EXISTS traffic_samples(
        id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER, ts TEXT,
        iface TEXT, rx_bytes INTEGER, tx_bytes INTEGER)""")
    execute("""CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT)""")
    execute("""CREATE TABLE IF NOT EXISTS device_heartbeats(
        id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER, ts TEXT, online INTEGER)""")
    execute("""CREATE TABLE IF NOT EXISTS offline_events(
        id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER, device_name TEXT,
        went_offline TEXT, went_online TEXT, offline_seconds INTEGER DEFAULT NULL)""")
    execute("""CREATE TABLE IF NOT EXISTS owctl_actions(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, device_id INTEGER, device_name TEXT,
        action TEXT, detail TEXT, result TEXT, error TEXT)""")
    execute("""CREATE TABLE IF NOT EXISTS api_audit(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, method TEXT, path TEXT,
        client TEXT, status INTEGER)""")
    execute("""CREATE TABLE IF NOT EXISTS vlans(
        vlan_id TEXT PRIMARY KEY, name TEXT, subnet TEXT, dhcp INTEGER, created_at TEXT)""")
    execute("""CREATE TABLE IF NOT EXISTS dhcp(
        device_id INTEGER, vlan_id TEXT, iface TEXT, start INTEGER, "limit" INTEGER,
        lease_time TEXT, enabled INTEGER, ts TEXT,
        options TEXT, static_leases TEXT, subnet TEXT, ifname TEXT,
        PRIMARY KEY(device_id, vlan_id))""")
    execute("""CREATE TABLE IF NOT EXISTS dns(
        device_id INTEGER PRIMARY KEY, servers TEXT, search_domains TEXT, scope TEXT, ts TEXT)""")
    try:
        execute("ALTER TABLE dns ADD COLUMN scope TEXT")
    except sqlite3.OperationalError:
        pass
    # ponytail: one row per (device, provider, hostname). Credentials live next to
    # device creds in the same DB; the API never returns them (see dyndns_read).
    execute("""CREATE TABLE IF NOT EXISTS dyndns(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
        provider TEXT NOT NULL, hostname TEXT NOT NULL,
        token TEXT, extra TEXT, enabled INTEGER DEFAULT 1,
        last_ip TEXT, last_update TEXT, last_result TEXT,
        UNIQUE(device_id, provider, hostname))""")
    execute("""CREATE TABLE IF NOT EXISTS qos(
        device_id INTEGER PRIMARY KEY, enabled INTEGER, interface TEXT,
        download_kbps INTEGER, upload_kbps INTEGER, qdisc TEXT, ecn INTEGER, ts TEXT)""")
    execute("""CREATE TABLE IF NOT EXISTS fw_rules(
        id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER, kind TEXT, name TEXT,
        proto TEXT, src_dport INTEGER, dest_ip TEXT, dest_port INTEGER,
        src_zone TEXT, dst_zone TEXT, target TEXT, ts TEXT,
        UNIQUE(device_id, kind, name))""")
    execute("""CREATE TABLE IF NOT EXISTS device_status(
        id INTEGER PRIMARY KEY AUTOINCREMENT, device_id INTEGER UNIQUE, ts TEXT,
        clients INTEGER, uptime_s INTEGER, firmware TEXT, rx_bytes INTEGER, tx_bytes INTEGER)""")
    execute("""CREATE TABLE IF NOT EXISTS pending_applies(
        device_id INTEGER, feature TEXT, restart_cmd TEXT, saved_at TEXT,
        PRIMARY KEY(device_id, feature))""")
    # Which device carries each VLAN and in what role (routed on the router,
    # tagged on a switch). Recorded on apply; union of members drives the
    # "one network" per-VLAN view.
    execute("""CREATE TABLE IF NOT EXISTS vlans_devices(
        vlan_id TEXT, device_id INTEGER, role TEXT,
        PRIMARY KEY(vlan_id, device_id))""")
    # ---- Routing (logical "one network" object, realized on devices) ----
    # A route is one logical network fact (dst + via + metric), NOT a per-device
    # row. `via` is either a concrete IPv4 gateway or a LOGICAL reference
    # "vlan:<id>" (resolved to that VLAN's gateway at apply time — see
    # resolve_via). `policy` distinguishes plain unicast routing ("default")
    # from policy-routing table entries ("table:<name>"). Per-device
    # realization (applied/pending/failed) lives in routes_devices, mirroring
    # vlans_devices so the "one network" endpoints can show a union view.
    execute("""CREATE TABLE IF NOT EXISTS routes(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        dst TEXT NOT NULL, via TEXT NOT NULL, metric INTEGER,
        policy TEXT DEFAULT 'default',
        note TEXT, created_at TEXT,
        UNIQUE(dst, via, policy))""")
    execute("""CREATE TABLE IF NOT EXISTS routes_devices(
        route_id INTEGER, device_id INTEGER, state TEXT,
        PRIMARY KEY(route_id, device_id))""")
    for _col, _typ in (("installed_pkgs", "TEXT"), ("obsolete_pkgs", "TEXT"), ("meshd", "TEXT"), ("upgradable_pkgs", "TEXT")):
        try:
            execute(f"ALTER TABLE device_status ADD COLUMN {_col} {_typ}")
        except sqlite3.OperationalError:
            pass
    # Idempotent migration for databases created before the full per-VLAN DHCP
    # surface (options + static leases JSON + subnet/ifname) existed.
    for _col in ("options", "static_leases", "subnet", "ifname"):
        try:
            execute(f"ALTER TABLE dhcp ADD COLUMN {_col} TEXT")
        except sqlite3.OperationalError:
            pass
    # Idempotent migration for databases created before wifi_capable existed.
    try:
        execute("ALTER TABLE device_status ADD COLUMN wifi_capable INTEGER")
    except sqlite3.OperationalError:
        pass
    # Idempotent migration for firmware_info column.
    try:
        execute("ALTER TABLE device_status ADD COLUMN firmware_info TEXT")
    except sqlite3.OperationalError:
        pass
    # Idempotent migration for databases created before the tags column existed.
    try:
        execute("ALTER TABLE devices ADD COLUMN tags TEXT")
    except sqlite3.OperationalError:
        pass
    # Role normalization: roles are the lowercase enum router/ap/switch/other.
    # Idempotent migration for any rows added before this code shipped.
    try:
        execute("UPDATE devices SET role=lower(role) WHERE role IS NOT NULL AND role != lower(role)")
    except sqlite3.OperationalError:
        pass
    # Hot-path indexes (idempotent): findings/heartbeats/status lookups by
    # device, and the retention prunes' ts scans. CREATE TABLE above already
    # covers PRIMARY KEY/PK cases, so only plain single-column helpers here.
    for _idx in (
        "CREATE INDEX IF NOT EXISTS idx_findings_device_id ON findings(device_id)",
        "CREATE INDEX IF NOT EXISTS idx_findings_ts ON findings(ts)",
        "CREATE INDEX IF NOT EXISTS idx_api_audit_ts ON api_audit(ts)",
        "CREATE INDEX IF NOT EXISTS idx_traffic_device_ts ON traffic_samples(device_id, ts)",
        "CREATE INDEX IF NOT EXISTS idx_heartbeats_device_ts ON device_heartbeats(device_id, ts)",
        "CREATE INDEX IF NOT EXISTS idx_offline_device_ts ON offline_events(device_id, went_offline)",
        "CREATE INDEX IF NOT EXISTS idx_config_history_device_ts ON config_history(device_id, ts)",
        "CREATE INDEX IF NOT EXISTS idx_actions_ts ON owctl_actions(ts)",
    ):
        try:
            execute(_idx)
        except sqlite3.OperationalError:
            pass  # corrupt index state must never block startup; tables still work


def log_action(device, action, detail='', ok=None, error=''):
    """Insert an audit-log row for a mutating operation. Never raises — logging
    must not break the operation it is recording."""
    try:
        dev_id = None
        dev_name = None
        if isinstance(device, dict):
            dev_id = device.get('id')
            dev_name = device.get('name')
        execute(
            "INSERT INTO owctl_actions(ts, device_id, device_name, action, detail, result, error) "
            "VALUES(?,?,?,?,?,?,?)",
            (now(), dev_id, dev_name, action, detail, 'ok' if ok else 'failed', error or ''))
    except Exception:
        pass


def get_setting(k, d=None):
    r = q("SELECT value FROM settings WHERE key=?", (k,))
    return r[0]["value"] if r else d


def set_setting(k, v):
    execute("INSERT INTO settings(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, str(v)))
