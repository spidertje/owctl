"""owctl — centralized control + threat detection for OpenWrt devices.

Modular backend. Run:  python owctl.py
"""
import base64, difflib, json, os, re, secrets, smtplib, socket, sqlite3, ssl
import threading, time, logging, sys, ipaddress, paramiko, bcrypt
import urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from email.message import EmailMessage
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# ── state / constants (package level, patchable) ──
HOST = os.environ.get("OWCTL_HOST", "0.0.0.0")

PORT = int(os.environ.get("OWCTL_PORT", "8090"))

DATA_DIR = os.environ.get("OWCTL_DATA", os.path.join(BASE, "data"))

DB_PATH = os.path.join(DATA_DIR, "owctl.db")

BACKUP_DIR = os.path.join(DATA_DIR, "backups")

LOG_PATH = os.environ.get("OWCTL_LOG", os.path.join(DATA_DIR, "owctl.log")).strip()

SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

SERVER_STARTED_AT = time.time()

_HEARTBEAT_STATE = {}  # device_id -> last known online bool

_LUCI_SCHEMES = {}

_FALLBACK_CRED_KEY = None  # in-memory key when the DB is unavailable (tests)

_PENDING_RESTARTS = {
    "firewall": "fw4 restart",
    "qos": "sqm restart",
    "dhcp": "/etc/init.d/odhcpd reload 2>/dev/null || /etc/init.d/dnsmasq reload 2>/dev/null || true",
    "dns": "/etc/init.d/dnsmasq restart 2>/dev/null || /etc/init.d/odhcpd restart 2>/dev/null || /etc/init.d/system restart 2>/dev/null || true",
    "vlan": "netifd restart 2>/dev/null || true; /etc/init.d/odhcpd reload 2>/dev/null || true; fw4 restart 2>/dev/null || true",
    "wireless": "wifi reload 2>/dev/null || true",
    # routing: static routes live in the network package (netifd applies them);
    # BGP (bird) is restarted if present. Both no-op when absent.
    "routing": "netifd restart 2>/dev/null || true; /etc/init.d/bird restart 2>/dev/null || true; ip route flush cache 2>/dev/null || true",
}

_shutdown_event = threading.Event()

_backup_lock = threading.Lock()

BACKUP_MIN_INTERVAL_S = 3600

_last_backup_at = 0.0

os.makedirs(BACKUP_DIR, exist_ok=True)
# ── app (created before routes attach) ──
def _setup_logging():
    """Persistent rotating log (DATA_DIR/owctl.log, override via OWCTL_LOG).

    Every 'owctl' log line, every unhandled-request traceback and every
    faulthandler crash dump lands in this file, so a quit is never silent.
    Falls back to console-only when the log file cannot be opened (read-only
    DATA_DIR, tests) — logging must never take the app down.
    """
    fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    handler = None
    if LOG_PATH:
        try:
            from logging.handlers import RotatingFileHandler
            handler = RotatingFileHandler(
                LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
            handler.setFormatter(fmt)
        except Exception:
            handler = None
    if handler is None:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(fmt)
    # Attach the handler to the ROOT logger. Child loggers that propagate
    # (owctl, fastapi — the defaults) flow their records here exactly once.
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    if not any(h is handler or (isinstance(h, type(handler)) and
               getattr(h, "stream", None) is getattr(handler, "stream", None))
               for h in root.handlers):
        root.addHandler(handler)
    # uvicorn configures its loggers with propagate=False, so they never reach
    # root — attach the handler to them directly (no double-emission, since they
    # don't propagate). owctl/fastapi are left to propagate to root.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.setLevel(logging.INFO)
        if not any(h is handler or (isinstance(h, type(handler)) and
                   getattr(h, "stream", None) is getattr(handler, "stream", None))
                   for h in lg.handlers):
            lg.addHandler(handler)

def _install_thread_pool_hook():
    """Lifespan context: on startup, bump the default thread pool on the LIVE
    uvicorn event loop. anyio's default thread limiter is per-event-loop — the
    old code ran _bump_thread_pool() in a throwaway asyncio.run() loop before
    uvicorn started, so the running server's pool stayed at the 40-worker
    default. Doing it here, on the actual request loop, makes the bump stick.
    """
    import contextlib

    @contextlib.asynccontextmanager
    async def _lifespan(_app):
        if _bump_thread_pool():
            logging.getLogger("owctl").info(
                "default thread pool raised to 200 on the live event loop")
        yield

    return _lifespan

import importlib as _owctl_il
import sys as _owctl_sys
_owctl_sys.modules.pop("owctl.db", None)  # fresh on reload
_dbmod = _owctl_il.import_module("owctl.db")
init_db = _dbmod.init_db
app = FastAPI(title="owctl", lifespan=_install_thread_pool_hook())
init_db()
_setup_logging()
import faulthandler
faulthandler.enable(file=sys.stderr, all_threads=True)
# ── app infrastructure (handlers, limiter, TLS) ──
@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception):
    """Last line of defense: an uncaught error in any handler becomes a
    structured 500 instead of a bare ASGI error, and the FULL traceback goes
    to the log (owctl.log) so a 'quit without a reason' is diagnosable.
    HTTPException (our own 4xx/502 responses) is left alone."""
    import traceback as _tb
    logger = logging.getLogger("owctl")
    logger.error("unhandled exception on %s %s: %s\n%s",
                 request.method, request.url.path, exc, _tb.format_exc())
    return JSONResponse({"error": "internal error", "detail": str(exc)}, status_code=500)

_RATELIMIT_MAX = int(os.environ.get("OWCTL_RATELIMIT_MAX", "120"))

_RATELIMIT_WINDOW = int(os.environ.get("OWCTL_RATELIMIT_WINDOW", "60"))

class _RateLimiter:
    """Fixed-window per-client-IP limiter. Thread-safe; in-memory (per process).

    Eviction is LRU (drop the least-recently-seen keys once the cap is hit),
    NOT a blanket clear(): a burst of distinct client IPs (CGNAT, VPNs, NAT
    ranges) used to wipe every counter at once, opening a DoS window where the
    limiter stopped limiting for everyone.
    """

    def __init__(self, limit: int, window: int, max_keys: int = 8192):
        self.limit = max(1, limit)
        self.window = max(1, window)
        self.max_keys = max(1, max_keys)
        self._hits: dict = {}
        self._lock = threading.Lock()

    def allow(self, key: str):
        """Return (allowed, retry_after_seconds)."""
        now = int(time.time())
        bucket = now // self.window
        with self._lock:
            # LRU eviction: drop the least-recently-seen keys only if we're over
            # the cap. Re-inserting on every hit reorders the dict (py3.7+), so
            # oldest keys are the ones evicted first.
            while len(self._hits) >= self.max_keys:
                self._hits.pop(next(iter(self._hits)))
            n = self._hits.get(key, 0)
            if n < self.limit:
                if key in self._hits:
                    del self._hits[key]  # re-order: updated keys move to the tail (LRU)
                self._hits[key] = n + 1
                return True, 0
        remaining = (bucket + 1) * self.window - now
        return False, max(1, remaining)

_rate_limiter = _RateLimiter(_RATELIMIT_MAX, _RATELIMIT_WINDOW)

def _client_key(request) -> str:
    # Security: key on the real TCP address, NOT X-Forwarded-For. A client can
    # send arbitrary XFF values, so trusting them lets them rotate keys past the
    # rate limiter (and >4096 keys triggers the _hits.clear() self-wipe). Behind a
    # trusted reverse proxy, request.client.host is the proxy, so opt in with
    # OWCTL_TRUST_PROXY=1 — then we take the rightmost (last-appended) hop, which
    # is the first one the proxy couldn't forge.
    if os.environ.get("OWCTL_TRUST_PROXY") == "1":
        xf = request.headers.get("x-forwarded-for", "")
        if xf:
            right = xf.rsplit(",", 1)[-1].strip()
            if right:
                return right
    return (request.client.host if request.client else "") or "unknown"

def _gen_selfsigned(cert_path: str, key_path: str) -> None:
    """Generate a self-signed TLS fallback pair (HTTPS is mandatory; this is the
    one-shot path when no CA cert is configured). Delegates to the shared
    gen_selfsigned_cert.make_cert so the SAN handling is in exactly one place.

    The SAN covers the real ways a LAN client reaches this box: 127.0.0.1, the
    configured bind host when it is a concrete IP (0.0.0.0/empty excluded), and
    the DNS names localhost / owctl / owctl.local. Before this, the inline
    generator produced a cert with NO SubjectAlternativeName at all (just a
    hardcoded CN of 192.168.55.179) — modern clients ignore the CN, so any
    verification against it failed. Replace with a CA-signed cert in production
    by setting OWCTL_SSL_CERT/KEY (or OWCTL_SSL_CN for a custom CN)."""
    import gen_selfsigned_cert as gsc
    from cryptography.hazmat.primitives import serialization

    cn = (os.environ.get("OWCTL_SSL_CN") or "").strip() or "owctl"
    ips = ["127.0.0.1"]
    host = (os.environ.get("OWCTL_HOST") or "").strip()
    if host and host not in ("0.0.0.0", "::", "[::]"):
        try:
            ipaddress.ip_address(host)  # raises ValueError for hostnames
            if host not in ips:
                ips.append(host)
        except ValueError:
            pass
    dns = ["localhost", "owctl", "owctl.local"]
    key, cert = gsc.make_cert(cn=cn, days=825, ips=ips, dns=dns)
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    os.chmod(key_path, 0o600)

def tls_kwargs():
    """TLS options for the uvicorn run, from OWCTL_SSL_CERT / OWCTL_SSL_KEY.

    HTTPS is mandatory: a cert/key pair is required. If neither is set, a
    self-signed cert is generated on first boot and stored under DATA_DIR.
    Use a CA-signed cert in production by setting OWCTL_SSL_CERT/KEY.
    """
    cert = os.environ.get("OWCTL_SSL_CERT", "").strip()
    key = os.environ.get("OWCTL_SSL_KEY", "").strip()
    if not (cert and key):
        # fall back to a generated self-signed pair in DATA_DIR
        cert = os.path.join(DATA_DIR, "cert.pem")
        key = os.path.join(DATA_DIR, "key.pem")
        if not (os.path.exists(cert) and os.path.exists(key)):
            _gen_selfsigned(cert, key)
    if not os.path.exists(cert):
        raise ValueError(f"owctl: TLS cert not found: {cert}")
    if not os.path.exists(key):
        raise ValueError(f"owctl: TLS key not found: {key}")
    return {"ssl_certfile": cert, "ssl_keyfile": key}

@app.middleware("http")
async def token_guard(request, call_next):
    # Rate limiting on the API surface (protects the token endpoint from brute force).
    # Applied regardless of auth mode so it still guards an explicitly-open instance.
    if request.url.path.startswith("/api/"):
        allowed, retry_after = _rate_limiter.allow(_client_key(request))
        if not allowed:
            return JSONResponse(
                {"error": "rate limit exceeded",
                 "retry_after": retry_after,
                 "message": f"rate limit exceeded: retry after {retry_after}s"},
                status_code=429,
                headers={"Retry-After": str(retry_after)})
    # OWCTL_ALLOW_OPEN=1 disables auth (dev/tests only). Production should leave it unset.
    if os.environ.get("OWCTL_ALLOW_OPEN") == "1":
        return await call_next(request)
    path = request.url.path
    # Documentation paths are public (Swagger UI + OpenAPI spec). Exact match only —
    # not a prefix, so /api/* still requires a session token.
    if path in ("/docs", "/docs/oauth2-redirect", "/openapi.json"):
        return await call_next(request)
    if path.startswith("/api/auth") or path == "/api/health":
        return await call_next(request)
    # Auth: password-login session token only. On first boot an `admin` account
    # is seeded with no password; its password is set at the first
    # /api/auth/login. Two roles: admin (everything) and observer (read-only).
    auth = request.headers.get("authorization", "")
    parts = auth.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        user = _session_user(parts[1].strip())
        if user:
            if user["role"] == "admin":
                return await call_next(request)
            if _observer_allowed(path, request.method):
                return await call_next(request)
            return JSONResponse({"error": "forbidden"}, status_code=403)
        if path.startswith("/api/"):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
    # No session bearer header.
    if path.startswith("/api/"):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return await call_next(request)

@app.middleware("http")
async def security_headers(request, call_next):
    """Hardening headers on every response (API + static) + audit mutating API calls."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    # Security: record mutating API requests (who/when/what, with result) for accountability.
    path = request.url.path
    if request.method in ("POST", "PUT", "DELETE", "PATCH") and path.startswith("/api/"):
        try:
            execute("INSERT INTO api_audit(ts, method, path, client, status) VALUES(?,?,?,?,?)",
                    (now(), request.method, path, _client_key(request), response.status_code))
        except Exception:
            pass  # auditing must never break the request
    return response

def _bump_thread_pool():
    """Bump anyio's default thread pool (40) to 200 — but ONLY when called
    inside a running event loop (anyio's limiter is per-loop; calling outside
    one is a safe no-op, not an error).
    Why it matters: every blocking endpoint (SSH, opkg, SMTP, urlopen) runs
    on this pool, so a fleet upgrade + scheduler audit + LAN sweep together
    can exhaust 40 workers and queue requests indefinitely (the app looks
    'dead' while still running).
    anyio 4.x API: anyio.to_thread.current_default_thread_limiter()
    (the old top-level `anyio.current_default_thread_limiter` alias no longer
    exists in 4.15 — using it raised AttributeError, which the old
    `except: pass` swallowed, making the whole function a silent no-op).
    The server actually installs this bump on its live loop via the lifespan
    hook (_install_thread_pool_hook); this function remains the single
    implementation both paths (and the robustness check) use."""
    try:
        import anyio
        try:
            lim = anyio.to_thread.current_default_thread_limiter()
        except Exception:
            return False  # not on an async loop (sync check / import) — safe no-op
        lim.total_tokens = 200
        return True
    except Exception:
        return False  # pool tuning is best-effort; never take the app down

def _startup_diagnostics():
    """Fail fast with a human-readable reason if the environment cannot serve:
    bad port, unwritable data dir, missing TLS pair, corrupt DB. Called after
    imports (DB is already initialized) and before uvicorn binds, so a bad
    start never dies with a bare traceback to an unwatched terminal."""
    logger = logging.getLogger("owctl")
    problems = []
    try:
        if not os.access(DATA_DIR, os.W_OK):
            problems.append(f"data dir not writable: {DATA_DIR} (need it for the DB, logs, backups)")
        if not q("SELECT 1"):
            problems.append("database failed a read probe")
    except Exception as e:
        problems.append(f"database probe failed: {e}")
    cert = os.environ.get("OWCTL_SSL_CERT", "").strip()
    key = os.environ.get("OWCTL_SSL_KEY", "").strip()
    if not (cert and key):
        cert = os.path.join(DATA_DIR, "cert.pem")
        key = os.path.join(DATA_DIR, "key.pem")
        if not (os.path.exists(cert) and os.path.exists(key)):
            try:
                _gen_selfsigned(cert, key)
                logger.info("generated self-signed TLS pair at %s / %s", cert, key)
            except Exception as e:
                problems.append(f"no TLS cert/key and self-signed generation failed: {e}")
    for label, path in (("cert", cert), ("key", key)):
        try:
            if os.path.exists(path) and not os.access(path, os.R_OK):
                problems.append(f"TLS {label} not readable: {path}")
        except Exception:
            pass
    return problems

def _port_in_use():
    import socket as _sk
    s = _sk.socket(_sk.AF_INET, _sk.SOCK_STREAM)
    try:
        s.bind((HOST if HOST not in ("", "0.0.0.0") else "127.0.0.1", PORT))
        return False
    except OSError:
        return True
    finally:
        s.close()

# ── re-export submodule names to the package namespace ──
import importlib as _owctl_il
import sys as _owctl_sys
_owctl_sys.modules.pop('owctl.db', None)
_dbmod = _owctl_il.import_module('owctl.db')
now = _dbmod.now
db = _dbmod.db
q = _dbmod.q
execute = _dbmod.execute
init_db = _dbmod.init_db
log_action = _dbmod.log_action
get_setting = _dbmod.get_setting
set_setting = _dbmod.set_setting
_LOCK = _dbmod._LOCK
_owctl_sys.modules.pop('owctl.auth', None)
_authmod = _owctl_il.import_module('owctl.auth')
_ROLES = _authmod._ROLES
_SESSION_TTL = _authmod._SESSION_TTL
_OBSERVER_OK_POST = _authmod._OBSERVER_OK_POST
_ADMIN_ONLY_PATHS = _authmod._ADMIN_ONLY_PATHS
_hash_password = _authmod._hash_password
_verify_password = _authmod._verify_password
ensure_admin_password = _authmod.ensure_admin_password
_user_by_id = _authmod._user_by_id
_user_by_username = _authmod._user_by_username
_create_session = _authmod._create_session
_session_user = _authmod._session_user
_purge_expired_sessions = _authmod._purge_expired_sessions
_ensure_default_admin = _authmod._ensure_default_admin
_normalize_path = _authmod._normalize_path
_ADMIN_ONLY_RE = _authmod._ADMIN_ONLY_RE
_OBSERVER_OK_RE = _authmod._OBSERVER_OK_RE
_observer_allowed = _authmod._observer_allowed
_owctl_sys.modules.pop('owctl.heartbeats', None)
_heartbeatsmod = _owctl_il.import_module('owctl.heartbeats')
record_heartbeat = _heartbeatsmod.record_heartbeat
record_status_snapshot = _heartbeatsmod.record_status_snapshot
_owctl_sys.modules.pop('owctl.ssh', None)
_sshmod = _owctl_il.import_module('owctl.ssh')
GATHER_SCRIPT = _sshmod.GATHER_SCRIPT
_parse_sections = _sshmod._parse_sections
_ssh_known_hosts_path = _sshmod._ssh_known_hosts_path
_TrustOnFirstUse = _sshmod._TrustOnFirstUse
_ssh_connect = _sshmod._ssh_connect
_exec_capture = _sshmod._exec_capture
enrich_device_error = _sshmod.enrich_device_error
_build_status = _sshmod._build_status
ssh_gather = _sshmod.ssh_gather
gather = _sshmod.gather
DDNS_PROVIDERS = _sshmod.DDNS_PROVIDERS
_owctl_sys.modules.pop('owctl.luci', None)
_lucimod = _owctl_il.import_module('owctl.luci')
_luci_schemes = _lucimod._luci_schemes
_unverified_tls_ok = _lucimod._unverified_tls_ok
_luci_rpc = _lucimod._luci_rpc
luci_gather = _lucimod.luci_gather
luci_test = _lucimod.luci_test
_owctl_sys.modules.pop('owctl.dyndns', None)
_dyndnsmod = _owctl_il.import_module('owctl.dyndns')
_ddns_apply = _dyndnsmod._ddns_apply
dyndns_update_device = _dyndnsmod.dyndns_update_device
_dyndns_pkg_for = _dyndnsmod._dyndns_pkg_for
_dyndns_ensure_pkg = _dyndnsmod._dyndns_ensure_pkg
_dyndns_maybe_remove_pkg = _dyndnsmod._dyndns_maybe_remove_pkg
_owctl_sys.modules.pop('owctl.audit', None)
_auditmod = _owctl_il.import_module('owctl.audit')
audit_status = _auditmod.audit_status
check_config_changes = _auditmod.check_config_changes
calc_health_score = _auditmod.calc_health_score
_UCI_LINE_RE = _auditmod._UCI_LINE_RE
_uci_unquote = _auditmod._uci_unquote
parse_openwrt_release = _auditmod.parse_openwrt_release
parse_uci_show = _auditmod.parse_uci_show
parse_sqm = _auditmod.parse_sqm
parse_firewall = _auditmod.parse_firewall
firewall_zone_names = _auditmod.firewall_zone_names
firewall_find_redirect = _auditmod.firewall_find_redirect
firewall_find_rule = _auditmod.firewall_find_rule
_UCI_SLUG_RE = _auditmod._UCI_SLUG_RE
_uci_slug = _auditmod._uci_slug
_uci_quote = _auditmod._uci_quote
_ENC_PREFIX = _auditmod._ENC_PREFIX
_load_cred_key = _auditmod._load_cred_key
_store_device_cred = _auditmod._store_device_cred
_stored_device_cred = _auditmod._stored_device_cred
_uci_values = _auditmod._uci_values
_uci_list_values = _auditmod._uci_list_values
build_wifi_clone_cmds = _auditmod.build_wifi_clone_cmds
_parse_subnet = _auditmod._parse_subnet
build_dhcp_cmds = _auditmod.build_dhcp_cmds
build_dhcp_apply_cmds = _auditmod.build_dhcp_apply_cmds
build_dns_cmds = _auditmod.build_dns_cmds
_fw_commit = _auditmod._fw_commit
record_pending_apply = _auditmod.record_pending_apply
clear_pending_apply = _auditmod.clear_pending_apply
pending_apply_for = _auditmod.pending_apply_for
record_vlan_membership = _auditmod.record_vlan_membership
set_pending = _auditmod.set_pending
apply_pending_for = _auditmod.apply_pending_for
_run_ssh = _auditmod._run_ssh
ensure_pkg = _auditmod.ensure_pkg
do_qos = _auditmod.do_qos
do_fw_forward = _auditmod.do_fw_forward
do_fw_rule = _auditmod.do_fw_rule
do_zone_policy = _auditmod.do_zone_policy
delete_fw_rule = _auditmod.delete_fw_rule
delete_fw_forward = _auditmod.delete_fw_forward
apply_findings = _auditmod.apply_findings
_owctl_sys.modules.pop('owctl.alerting', None)
_alertingmod = _owctl_il.import_module('owctl.alerting')
DEFAULT_ALERTS = _alertingmod.DEFAULT_ALERTS
get_alert_cfg = _alertingmod.get_alert_cfg
set_alert_cfg = _alertingmod.set_alert_cfg
fire_alert = _alertingmod.fire_alert
build_digest = _alertingmod.build_digest
_owctl_sys.modules.pop('owctl.digest', None)
_digestmod = _owctl_il.import_module('owctl.digest')
digest_schedule = _digestmod.digest_schedule
digest_should_fire = _digestmod.digest_should_fire
send_digest = _digestmod.send_digest
_DIGEST_CADENCES = _digestmod._DIGEST_CADENCES
_owctl_sys.modules.pop('owctl.sweep', None)
_sweepmod = _owctl_il.import_module('owctl.sweep')
parse_spec = _sweepmod.parse_spec
_probe = _sweepmod._probe
run_sweep = _sweepmod.run_sweep
_owctl_sys.modules.pop('owctl.operations', None)
_operationsmod = _owctl_il.import_module('owctl.operations')
ensure_server_key = _operationsmod.ensure_server_key
_key_pub_line = _operationsmod._key_pub_line
ssh_test = _operationsmod.ssh_test
luci_test = _operationsmod.luci_test
push_ssh_key = _operationsmod.push_ssh_key
do_backup = _operationsmod.do_backup
_resolve_backup_path = _operationsmod._resolve_backup_path
do_restore = _operationsmod.do_restore
vlan_delete_cmds = _operationsmod.vlan_delete_cmds
delete_vlan_membership = _operationsmod.delete_vlan_membership
do_rebaseline = _operationsmod.do_rebaseline
do_vlan = _operationsmod.do_vlan
do_vlan_delete = _operationsmod.do_vlan_delete
_owctl_sys.modules.pop('owctl.routing', None)
_routingmod = _owctl_il.import_module('owctl.routing')
_IP4 = _routingmod._IP4
_valid_ip4 = _routingmod._valid_ip4
_valid_cidr = _routingmod._valid_cidr
_route_iface = _routingmod._route_iface
_primary_routed_iface = _routingmod._primary_routed_iface
resolve_via = _routingmod.resolve_via
parse_routing = _routingmod.parse_routing
parse_ip_route = _routingmod.parse_ip_route
parse_bgp_config = _routingmod.parse_bgp_config
build_route_cmds = _routingmod.build_route_cmds
build_policy_route_cmds = _routingmod.build_policy_route_cmds
build_bgp_cmds = _routingmod.build_bgp_cmds
_bgp_pkg_present = _routingmod._bgp_pkg_present
read_routing = _routingmod.read_routing
_split_sections = _routingmod._split_sections
parse_ip_rule = _routingmod.parse_ip_rule
_record_route_realization = _routingmod._record_route_realization
do_route = _routingmod.do_route
do_route_delete = _routingmod.do_route_delete
_resolve_concrete_via = _routingmod._resolve_concrete_via
do_policy_route = _routingmod.do_policy_route
do_bgp = _routingmod.do_bgp
parse_mac = _routingmod.parse_mac
lease_key = _routingmod.lease_key
merge_leases = _routingmod.merge_leases
remove_leases = _routingmod.remove_leases
validate_reservation = _routingmod.validate_reservation
merge_known_devices = _routingmod.merge_known_devices
vlan_members = _routingmod.vlan_members
do_mesh = _routingmod.do_mesh
do_guest_wifi = _routingmod.do_guest_wifi
do_upgrade = _routingmod.do_upgrade
do_reboot = _routingmod.do_reboot
check_device = _routingmod.check_device
_owctl_sys.modules.pop('owctl.dhcp', None)
_dhcpmod = _owctl_il.import_module('owctl.dhcp')
parse_dhcp_leases = _dhcpmod.parse_dhcp_leases
read_arp_neighbors = _dhcpmod.read_arp_neighbors
build_lease_cmds = _dhcpmod.build_lease_cmds
_saved_dhcp_rows = _dhcpmod._saved_dhcp_rows
_parse_uci_show = _dhcpmod._parse_uci_show
_read_live_dhcp = _dhcpmod._read_live_dhcp
_parse_dhcp_host_list = _dhcpmod._parse_dhcp_host_list
_parse_ipv6_section = _dhcpmod._parse_ipv6_section
_owctl_sys.modules.pop('owctl.dns', None)
_dnsmod = _owctl_il.import_module('owctl.dns')
_saved_dns_rows = _dnsmod._saved_dns_rows
_read_live_dns = _dnsmod._read_live_dns
_owctl_sys.modules.pop('owctl.qos', None)
_qosmod = _owctl_il.import_module('owctl.qos')
_read_live_qos = _qosmod._read_live_qos
_read_live_firewall = _qosmod._read_live_firewall
_saved_qos_row = _qosmod._saved_qos_row
_saved_fw_rows = _qosmod._saved_fw_rows
_owctl_sys.modules.pop('owctl.vlan', None)
_vlanmod = _owctl_il.import_module('owctl.vlan')
parse_vlan_ids = _vlanmod.parse_vlan_ids
parse_switch_vlans = _vlanmod.parse_switch_vlans
netmask_to_prefix = _vlanmod.netmask_to_prefix
parse_vlan_details = _vlanmod.parse_vlan_details
discover_vlans = _vlanmod.discover_vlans
read_vlan_state = _vlanmod.read_vlan_state
_upsert_discovered_vlan = _vlanmod._upsert_discovered_vlan
_owctl_sys.modules.pop('owctl.switch', None)
_switchmod = _owctl_il.import_module('owctl.switch')
read_switch_ports = _switchmod.read_switch_ports
parse_switch_port_map = _switchmod.parse_switch_port_map
read_switch_port_map = _switchmod.read_switch_port_map
build_switch_map = _switchmod.build_switch_map
do_vlan_port = _switchmod.do_vlan_port
_owctl_sys.modules.pop('owctl.wifi', None)
_wifimod = _owctl_il.import_module('owctl.wifi')
_parse_wifi_ifaces = _wifimod._parse_wifi_ifaces
_wifi_radios = _wifimod._wifi_radios
_parse_wifi_radios = _wifimod._parse_wifi_radios
_owctl_sys.modules.pop('owctl.maintenance', None)
_maintenancemod = _owctl_il.import_module('owctl.maintenance')
_prune_backup_copies = _maintenancemod._prune_backup_copies
_db_backup = _maintenancemod._db_backup
_prune_retention = _maintenancemod._prune_retention
_owctl_sys.modules.pop('owctl.scheduler', None)
_schedulermod = _owctl_il.import_module('owctl.scheduler')
_scheduler = _schedulermod._scheduler
_owctl_sys.modules.pop('owctl.routes', None)
_routesmod = _owctl_il.import_module('owctl.routes')
api_health = _routesmod.api_health
pending_apply = _routesmod.pending_apply
pending_applies_list = _routesmod.pending_applies_list
pending_all = _routesmod.pending_all
pending_apply_all = _routesmod.pending_apply_all
compare_device_drift = _routesmod.compare_device_drift
drift_report = _routesmod.drift_report
_ver_key = _routesmod._ver_key
rebaseline_preview = _routesmod.rebaseline_preview
rebaseline_apply = _routesmod.rebaseline_apply
index = _routesmod.index
list_devices = _routesmod.list_devices
network_overview = _routesmod.network_overview
add_device = _routesmod.add_device
update_device = _routesmod.update_device
delete_device = _routesmod.delete_device
device_check = _routesmod.device_check
device_test = _routesmod.device_test
device_push_key = _routesmod.device_push_key
device_backup = _routesmod.device_backup
device_restore = _routesmod.device_restore
apply_vlan = _routesmod.apply_vlan
read_vlan_state_endpoint = _routesmod.read_vlan_state_endpoint
delete_vlan = _routesmod.delete_vlan
read_routing_endpoint = _routesmod.read_routing_endpoint
add_route_endpoint = _routesmod.add_route_endpoint
delete_route_endpoint = _routesmod.delete_route_endpoint
policy_route_endpoint = _routesmod.policy_route_endpoint
bgp_endpoint = _routesmod.bgp_endpoint
fleet_routes = _routesmod.fleet_routes
fleet_routes_apply = _routesmod.fleet_routes_apply
fleet_routes_delete = _routesmod.fleet_routes_delete
apply_dhcp = _routesmod.apply_dhcp
dhcp_read = _routesmod.dhcp_read
get_dhcp_leases = _routesmod.get_dhcp_leases
dhcp_known_devices = _routesmod.dhcp_known_devices
dhcp_reserve = _routesmod.dhcp_reserve
apply_dns = _routesmod.apply_dns
dns_read = _routesmod.dns_read
list_vlans = _routesmod.list_vlans
_require_device = _routesmod._require_device
qos_read = _routesmod.qos_read
qos_apply = _routesmod.qos_apply
firewall_read = _routesmod.firewall_read
firewall_apply = _routesmod.firewall_apply
firewall_delete_rule = _routesmod.firewall_delete_rule
firewall_delete_forward = _routesmod.firewall_delete_forward
discover_vlans_endpoint = _routesmod.discover_vlans_endpoint
get_switch_ports = _routesmod.get_switch_ports
apply_switch_ports = _routesmod.apply_switch_ports
switch_map = _routesmod.switch_map
get_device_packages = _routesmod.get_device_packages
fleet_packages = _routesmod.fleet_packages
fleet_upgrade = _routesmod.fleet_upgrade
remove_packages = _routesmod.remove_packages
device_guest_wifi = _routesmod.device_guest_wifi
get_wifi_config = _routesmod.get_wifi_config
wifi_clone = _routesmod.wifi_clone
device_mesh = _routesmod.device_mesh
get_mesh_config = _routesmod.get_mesh_config
device_upgrade = _routesmod.device_upgrade
diff_snapshots = _routesmod.diff_snapshots
get_config_history = _routesmod.get_config_history
get_traffic_history = _routesmod.get_traffic_history
get_bandwidth = _routesmod.get_bandwidth
bulk_actions = _routesmod.bulk_actions
get_device_logs = _routesmod.get_device_logs
device_reboot = _routesmod.device_reboot
sweep = _routesmod.sweep
findings = _routesmod.findings
ack_finding = _routesmod.ack_finding
alerts_get = _routesmod.alerts_get
alerts_put = _routesmod.alerts_put
alerts_log = _routesmod.alerts_log
api_digest = _routesmod.api_digest
backups = _routesmod.backups
backup_now = _routesmod.backup_now
actions = _routesmod.actions
settings_get = _routesmod.settings_get
auth_status = _routesmod.auth_status
auth_setup = _routesmod.auth_setup
auth_login = _routesmod.auth_login
auth_logout = _routesmod.auth_logout
users_list = _routesmod.users_list
users_create = _routesmod.users_create
users_update = _routesmod.users_update
users_delete = _routesmod.users_delete
auth_me = _routesmod.auth_me
users_me_password_change = _routesmod.users_me_password_change
settings_put = _routesmod.settings_put
api_audit = _routesmod.api_audit
get_device_heartbeat = _routesmod.get_device_heartbeat
get_uptime = _routesmod.get_uptime
get_offline_events = _routesmod.get_offline_events
dyndns_read = _routesmod.dyndns_read
dyndns_create = _routesmod.dyndns_create
dyndns_delete = _routesmod.dyndns_delete
dyndns_force = _routesmod.dyndns_force
# ── static mount ──
app.mount("/static", StaticFiles(directory=os.path.join(BASE, "static")), name="static")
# ── entrypoint ──

def main():
    import sys, signal, uvicorn
    import owctl as _ow
    logger = logging.getLogger("owctl")
    def _on_signal(sig, frame):
        logger.info("received signal %s — shutting down", signal.Signals(sig).name)
        _ow._shutdown_event.set()
    try:
        signal.signal(signal.SIGTERM, _on_signal); signal.signal(signal.SIGINT, _on_signal)
    except Exception:
        pass
    problems = _startup_diagnostics()
    if problems:
        for p in problems: logger.error("startup blocked: %s", p)
        for p in problems: print(f"owctl: STARTUP FAILED — {p}", file=sys.stderr)
        sys.exit(2)
    if _port_in_use():
        msg = f"port {PORT} is already in use (host {HOST})"
        logger.error(msg); print(f"owctl: STARTUP FAILED — {msg}", file=sys.stderr); sys.exit(3)
    threading.Thread(target=_scheduler, daemon=True, name="owctl-scheduler").start()
    _ensure_default_admin()
    _bump_thread_pool()
    _tls = tls_kwargs()
    _scheme = "https" if _tls else "http"
    logger.info("starting owctl: %s://%s:%s%s — log: %s", _scheme, HOST, PORT,
                " (TLS)" if _tls else "", LOG_PATH or "(console only)")
    print(f"owctl: {_scheme}://{HOST}:{PORT}" + (f" (TLS, log: {LOG_PATH})" if _tls else f" (log: {LOG_PATH})"))
    try:
        uvicorn.run(app, host=HOST, port=PORT, log_level="info", limit_concurrency=1000, **_tls)
    except KeyboardInterrupt:
        logger.info("interrupted — exiting")
    except Exception as e:
        logger.error("server crashed: %s", e, exc_info=True)
        print(f"owctl: SERVER CRASHED — {e} (see {LOG_PATH})", file=sys.stderr); sys.exit(4)
    finally:
        _ow._shutdown_event.set(); logger.info("owctl stopped")
