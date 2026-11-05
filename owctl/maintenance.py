"""owctl.maintenance"""
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

def _prune_backup_copies():
    """Keep only the 14 newest DB snapshot copies; delete the rest. Cheap
    (listdir + unlink) and runs on every backup cycle — even when the
    snapshot itself is throttled — so the dir never grows unbounded."""
    removed = 0
    copies = sorted(
        (os.path.join(owctl.BACKUP_DIR, f) for f in os.listdir(owctl.BACKUP_DIR)
         if f.startswith("owctl-db-") and f.endswith(".db")),
        key=os.path.getmtime, reverse=True)
    for old in copies[14:]:
        try:
            os.remove(old)
            removed += 1
        except OSError:
            pass
    return removed


def _db_backup(force=False):
    """Snapshot the live sqlite DB to BACKUP_DIR/owctl-db-<ts>.db via VACUUM INTO
    (a consistent, self-contained copy even while the server runs). Keeps the 14
    newest; older copies are deleted. Never raises — a failed backup must not
    break the scheduler; the error is logged and returned in the result dict.
    The scheduler calls it without `force`; to bound write amplification and
    preserve a meaningful retention window, scheduler-driven snapshots are
    throttled to one per BACKUP_MIN_INTERVAL_S (1h) — the old 'every cycle'
    call (default 30 min) filled the 14-copy retention in ~7h. Retention
    pruning still runs on every call (it is cheap); `force=True` (manual
    /api/backup) always takes a snapshot immediately."""
    logger = logging.getLogger("owctl")
    if not force:
        if time.time() - owctl._last_backup_at < owctl.BACKUP_MIN_INTERVAL_S:
            try:
                removed = _prune_backup_copies()
            except Exception:
                removed = 0
            return {"ok": True, "skipped": True, "pruned": removed,
                    "reason": f"last backup {int(time.time() - owctl._last_backup_at)}s ago (< {owctl.BACKUP_MIN_INTERVAL_S}s); manual /api/backup bypasses"}
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(owctl.BACKUP_DIR, f"owctl-db-{ts}.db")
    if not owctl._backup_lock.acquire(blocking=False):
        return {"ok": False, "reason": "another backup in progress"}
    try:
        # VACUUM INTO needs a dedicated connection with no open transaction.
        try:
            os.remove(dest)
        except OSError:
            pass
        src = sqlite3.connect(owctl.DB_PATH)
        try:
            src.execute("VACUUM INTO ?", (dest,))
            src.commit()
        finally:
            src.close()
        size = os.path.getsize(dest)
        # retention: keep the 14 newest copies
        removed = 0
        try:
            removed = _prune_backup_copies()
        except Exception:
            removed = 0
        logger.info("db backup: %s (%.1f KB, %d pruned)",
                    os.path.basename(dest), size / 1024, removed)
        owctl._last_backup_at = time.time()
        return {"ok": True, "path": dest, "size": size, "pruned": removed}
    except Exception as e:
        logger.error("db backup failed: %s", e)
        try:
            os.remove(dest)
        except OSError:
            pass
        return {"ok": False, "reason": str(e)}
    finally:
        owctl._backup_lock.release()


def _prune_retention():
    """Bound the unbounded tables (findings, api_audit, config_history,
    device_heartbeats, owctl_actions). Runs in the scheduler loop; a failed
    prune is logged and swallowed — housekeeping must never kill the loop.
    ts columns store UTC 'YYYY-MM-DD HH:MM:SS.mmm' strings, so lexicographic
    comparison against a UTC cutoff is correct.
    """
    logger = logging.getLogger("owctl")
    try:
        from datetime import timedelta
        pruned = {}
        for table, keep_days in (("findings", 120), ("api_audit", 90),
                                 ("config_history", 180), ("device_heartbeats", 30),
                                 ("owctl_actions", 180)):
            cut = (datetime.now(timezone.utc) - timedelta(days=keep_days)).strftime("%Y-%m-%d %H:%M:%S")
            owctl.execute(f"DELETE FROM {table} WHERE ts < ?", (cut,))
            pruned[table] = keep_days
        logger.info("retention prune done (keep: %s)",
                    ", ".join(f"{k} {v}d" for k, v in pruned.items()))
        return {"ok": True, "keep_days": pruned}
    except Exception as e:
        logger.warning("retention prune failed: %s", e)
        return {"ok": False, "reason": str(e)}
