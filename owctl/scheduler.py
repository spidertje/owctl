"""owctl.scheduler"""
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

def _scheduler():
    """Background loop: digest, DB backup, retention, device audits.

    Every cycle logs a line (start/finish, device counts, failures) so a
    stalled or dead scheduler is visible in owctl.log instead of silent.
    Exits promptly on _shutdown_event (SIGTERM/Ctrl-C).
    """
    logger = logging.getLogger("owctl")
    cycle = 0
    while not owctl._shutdown_event.is_set():
        cycle += 1
        logger.info("scheduler cycle %d: starting (audit + maintenance)", cycle)
        # 1) digest scheduling (daily|weekly|never). The digest CONTENT is
        #    untouched — build_digest + send_digest are the same path the
        #    manual POST /api/digest uses. Wrapped so a failure never raises
        #    into the scheduler loop.
        try:
            cadence = owctl.digest_schedule()
            if cadence != "never":
                last = int(owctl.get_setting("digest_last_sent", "0") or "0")
                if owctl.digest_should_fire(cadence, last):
                    try:
                        owctl.send_digest()
                    except Exception as e:
                        logger.warning("scheduled digest failed: %s", e)
                    owctl.set_setting("digest_last_sent", str(int(time.time())))
        except Exception as e:
            logger.warning("digest check failed: %s", e)
        # 2) maintenance: DB backup + retention, every cycle
        owctl._db_backup()
        owctl._prune_retention()
        # 3) audit loop (sleep in small chunks so shutdown stays responsive)
        try:
            interval_min = max(5, int(owctl.get_setting("audit_interval_min", "30") or 30))
        except Exception:
            interval_min = 30
        slept = 0
        while slept < interval_min * 60 and not owctl._shutdown_event.is_set():
            time.sleep(min(5, interval_min * 60 - slept))
            slept += 5
        if owctl._shutdown_event.is_set():
            logger.info("scheduler: shutdown requested, exiting loop")
            break
        online = offline = errors = 0
        for dev in owctl.q("SELECT * FROM devices WHERE access IN ('ssh','luci')"):
            try:
                st = owctl.gather(dev)
                owctl.record_heartbeat(dev, True)
                owctl.execute("UPDATE devices SET status='online', last_checked=? WHERE id=?", (owctl.now(), dev["id"]))
                owctl.apply_findings(dev, st)
                owctl._ddns_apply(dev, st)
                online += 1
            except Exception as e:
                owctl.record_heartbeat(dev, False)
                owctl.execute("UPDATE devices SET status='offline' WHERE id=?", (dev["id"],))
                offline += 1
                logger.info("audit: %s (%s) failed: %s", dev.get("name"), dev.get("host"), e)
        logger.info("scheduler cycle %d: audit done — %d online, %d offline", cycle, online, offline)
    logger.info("scheduler stopped (cycle %d)", cycle)
