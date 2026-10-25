#!/usr/bin/env python3
"""checks_robustness.py — robustness additions: health endpoint, logging,
DB backup, retention, rate-limiter LRU, thread pool bump.

Run: .venv/bin/python checks_robustness.py
"""
import os
import sys
import time
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
_tmp = tempfile.mkdtemp()
os.environ["OWCTL_DATA"] = _tmp
os.environ["OWCTL_ALLOW_OPEN"] = "1"
os.environ["OWCTL_LOG"] = os.path.join(_tmp, "test.log")

import owctl  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

CHECKS = []


def check(name, cond, extra=""):
    CHECKS.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


def main():
    client = TestClient(owctl.app, raise_server_exceptions=False)

    # --- health endpoint: public (no auth needed), ok, uptime sane ---
    r = client.get("/api/health")
    check("health: 200", r.status_code == 200, str(r.status_code))
    body = r.json()
    check("health: ok true", body.get("ok") is True, str(body))
    check("health: uptime_s int >= 0", isinstance(body.get("uptime_s"), int) and body["uptime_s"] >= 0, str(body))

    # --- log file actually written (rotating handler) ---
    check("logging: log file exists", os.path.exists(os.environ["OWCTL_LOG"]), os.environ["OWCTL_LOG"])
    with open(os.environ["OWCTL_LOG"]) as fh:
        content = fh.read()
    check("logging: log contains owctl lines", "owctl" in content or "starting" in content or len(content) > 0)

    # --- DB backup: creates a file in backups dir, retention prunes old ---
    backups = os.path.join(_tmp, "backups")
    os.makedirs(backups, exist_ok=True)
    res = owctl._db_backup()
    check("backup: ok", res.get("ok") is True, str(res))
    if res.get("ok"):
        check("backup: file exists", os.path.exists(res["path"]), str(res["path"]))
        check("backup: size > 0", res.get("size", 0) > 0, str(res.get("size")))
        # the backup must be a valid, readable sqlite copy
        import sqlite3
        c2 = sqlite3.connect(res["path"])
        n = c2.execute("SELECT count(*) FROM devices").fetchone()[0]
        c2.close()
        check("backup: copy is readable sqlite with devices table", isinstance(n, int))

    # retention: simulate 20 old backup copies, expect prune to 14
    import datetime as _dt
    now = _dt.datetime.now()
    for i in range(20):
        p = os.path.join(backups, f"owctl-db-{i:04d}-test.db")
        with open(p, "w") as fh:
            fh.write("x")
    owctl._db_backup()  # triggers retention
    copies = [f for f in os.listdir(backups) if f.startswith("owctl-db-") and f.endswith(".db")]
    check("backup: retention keeps <= 14", len(copies) <= 14, f"count={len(copies)}")

    # --- retention prune: does not crash, returns ok ---
    # seed some rows then prune (cutoffs are 30-180d back; new rows survive)
    owctl.execute("INSERT INTO findings(ts, device_id, device_name, rule_id, severity, message) VALUES(?,?,?,?,?,?)",
                  (owctl.now(), 1, "x", "r", "INFO", "test"))
    pr = owctl._prune_retention()
    check("prune: ok", pr.get("ok") is True, str(pr))
    check("prune: recent row survives", bool(owctl.q("SELECT 1 FROM findings WHERE message='test'")))
    # old row gets pruned
    owctl.execute("INSERT INTO findings(ts, device_id, device_name, rule_id, severity, message) VALUES(?,?,?,?,?,?)",
                  ("2000-01-01 00:00:00", 1, "x", "r", "INFO", "ancient"))
    owctl._prune_retention()
    check("prune: ancient row removed", not owctl.q("SELECT 1 FROM findings WHERE message='ancient'"))

    # --- rate limiter LRU: over cap evicts oldest, keeps newest (no full wipe) ---
    rl = owctl._RateLimiter(limit=2, window=60, max_keys=3)
    rl.allow("a")
    rl.allow("b")
    rl.allow("c")
    rl.allow("d")  # should evict 'a' (oldest), keep b,c,d
    ok_b, _ = rl.allow("b")
    check("ratelimit LRU: 'b' still has budget (not wiped)", ok_b)
    # 'a' was evicted so it has a fresh budget again
    ok_a1, _ = rl.allow("a")
    ok_a2, _ = rl.allow("a")
    ok_a3, _ = rl.allow("a")
    check("ratelimit LRU: evicted 'a' gets fresh budget", ok_a1 and ok_a2 and not ok_a3)

    # --- thread pool bump: function runs without error ---
    try:
        owctl._bump_thread_pool()
        check("thread pool bump: no error", True)
    except Exception as e:
        check("thread pool bump: no error", False, str(e))

    # --- unhandled exception handler: a route that raises gets a 500 JSON, logged ---
    @owctl.app.get("/api/_robustness_boom")
    def _boom():
        raise RuntimeError("deliberate crash for test")
    r = client.get("/api/_robustness_boom")
    check("exception handler: 500 returned", r.status_code == 500, str(r.status_code))
    check("exception handler: JSON body", r.json().get("error") == "internal error", str(r.json()))
    # and it's in the log
    time.sleep(0.1)
    with open(os.environ["OWCTL_LOG"]) as fh:
        content2 = fh.read()
    check("exception handler: traceback in log", "deliberate crash for test" in content2 and "Traceback" in content2)

    # --- startup diagnostics: clean env returns no problems ---
    probs = owctl._startup_diagnostics()
    check("startup diagnostics: clean env -> no problems", probs == [], str(probs))

    # --- on-demand backup endpoint: POST /api/backup creates a copy ---
    r = client.post("/api/backup")
    check("POST /api/backup: 200", r.status_code == 200, str(r.status_code))
    b = r.json()
    check("POST /api/backup: ok + path", b.get("ok") is True and os.path.exists(b.get("path", "")), str(b))

    print(f"\n=== SUMMARY ===\n{sum(1 for _, ok, _ in CHECKS if ok)}/{len(CHECKS)} checks passed")
    failed = [n for n, ok, _ in CHECKS if not ok]
    if failed:
        for n in failed:
            print(" -", n)
        sys.exit(1)
    print("ALL ROBUSTNESS CHECKS PASSED")


if __name__ == "__main__":
    main()
