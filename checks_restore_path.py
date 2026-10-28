#!/usr/bin/env python3
"""checks_restore_path.py — do_restore path-confainment regression guard.

Contract (audit P0): do_restore used to open/push an arbitrary server-side file
path supplied by the client. After the fix, _resolve_backup_path confines the
path to BACKUP_DIR (resolving symlinks and `..`), so /etc/shadow, ../etc/passwd,
and symlink escapes are all rejected.

Self-contained: throwaway OWCTL_DATA, reloads the app. Exits non-zero on failure.
Run: .venv/bin/python checks_restore_path.py
"""
import os
os.environ["OWCTL_DATA"] = "/tmp/owctl-restore-path-" + str(os.getpid())
os.makedirs(os.environ["OWCTL_DATA"], exist_ok=True)
os.environ["OWCTL_ALLOW_OPEN"] = "1"
import importlib, sys, tempfile
import owctl
importlib.reload(owctl)

passed = failed = 0
def check(name, cond, extra=""):
    global passed, failed
    if cond: passed += 1; print("PASS", name)
    else: failed += 1; print("FAIL", name, (f"[{extra}]" if extra else ""))

from starlette.exceptions import HTTPException
root = os.path.realpath(owctl.BACKUP_DIR)

# a legit backup inside BACKUP_DIR
good = os.path.join(root, "router-2026.conf")
with open(good, "w") as f:
    f.write("config system\n\toption hostname router\n")
# a secret OUTSIDE BACKUP_DIR (the thing a path traversal would grab)
secret = os.path.join(tempfile.mkdtemp(prefix="rsec-"), "secret.txt")
with open(secret, "w") as f:
    f.write("TOP-SECRET")

def code(fn):
    try:
        fn(); return 200
    except HTTPException as e:
        return e.status_code

# 1. legit path inside BACKUP_DIR -> accepted, returns the safe absolute path
r = owctl._resolve_backup_path(good)
check("backup inside dir accepted", r == good, r)

# relative path is anchored at BACKUP_DIR
rel = os.path.basename(good)
r2 = owctl._resolve_backup_path(rel)
check("relative path anchored at BACKUP_DIR", r2 == good, r2)

# 2. absolute path OUTSIDE -> 400
check("absolute path outside dir -> 400", code(lambda: owctl._resolve_backup_path(secret)) == 400)
check("/etc/shadow -> 400", code(lambda: owctl._resolve_backup_path("/etc/shadow")) == 400)

# 3. `..` traversal -> 400
check("../ escape -> 400", code(lambda: owctl._resolve_backup_path(os.path.join(root, "..", os.path.basename(secret)))) == 400)

# 4. symlink pointing out of BACKUP_DIR -> 400
link = os.path.join(root, "escape-link")
if os.path.lexists(link):
    os.remove(link)
os.symlink(secret, link)
check("symlink escaping dir -> 400", code(lambda: owctl._resolve_backup_path(link)) == 400)

# 5. nonexistent -> 404 ; empty -> 400
check("nonexistent backup -> 404", code(lambda: owctl._resolve_backup_path(os.path.join(root, "nope.conf"))) == 404)
check("empty path -> 400", code(lambda: owctl._resolve_backup_path("")) == 400)

# 6. do_restore rejects an outside path BEFORE touching SSH (device access=ssh,
#    but no SSH server exists at 127.0.0.1:1 — if it tried to connect we'd get
#    a timeout, not a clean 400; a clean 400 proves the path check came first)
dev = {"id": 1, "name": "r1", "host": "127.0.0.1", "access": "ssh"}
check("do_restore outside path -> 400 (before SSH)", code(lambda: owctl.do_restore(dev, secret)) == 400)
check("do_restore /etc/shadow -> 400 (before SSH)", code(lambda: owctl.do_restore(dev, "/etc/shadow")) == 400)

print(f"\n=== SUMMARY ===\n{passed}/{passed+failed} checks passed")
print("ALL RESTORE-PATH CHECKS PASSED" if failed == 0 else "SOME CHECKS FAILED")
os.system(f"rm -rf {os.environ['OWCTL_DATA']}")
sys.exit(1 if failed else 0)
