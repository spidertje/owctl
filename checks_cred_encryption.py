#!/usr/bin/env python3
"""checks_cred_encryption.py — device credentials are encrypted at rest.

Contract (audit P2, MED): device SSH/LuCI passwords were stored PLAINTEXT in
owctl.db. They are now AES-256-GCM encrypted before write (prefix 'enc.v1.'),
and decrypted transparently on the two consumption paths (SSH connect, LuCI
RPC). This check proves, without a live device:
  - add_device stores an ENCRYPTED blob (plaintext NOT in the DB);
  - the stored value decrypts back to the exact plaintext (round-trip);
  - a legacy PLAINTEXT row (inserted before this feature) still reads back
    correctly via _stored_device_cred (backward compat);
  - update keep-empty keeps the stored secret; a new value overwrites it;
  - OWCTL_CRED_KEY env key is honored (explicit key material).
Run: .venv/bin/python checks_cred_encryption.py
"""
import os, sys, base64, secrets, tempfile

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
os.environ["OWCTL_DATA"] = tempfile.mkdtemp()
os.environ["OWCTL_ALLOW_OPEN"] = "1"
# deterministic explicit key so round-trip is stable across calls
os.environ["OWCTL_CRED_KEY"] = base64.b64encode(secrets.token_bytes(32)).decode()

import owctl  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

FAILS = 0
def check(name, ok, detail=""):
    global FAILS
    if not ok:
        FAILS += 1
    print(("PASS " if ok else "FAIL ") + name + (f" :: {detail}" if detail and not ok else ""))

client = TestClient(owctl.app)
owctl.init_db()

# 1) add_device stores an encrypted blob, not plaintext
r = client.post("/api/devices", json={
    "name": "r1", "host": "192.168.1.10", "access": "ssh",
    "ssh_user": "root", "ssh_password": "hunter2",
    "luci_user": "root", "luci_pass": "lucipw"})
check("add_device: 200", r.status_code == 200, r.text[:200])
row = owctl.q("SELECT ssh_password, luci_pass FROM devices WHERE host='192.168.1.10'")
ssh_stored, luci_stored = row[0]["ssh_password"], row[0]["luci_pass"]
check("ssh pw NOT plaintext in DB", "hunter2" not in (ssh_stored or "") and bool(ssh_stored), repr(ssh_stored)[:60])
check("luci pw NOT plaintext in DB", "lucipw" not in (luci_stored or "") and bool(luci_stored), repr(luci_stored)[:60])
check("ssh pw decrypts back to plaintext", owctl._stored_device_cred(ssh_stored) == "hunter2")
check("luci pw decrypts back to plaintext", owctl._stored_device_cred(luci_stored) == "lucipw")
check("stored value is marked enc.v1.", (ssh_stored or "").startswith("enc.v1."), ssh_stored[:20])

# 2) legacy plaintext row (pre-feature) still reads back unchanged
owctl.execute("INSERT INTO devices(name, host, access, ssh_password, luci_pass) "
              "VALUES('legacy','192.168.1.11','ssh','oldplain','oldluci')")
legacy = owctl.q("SELECT ssh_password, luci_pass FROM devices WHERE host='192.168.1.11'")[0]
check("legacy plaintext ssh reads back", owctl._stored_device_cred(legacy["ssh_password"]) == "oldplain")
check("legacy plaintext luci reads back", owctl._stored_device_cred(legacy["luci_pass"]) == "oldluci")

# 3) update: empty keeps the secret, new value overwrites
did = owctl.q("SELECT id FROM devices WHERE host='192.168.1.10'")[0]["id"]
client.put(f"/api/devices/{did}", json={
    "name": "r1", "role": "router", "access": "ssh", "ssh_port": 22, "ssh_user": "root",
    "ssh_password": "", "luci_user": "root", "luci_pass": ""})
row = owctl.q("SELECT ssh_password FROM devices WHERE id=?", (did,))[0]
check("update empty pw keeps secret", owctl._stored_device_cred(row["ssh_password"]) == "hunter2")

client.put(f"/api/devices/{did}", json={
    "name": "r1", "role": "router", "access": "ssh", "ssh_port": 22, "ssh_user": "root",
    "ssh_password": "brandnew42", "luci_user": "root", "luci_pass": ""})
row = owctl.q("SELECT ssh_password FROM devices WHERE id=?", (did,))[0]
check("update new pw overwrites", owctl._stored_device_cred(row["ssh_password"]) == "brandnew42")
check("new pw stored encrypted (not plaintext)", "brandnew42" not in (row["ssh_password"] or ""))

# 4) _store_device_cred is idempotent (an encrypted value passes through)
enc = owctl._store_device_cred("hunter2")
check("store is idempotent on encrypted value", owctl._store_device_cred(enc) == enc)

# 5) wrong key does not crash the read path (returns '' rather than raising)
os.environ["OWCTL_CRED_KEY"] = base64.b64encode(secrets.token_bytes(32)).decode()
got = owctl._stored_device_cred(enc)
check("wrong key: read returns '' without raising", got == "", repr(got))

print()
if FAILS:
    print(f"=== {FAILS} check(s) FAILED ===")
    sys.exit(1)
print("13/13 checks passed")
print("ALL CRED-ENCRYPTION CHECKS PASSED")
