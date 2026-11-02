#!/usr/bin/env python3
"""checks_error_context.py — enrich_device_error behavior guard.

Verifies the enrich_device_error helper:
- detects 'not found' / 'command not found' and extracts the binary
- includes host, firmware, hint (opkg install)
- handles Permission denied, Connection refused, No such file, timeout
- falls back to original text when no known signature
- endpoint integration: push-key path returns enriched 502 detail
"""
import os
import sys
import tempfile

_tmp = tempfile.mkdtemp(prefix="owctl-errorctx-")
os.environ["OWCTL_DATA"] = os.path.join(_tmp, "data")
os.environ.setdefault("OWCTL_ALLOW_OPEN", "1")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import owctl  # noqa: E402

owctl.init_db()

PASS = FAIL = 0


def check(label, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"PASS {label}")
    else:
        FAIL += 1
        print(f"FAIL {label} :: {detail}")


# ---- fake device dicts ----
dev_with_firmware = {
    "id": 1,
    "name": "router1",
    "host": "192.168.30.1",
    "firmware": "OpenWrt 24.10.4 r28959",
    "firmware_info": {
        "description": "OpenWrt 24.10.4",
        "version": "24.10.4",
        "revision": "r28959",
    },
}

dev_no_firmware = {"id": 2, "name": "ap1", "host": "192.168.30.2"}

dev_minimal = {"id": 3, "name": "switch1", "host": "192.168.30.3"}

# ---- direct helper tests ----

# 1. command not found pattern (ash: base64: not found)
out = owctl.enrich_device_error(
    dev_with_firmware, "ash: base64: not found", "push_ssh_key"
)
check(
    "not found: extracts base64 and includes host+firmware+hint",
    "base64" in out
    and "192.168.30.1" in out
    and "24.10.4" in out
    and "opkg install base64" in out,
    out,
)

# 2. command not found pattern (command not found: foo)
out = owctl.enrich_device_error(
    dev_with_firmware, "command not found: opkg", "backup"
)
check(
    "command not found: extracts opkg and includes hint",
    "opkg" in out and "opkg install opkg" in out and "backup failed" in out,
    out,
)

# 3. Permission denied
out = owctl.enrich_device_error(
    dev_no_firmware, "Permission denied", "restore"
)
check(
    "permission denied: includes host",
    "192.168.30.2" in out and "Permission denied" in out and "restore failed" in out,
    out,
)

# 4. Connection refused
out = owctl.enrich_device_error(
    dev_with_firmware, "Connection refused", "vlan_read"
)
check(
    "connection refused: includes firmware",
    "192.168.30.1" in out and "24.10.4" in out and "Connection refused" in out,
    out,
)

# 5. No such file or directory
out = owctl.enrich_device_error(
    dev_minimal, "No such file or directory", "switch_read"
)
check(
    "no such file: includes host",
    "192.168.30.3" in out and "No such file" in out and "switch operation failed" in out,
    out,
)

# 6. Timeout / timed out
out = owctl.enrich_device_error(dev_with_firmware, "timed out", "mesh_apply")
check(
    "timeout: includes firmware",
    "192.168.30.1" in out and "24.10.4" in out and "Timeout" in out,
    out,
)

out = owctl.enrich_device_error(dev_with_firmware, "timeout", "upgrade")
check(
    "timeout (short): includes firmware",
    "192.168.30.1" in out and "24.10.4" in out and "Timeout" in out,
    out,
)

# 7. Unknown signature -> fallback
out = owctl.enrich_device_error(dev_with_firmware, "some weird error", "backup")
check(
    "unknown signature falls back to original",
    out == "some weird error",
    f"got: {out!r}",
)

# 8. Empty err_text -> fallback
out = owctl.enrich_device_error(dev_with_firmware, "", "push_ssh_key")
check(
    "empty err_text falls back to failed_cmd",
    out == "push_ssh_key",
    f"got: {out!r}",
)

# ---- endpoint integration test ----
# monkeypatch _ssh_connect and _exec_capture to simulate missing base64 on push-key
orig_ssh_connect = owctl._ssh_connect
orig_exec_capture = owctl._exec_capture


class _DummyClient:
    def close(self):
        pass


def fake_ssh_connect(dev):
    return _DummyClient()


def fake_exec_capture_base64_missing(client, cmd, timeout=300):
    return b"", b"ash: base64: not found", 127


owctl._ssh_connect = fake_ssh_connect
owctl._exec_capture = fake_exec_capture_base64_missing

# insert a test device
owctl.execute(
    "INSERT INTO devices(name, host, access, ssh_user, ssh_password, added_at) "
    "VALUES(?,?,?,?,?,?)",
    ("testpush", "192.168.30.10", "ssh", "root", "x", owctl.now()),
)
dev = owctl.q("SELECT * FROM devices WHERE host='192.168.30.10'")[0]

# call push_ssh_key directly (which calls _exec_capture internally)
try:
    owctl.push_ssh_key(dev)
    check("push_ssh_key raises on missing base64", False, "no exception raised")
except RuntimeError as e:
    detail = str(e)
    check(
        "push_ssh_key error enriched: contains base64+host+hint",
        "base64" in detail
        and "192.168.30.10" in detail
        and "opkg install base64" in detail,
        detail,
    )

# restore
owctl._ssh_connect = orig_ssh_connect
owctl._exec_capture = orig_exec_capture

# 9. Test via HTTP endpoint (TestClient)
from fastapi.testclient import TestClient  # noqa: E402

client = TestClient(owctl.app)

# Need to monkeypatch _ssh_connect and _exec_capture again for the endpoint test
owctl._ssh_connect = fake_ssh_connect
owctl._exec_capture = fake_exec_capture_base64_missing

try:
    r = client.post(f"/api/devices/{dev['id']}/push-key")
    check(
        "push-key endpoint returns 502",
        r.status_code == 502,
        f"status={r.status_code} body={r.text}",
    )
    if r.status_code == 502:
        detail = r.json().get("detail", "")
        check(
            "push-key endpoint detail enriched",
            "base64" in detail
            and "192.168.30.10" in detail
            and "opkg install base64" in detail,
            detail,
        )
except Exception as e:
    check("push-key endpoint test error", False, str(e))

# restore again
owctl._ssh_connect = orig_ssh_connect
owctl._exec_capture = orig_exec_capture


print(f"\n=== SUMMARY ===\n{PASS}/{PASS + FAIL} checks passed")
sys.exit(0 if FAIL == 0 else 1)