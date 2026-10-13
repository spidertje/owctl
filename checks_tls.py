# Copyright (C) 2026 spidertje
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#!/usr/bin/env python3
"""checks_tls.py — optional TLS via OWCTL_SSL_CERT / OWCTL_SSL_KEY.

Contract:
- Neither set -> no TLS kwargs (plain HTTP).
- Both set to existing files -> ssl_certfile/ssl_keyfile kwargs passed through.
- Cert set but key missing -> error surfaced (not silently plain).

Run: .venv/bin/python checks_tls.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["OWCTL_DATA"] = tempfile.mkdtemp()

import owctl  # noqa: E402

CHECKS = []


def check(name, cond, extra=""):
    CHECKS.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


def main():
    tmp = tempfile.mkdtemp()
    cert = os.path.join(tmp, "c.pem"); key = os.path.join(tmp, "k.pem")
    open(cert, "w").write("CERT")
    open(key, "w").write("KEY")

    # neither -> no TLS
    os.environ.pop("OWCTL_SSL_CERT", None)
    os.environ.pop("OWCTL_SSL_KEY", None)
    kw = owctl.tls_kwargs()
    check("no certs: plain (no ssl kwargs)", kw == {}, str(kw))

    # both -> TLS kwargs
    os.environ["OWCTL_SSL_CERT"] = cert
    os.environ["OWCTL_SSL_KEY"] = key
    kw = owctl.tls_kwargs()
    check("both set: ssl_certfile", kw.get("ssl_certfile") == cert, str(kw))
    check("both set: ssl_keyfile", kw.get("ssl_keyfile") == key, str(kw))

    # cert but no key -> raises
    os.environ.pop("OWCTL_SSL_KEY", None)
    raised = False
    msg = ""
    try:
        owctl.tls_kwargs()
    except Exception as e:
        raised = True
        msg = str(e)
    check("cert without key: raises", raised, "")
    if raised:
        check("cert without key: message mentions key", "key" in msg.lower(), msg)

    print(f"\n=== SUMMARY ===\n{sum(1 for _, ok, _ in CHECKS if ok)}/{len(CHECKS)} checks passed")
    failed = [n for n, ok, _ in CHECKS if not ok]
    if failed:
        for n in failed:
            print(" -", n)
        sys.exit(1)
    print("ALL TLS CHECKS PASSED")


if __name__ == "__main__":
    main()
