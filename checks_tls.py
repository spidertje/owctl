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

    # neither -> TLS-mandatory: a self-signed pair is generated under DATA_DIR
    # (HTTPS is never optional; a plain-HTTP fallback would leak credentials).
    os.environ.pop("OWCTL_SSL_CERT", None)
    os.environ.pop("OWCTL_SSL_KEY", None)
    kw = owctl.tls_kwargs()
    check("no certs: TLS-mandatory (ssl kwargs present)",
          bool(kw.get("ssl_certfile")) and bool(kw.get("ssl_keyfile")), str(kw))
    check("no certs: self-signed cert exists",
          os.path.exists(kw["ssl_certfile"]), kw.get("ssl_certfile", ""))
    check("no certs: self-signed key exists",
          os.path.exists(kw["ssl_keyfile"]), kw.get("ssl_keyfile", ""))

    # both -> TLS kwargs passed through to the provided files
    os.environ["OWCTL_SSL_CERT"] = cert
    os.environ["OWCTL_SSL_KEY"] = key
    kw = owctl.tls_kwargs()
    check("both set: ssl_certfile", kw.get("ssl_certfile") == cert, str(kw))
    check("both set: ssl_keyfile", kw.get("ssl_keyfile") == key, str(kw))

    # cert but no key -> under TLS-mandatory this does NOT raise; it falls back
    # to the self-signed pair in DATA_DIR (never serves plain HTTP). The returned
    # cert is the generated one, not the provided (keyless) file.
    os.environ.pop("OWCTL_SSL_KEY", None)
    kw3 = owctl.tls_kwargs()
    check("cert without key: no raise (TLS-mandatory fallback)",
          bool(kw3.get("ssl_certfile")) and bool(kw3.get("ssl_keyfile")), str(kw3))
    check("cert without key: returns existing files",
          os.path.exists(kw3["ssl_certfile"]) and os.path.exists(kw3["ssl_keyfile"]), str(kw3))

    print(f"\n=== SUMMARY ===\n{sum(1 for _, ok, _ in CHECKS if ok)}/{len(CHECKS)} checks passed")
    failed = [n for n, ok, _ in CHECKS if not ok]
    if failed:
        for n in failed:
            print(" -", n)
        sys.exit(1)
    print("ALL TLS CHECKS PASSED")


if __name__ == "__main__":
    main()
