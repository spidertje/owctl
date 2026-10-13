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
"""checks_tls_serve.py — a self-signed cert actually serves HTTPS.

Contract:
- gen_selfsigned_cert.make_cert() returns a key+cert that loads in a TLS server.
- A uvicorn server run with those certs answers https:// on the chosen port.
- A plain-http request to the same port fails (server is TLS-only).
- The cert is not-yet-expired / not-before is in the past.

Run: .venv/bin/python checks_tls_serve.py
"""
import datetime
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ["OWCTL_DATA"] = tempfile.mkdtemp()

import gen_selfsigned_cert as g  # noqa: E402

CHECKS = []


def check(name, cond, extra=""):
    CHECKS.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


def main():
    from cryptography import x509 as _x
    from cryptography.hazmat.primitives import serialization

    key, cert = g.make_cert(cn="owctl", days=825, ips=["127.0.0.1"], dns=["localhost"])

    # cert sanity
    now = datetime.datetime.now(datetime.timezone.utc)
    check("cert not_valid_before <= now", cert.not_valid_before_utc <= now)
    check("cert not_valid_after > now", cert.not_valid_after_utc > now)
    check("cert has SAN (localhost)", any(isinstance(e, _x.DNSName) and e.value == "localhost"
                                          for e in cert.extensions.get_extension_for_class(_x.SubjectAlternativeName).value))

    # write PEM files
    tmp = tempfile.mkdtemp()
    crt = os.path.join(tmp, "c.crt"); keyp = os.path.join(tmp, "k.key")
    open(crt, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(keyp, "wb").write(key.private_bytes(serialization.Encoding.PEM,
                                             serialization.PrivateFormat.TraditionalOpenSSL,
                                             serialization.NoEncryption()))

    # run the real server over TLS in a subprocess
    port = 18443
    env = dict(os.environ, OWCTL_ALLOW_OPEN="1", OWCTL_SSL_CERT=crt, OWCTL_SSL_KEY=keyp,
               OWCTL_DATA=tempfile.mkdtemp(), OWCTL_PORT=str(port))
    proc = subprocess.Popen([sys.executable, "owctl.py"], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        # wait for it to come up (poll TLS handshake)
        ctx = ssl.create_default_context(cafile=crt)  # trust our self-signed cert
        ok_handshake = False
        last = ""
        for _ in range(60):
            time.sleep(0.5)
            try:
                req = urllib.request.Request(f"https://127.0.0.1:{port}/api/uptime")
                with urllib.request.urlopen(req, context=ctx, timeout=3) as r:
                    body = r.read().decode()
                    ok_handshake = (r.status == 200)
                    last = f"status={r.status} body={body[:40]!r}"
                    break
            except urllib.error.HTTPError as e:
                ok_handshake = True  # we got a TLS response even if the path 4xx'd
                last = f"HTTPError {e.code}"
                break
            except (urllib.error.URLError, ssl.SSLError, ConnectionError, TimeoutError):
                continue
            except Exception as e:
                last = f"{type(e).__name__}: {e}"
                break
        check("TLS server answers https:// (api/uptime)", ok_handshake, last)

        # and the dashboard itself is served over TLS
        try:
            with urllib.request.urlopen(urllib.request.Request(f"https://127.0.0.1:{port}/"),
                                       context=ctx, timeout=3) as r:
                home = r.read().decode(errors="replace")
            check("dashboard served over TLS (has <html>)", "<html" in home.lower() and r.status == 200)
        except Exception as e:
            check("dashboard served over TLS (has <html>)", False, f"{type(e).__name__}: {e}")

        # plain http should NOT succeed against a TLS-only port
        plain_works = True
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{port}/api/uptime")
            urllib.request.urlopen(req, timeout=3)
        except (urllib.error.URLError, ssl.SSLError, ConnectionError, TimeoutError, OSError):
            plain_works = False
        check("plain-http request fails (TLS-only)", not plain_works)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    print(f"\n=== SUMMARY ===\n{sum(1 for _, ok, _ in CHECKS if ok)}/{len(CHECKS)} checks passed")
    failed = [n for n, ok, _ in CHECKS if not ok]
    if failed:
        for n in failed:
            print(" -", n)
        sys.exit(1)
    print("ALL TLS-SERVE CHECKS PASSED")


if __name__ == "__main__":
    main()
