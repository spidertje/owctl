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
"""gen_selfsigned_cert.py — create a self-signed TLS cert for owctl.

Usage:
  python gen_selfsigned_cert.py [--out-dir data] [--days 825] [--cn owctl]
    [--ip 192.168.55.179] [--hostname owctl.local]

Writes <out-dir>/owctl-selfsigned.crt and .key, then prints the two
OWCTL_SSL_CERT / OWCTL_SSL_KEY env lines ready to paste into your service.
Uses the `cryptography` package (already in requirements).
"""
import argparse
import datetime
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def make_cert(cn="owctl", days=825, ips=None, dns=None):
    ips = ips or ["127.0.0.1"]
    dns = dns or [cn, f"{cn}.local", "localhost"]

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    not_before = datetime.datetime.now(datetime.timezone.utc)
    not_after = not_before + datetime.timedelta(days=days)

    san = [x509.DNSName(d) for d in dns] + [
        x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips
    ]

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="data")
    ap.add_argument("--days", type=int, default=825)
    ap.add_argument("--cn", default="owctl")
    ap.add_argument("--ip", action="append", default=None, help="SAN IP (repeatable)")
    ap.add_argument("--hostname", action="append", default=None, help="SAN DNS (repeatable)")
    a = ap.parse_args()

    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    ip_list = a.ip or ["127.0.0.1"]
    # Union the explicit hostnames with the sensible defaults (cn, cn.local,
    # localhost) instead of replacing them — before, `--hostname foo` produced a
    # cert whose SAN only had `foo`, dropping the names clients usually reach it
    # by (e.g. `owctl.local`). Dedup, preserve order.
    defaults = [a.cn, f"{a.cn}.local", "localhost"]
    dns_list = list(dict.fromkeys((a.hostname or []) + defaults))

    key, cert = make_cert(cn=a.cn, days=a.days, ips=ip_list, dns=dns_list)

    crt_path = out / "owctl-selfsigned.crt"
    key_path = out / "owctl-selfsigned.key"
    crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    os.chmod(key_path, 0o600)

    san = ", ".join(list(dns_list) + ip_list)
    print(f"wrote: {crt_path}")
    print(f"wrote: {key_path}")
    print(f"SAN:   {san}")
    print(f"valid: until {(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=a.days)).date()}")
    print("\n# add to your owctl service environment:")
    print(f'OWCTL_SSL_CERT={crt_path.resolve()}')
    print(f'OWCTL_SSL_KEY={key_path.resolve()}')
    print("\n# or launch directly:")
    print(f'OWCTL_SSL_CERT={crt_path.resolve()} OWCTL_SSL_KEY={key_path.resolve()} python owctl.py')


if __name__ == "__main__":
    main()
