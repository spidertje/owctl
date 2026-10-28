#!/usr/bin/env python3
"""checks_tls_policy.py — unverified-TLS policy regression guard.

Contract (audit P2, LOW): LuCI RPC and the sweep used CERT_NONE unconditionally
for ANY host — including public IPs (self-signed or MITM'd on the open
internet). The fix: unverified (self-signed) TLS stays allowed for loopback /
private / link-local targets (the normal LAN case), but a public IP literal —
or a hostname resolving to a public address — demands VERIFIED TLS, and an
unresolvable host fails closed (verify). This check exercises the policy
decision function directly (no network) against the two call sites' inputs.
Run: .venv/bin/python checks_tls_policy.py
"""
import os, sys, tempfile, ssl

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
os.environ["OWCTL_DATA"] = tempfile.mkdtemp()
os.environ["OWCTL_ALLOW_OPEN"] = "1"

import owctl  # noqa: E402

FAILS = 0
def check(name, ok, detail=""):
    global FAILS
    if not ok:
        FAILS += 1
    print(("PASS " if ok else "FAIL ") + name + (f" :: {detail}" if detail and not ok else ""))

f = owctl._unverified_tls_ok

# loopback + private + link-local: unverified OK (self-signed LAN boxes work)
check("127.0.0.1 -> unverified ok", f("127.0.0.1") is True)
check("10.0.0.1 -> unverified ok", f("10.0.0.1") is True)
check("192.168.1.1 -> unverified ok", f("192.168.1.1") is True)
check("169.254.10.10 (link-local) -> unverified ok", f("169.254.10.10") is True)

# public IP literals: verified required (CERT_NONE denied)
check("93.184.216.34 -> verified required", f("93.184.216.34") is False)
check("8.8.8.8 -> verified required", f("8.8.8.8") is False)

# unresolvable hostname: fail closed (verified required), never raise
check("nonexistent.invalid -> verified required", f("nonexistent.invalid") is False)

# a loopback hostname (resolves to 127.0.0.1) stays unverified-ok
check("localhost -> unverified ok", f("localhost") is True)

# The policy is actually wired into both CERT_NONE sites:
src = open(os.path.join(BASE, "owctl.py"), encoding="utf-8").read()
cert_none_sites = src.count("ctx.verify_mode = ssl.CERT_NONE")
gates = src.count("_unverified_tls_ok(")  # 1 def + 2 call sites
check("exactly the 2 CERT_NONE sites remain (both now gated)", cert_none_sites == 2, f"CERT_NONE sites={cert_none_sites}")
check("both CERT_NONE sites are gated by the policy", gates == cert_none_sites + 1, f"gates={gates} (1 def + {cert_none_sites} sites)")

print()
if FAILS:
    print(f"=== {FAILS} check(s) FAILED ===")
    sys.exit(1)
print("10/10 checks passed")
print("ALL TLS-POLICY CHECKS PASSED")
