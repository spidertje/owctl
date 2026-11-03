"""checks_docs_auth.py — /docs and /openapi.json must be reachable WITHOUT auth.

Deliberately does NOT set OWCTL_ALLOW_OPEN so the live middleware is exercised.
"""
import os
import sys
import importlib
import httpx

# 1) Fresh temp data dir, real middleware live (OWCTL_ALLOW_OPEN unset).
os.environ["OWCTL_DATA"] = "/tmp/owctl_docs_auth_test"
os.environ.pop("OWCTL_ALLOW_OPEN", None)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import owctl
importlib.reload(owctl)

base = "http://127.0.0.1:18080"


def _start():
    import threading
    import uvicorn

    cfg = uvicorn.Config(owctl.app, host="127.0.0.1", port=18080, log_level="error")
    server = uvicorn.Server(cfg)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    import time
    for _ in range(50):
        try:
            httpx.get(f"{base}/api/health", timeout=1)
            return server
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("server did not start")


server = _start()
failures = []


def check(name, cond):
    if cond:
        print(f"PASS {name}")
    else:
        print(f"FAIL {name}")
        failures.append(name)


# (a) /openapi.json without any Authorization header → 200
r = httpx.get(f"{base}/openapi.json", timeout=5)
check("GET /openapi.json no-auth returns 200", r.status_code == 200)
check("GET /openapi.json body is JSON spec", isinstance(r.json(), dict) and "paths" in r.json())

# (b) /docs without auth → 200 (Swagger UI HTML)
r = httpx.get(f"{base}/docs", timeout=5, follow_redirects=True)
check("GET /docs no-auth returns 200", r.status_code == 200)
check("GET /docs returns HTML", "text/html" in r.headers.get("content-type", ""))

# (c) /docs/oauth2-redirect without auth → 200 (or 404 if not registered, but must NOT 401)
r = httpx.get(f"{base}/docs/oauth2-redirect", timeout=5, follow_redirects=True)
check("GET /docs/oauth2-redirect no-auth not 401", r.status_code != 401)

# (d) /api/devices still 401s unauthenticated (auth not weakened for /api/*)
r = httpx.get(f"{base}/api/devices", timeout=5)
check("GET /api/devices no-auth returns 401", r.status_code == 401)

server.should_exit = True

if failures:
    print(f"\n{len(failures)} FAILURES: {failures}")
    sys.exit(1)
print("\nALL DOCS AUTH CHECKS PASSED")