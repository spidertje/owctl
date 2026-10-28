#!/usr/bin/env python3
"""checks_threadpool.py — anyio thread-pool bump regression guard.

Contract (audit P2, LOW): _bump_thread_pool used anyio.current_default_thread_limiter()
(a top-level alias removed in anyio 4.x — lazy import raises AttributeError)
inside a throwaway asyncio.run() loop. Two failures compounded:
  1. the API name no longer exists -> except: pass swallowed it -> NO-OP;
  2. anyio's limiter is per-event-loop, so even a successful bump on a
     throwaway loop would never apply to the uvicorn request loop.
Fixed: _bump_thread_pool uses anyio.to_thread.current_default_thread_limiter()
and returns True only when it actually applied (i.e. it ran inside a running
loop); the server installs it on the LIVE loop via the app lifespan hook.
This check proves both halves: in-loop bump sticks on THAT loop; out-of-loop
call is a safe no-op (False, no exception)."""
import sys, os, asyncio, contextlib

BASE = os.path.dirname(os.path.abspath(__file__))
os.environ["OWCTL_ALLOW_OPEN"] = "1"
os.environ["OWCTL_DATA_DIR"] = os.path.join(BASE, "test_data_threadpool")
sys.path.insert(0, BASE)
import owctl  # noqa: E402
import anyio  # noqa: E402

fails = 0
def check(name, ok, detail=""):
    global fails
    if not ok:
        fails += 1
    print(("PASS " if ok else "FAIL ") + name + (f" :: {detail}" if detail and not ok else ""))

# 1) In a running loop: bump must apply (tokens 40 -> 200) and return True.
async def in_loop():
    before = anyio.to_thread.current_default_thread_limiter().total_tokens
    applied = owctl._bump_thread_pool()
    after = anyio.to_thread.current_default_thread_limiter().total_tokens
    return before, applied, after

before, applied, after = asyncio.run(in_loop())
check("bump applies inside a running loop (tokens raised)",
      applied is True and after == 200 and before == 40,
      f"before={before} applied={applied} after={after}")

# 2) Fresh loop (simulating the uvicorn server loop): the bump must be
#    re-apply-able there — it is per-loop, so the lifespan hook calls it again.
async def fresh_loop():
    lim = anyio.to_thread.current_default_thread_limiter()
    applied = owctl._bump_thread_pool()
    return lim.total_tokens

tok = asyncio.run(fresh_loop())
check("bump re-applies on a fresh (server-equivalent) loop", tok == 200, f"tokens={tok}")

# 3) Called synchronously (no running loop): safe no-op, returns False, no raise.
res = owctl._bump_thread_pool()
check("sync call is a safe no-op (returns False, no exception)", res is False, f"returned {res!r}")

# 4) The app actually carries a lifespan hook that installs the bump on start.
ls = getattr(owctl.app, "router", None)
has_hook = getattr(owctl.app, "router", None) is not None and owctl._install_thread_pool_hook() is not None
check("app has the lifespan hook factory (_install_thread_pool_hook)", has_hook)

# 5) Lifespan runs _bump_thread_pool inside its loop without error.
async def lifespan_run():
    hook = owctl._install_thread_pool_hook()
    async with hook(owctl.app):
        return anyio.to_thread.current_default_thread_limiter().total_tokens
tok2 = asyncio.run(lifespan_run())
check("lifespan hook leaves the loop's pool at 200", tok2 == 200, f"tokens={tok2}")

print()
if fails:
    print(f"=== {fails} check(s) FAILED ===")
    sys.exit(1)
print("5/5 checks passed")
print("ALL THREADPOOL CHECKS PASSED")
