#!/usr/bin/env bash
#
# Copyright (C) 2026 spidertje
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied fitness for a
# particular purpose. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.
#
# owctl supervision loop — portable across macOS and Linux.
#
# Restarts owctl automatically whenever it exits, with a small backoff so a
# crash-loop can't spin the CPU. This is the simplest cross-platform
# supervisor; use launchd (macOS) or systemd (Linux) for boot-time start.
#
# Usage:
#   ./launch.sh                # foreground (Ctrl-C to stop)
#   nohup ./launch.sh >/dev/null 2>&1 &   # background
#
# Env (all optional, passed through to owctl):
#   OWCTL_HOST, OWCTL_PORT, OWCTL_DATA, OWCTL_LOG, OWCTL_SSL_CERT, OWCTL_SSL_KEY
#
# Stop a backgrounded instance:
#   kill "$(cat data/.owctl-supervisor.pid)"

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-.venv/bin/python}"
[ -x "$PYTHON" ] || PYTHON="${PYTHON:-python3}"

# Data dir: honor OWCTL_DATA, else the default ./data (same rule owctl.py uses).
DATA_DIR="${OWCTL_DATA:-$ROOT/data}"
# Log file: default to <data>/owctl.log (same as owctl.py), else console.
if [ -n "${OWCTL_LOG:-}" ]; then
    LOG_FILE="$OWCTL_LOG"
else
    LOG_FILE="$DATA_DIR/owctl.log"
fi
PID_FILE="$(dirname "$LOG_FILE")/.owctl-supervisor.pid"
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true

log() { echo "$*" | tee -a "$LOG_FILE" >/dev/null 2>&1; }

log "owctl supervisor: starting (python=$PYTHON data=$DATA_DIR log=$LOG_FILE)"

echo $$ > "$PID_FILE" 2>/dev/null || true
cleanup() { rm -f "$PID_FILE" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

attempt=0
while true; do
    attempt=$((attempt + 1))
    if [ "$attempt" -gt 1 ]; then
        # Exponential-ish backoff, capped at 30s, so a crash-loop cools down.
        delay=$(( 2 ** (attempt - 1) ))
        [ "$delay" -gt 30 ] && delay=30
        log "owctl supervisor: restarting in ${delay}s (attempt $attempt)"
        sleep "$delay"
    fi
    # Run owctl in the foreground of this loop. Capture its exit code so we
    # can tell a clean stop (0) from a crash (non-zero).
    "$PYTHON" "$ROOT/owctl.py"
    code=$?
    log "owctl supervisor: owctl exited with code $code"
    # If the user asked to stop (SIGTERM/SIGINT to the supervisor), don't
    # restart — that would fight the stop. 130=SIGINT, 143=SIGTERM.
    if [ "$code" -eq 130 ] || [ "$code" -eq 143 ]; then
        log "owctl supervisor: stop signal detected, not restarting."
        exit 0
    fi
done
