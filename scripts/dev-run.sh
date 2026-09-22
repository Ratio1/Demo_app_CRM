#!/usr/bin/env bash
#
# dev-run.sh — serve Demo_App_CRM on the host, over TLS, for a human. It is
# NOT the container entrypoint: that is scripts/start, which binds 0.0.0.0:3000
# and adds no TLS of its own.
#
#   scripts/dev-run.sh
#
# What it does, in order:
#
#   1. Scrubs every PG* variable out of the environment. The application
#      passes every libpq parameter explicitly, so a hostile PGSSLMODE or
#      PGHOST cannot *override* anything — but a PGSERVICE naming a service
#      that does not exist is a hard connection failure, which is an
#      availability lever any process that can set this process's environment
#      could pull. Scrubbing is fail-closed and costs nothing.
#   2. Generates a self-signed 127.0.0.1 certificate if none is there yet,
#      and never regenerates one that exists. Both paths are git-ignored
#      (.gitignore: app/certs/dev-server.crt, app/certs/dev-server.key).
#   3. Execs uvicorn through scripts/with-env, which is the only way a
#      credential reaches a process here.
#
# Port 3002 is this app's development port and it binds 127.0.0.1 only. Tests
# never use it: the suite's protocol tests run the application in process over
# httpx.ASGITransport, and the one real TLS server it still starts is
# session-scoped on an ephemeral port. So a dev server may stay up while the
# suite runs.
#
# The stored public origin is NOT written here — this script never touches the
# database. Point it at this server once, by hand:
#
#   scripts/with-env .env.owner.local -- python -B scripts/manage \
#     set-origin --origin https://127.0.0.1:3002

set -Eeuo pipefail

# Resolve the submodule root from this script's own location, so the command
# works from any working directory. app/certs/ca-bundle.pem is resolved
# relative to the app package itself, but the uvicorn --ssl-* paths below and
# `app.main:app`'s import both still need the root as the cwd.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
root_dir="$(cd -- "${script_dir}/.." && pwd)"
cd -- "$root_dir"

# 1. Every PG* name, unconditionally, before anything else runs.
for pg_name in "${!PG@}"; do
  unset "$pg_name"
done
unset pg_name

readonly CERT_FILE="app/certs/dev-server.crt"
readonly KEY_FILE="app/certs/dev-server.key"
readonly DEV_PORT=3002

# 2. Generate the development certificate once. `-days 30` keeps a forgotten
# certificate from living forever; deleting the pair regenerates it.
if [ ! -f "$CERT_FILE" ]; then
  printf 'dev-run: generating a self-signed development certificate\n' >&2
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -subj "/CN=127.0.0.1" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
  chmod 600 "$KEY_FILE"
fi

# 3. Same flag list as scripts/start, plus the host/port/TLS trio.
exec scripts/with-env .env -- python -B -m uvicorn app.main:app \
  --host 127.0.0.1 \
  --port "$DEV_PORT" \
  --workers 1 \
  --no-server-header \
  --no-proxy-headers \
  --no-access-log \
  --limit-concurrency 64 \
  --backlog 128 \
  --timeout-graceful-shutdown 20 \
  --ssl-certfile "$CERT_FILE" \
  --ssl-keyfile "$KEY_FILE"
