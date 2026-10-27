#!/bin/bash
# Boot openhost-vaultwarden.
#
#   browser → https://vaultwarden.<zone>/ → container :8080 (auth_proxy.py)
#                                         → 127.0.0.1:8088 (vaultwarden / Rocket)
#
# Pattern E — no auto-SSO.  The OpenHost zone_auth gate keeps the
# subdomain private, but the user logs in to Vaultwarden with their
# MASTER PASSWORD.  See README.md for rationale.

set -euo pipefail

PERSIST="${OPENHOST_APP_DATA_DIR:-/data/app_data/vaultwarden}"
mkdir -p "$PERSIST"

ZONE_DOMAIN="${OPENHOST_ZONE_DOMAIN:-localhost}"
APP_NAME="${OPENHOST_APP_NAME:-vaultwarden}"
PUBLIC_HOSTNAME="${PUBLIC_HOSTNAME:-${APP_NAME}.${ZONE_DOMAIN}}"

# ----------------------------------------------------------------------
# Admin token
#
# /admin is Vaultwarden's diagnostic / configuration panel, accessed
# by entering an "admin token".  The token is read from $ADMIN_TOKEN.
# We generate one on first boot (32 random bytes, base64-url'd) and
# persist it under $PERSIST/admin_token.txt so subsequent boots reuse
# it — ensuring the operator's saved token remains valid across
# restarts and image updates.
#
# This file is NOT a user credential — it only protects the server-
# admin diagnostic panel, which doesn't grant vault access.  Vault
# data is end-to-end encrypted with the user's master password, which
# is never on disk.  Still, we mode-0600 it as a defence-in-depth
# measure against co-located apps with `app_data` permission (file-
# browser).
# ----------------------------------------------------------------------

ADMIN_TOKEN_FILE="$PERSIST/admin_token.txt"
if [[ ! -s "$ADMIN_TOKEN_FILE" ]]; then
    echo "[start.sh] First boot: generating admin token"
    head -c 32 /dev/urandom | base64 | tr -d '\n=' | tr '+/' '-_' \
        > "$ADMIN_TOKEN_FILE"
    chmod 0600 "$ADMIN_TOKEN_FILE"
fi
ADMIN_TOKEN_VALUE="$(cat "$ADMIN_TOKEN_FILE")"

echo "[start.sh] -----------------------------------------------------"
echo "[start.sh] Vaultwarden /admin token (for the diagnostic panel):"
echo "[start.sh]     $ADMIN_TOKEN_VALUE"
echo "[start.sh] Visit https://${PUBLIC_HOSTNAME}/admin and enter the"
echo "[start.sh] token above to access server admin / config."
echo "[start.sh] -----------------------------------------------------"

# ----------------------------------------------------------------------
# Vaultwarden environment configuration
#
# Vaultwarden picks up settings from environment variables.  We set
# them here rather than in a .env file because OpenHost rebuilds the
# container fresh on every reload — anything inside the image is
# ephemeral, so the source of truth must be either env vars (here) or
# files under $OPENHOST_APP_DATA_DIR (admin_token.txt, db.sqlite3).
#
# DOMAIN must match the public-facing URL or some Vaultwarden features
# (push notifications targeting, attachment URL generation, U2F/WebAuthn
# origin matching) will break.
#
# SIGNUPS_ALLOWED defaults to true on first boot so the owner can
# register their first account via the web vault UI.  After
# registration the operator should:
#   1. Set SIGNUPS_ALLOWED=false (re-deploy with the env override or
#      via the /admin panel).
#   2. Or invite users from /admin instead of letting them register.
# This is documented in README.md.
# ----------------------------------------------------------------------

export DOMAIN="${DOMAIN:-https://${PUBLIC_HOSTNAME}}"
export DATA_FOLDER="${DATA_FOLDER:-$PERSIST}"
export SIGNUPS_ALLOWED="${SIGNUPS_ALLOWED:-true}"
export WEB_VAULT_ENABLED="${WEB_VAULT_ENABLED:-true}"
# Vaultwarden warns (and rightly so) when ADMIN_TOKEN is a plain-text
# string, since it's then compared in the clear. Store an Argon2id PHC
# hash instead: the operator still logs in with the plaintext token from
# admin_token.txt (printed above), but the value in the environment /
# process table is only a hash. Recomputed each boot with a fresh salt;
# the plaintext token stays the stable operator credential. An explicit
# ADMIN_TOKEN override (env) is honoured as-is. Argon2 params follow
# Vaultwarden's docs.
if [[ -z "${ADMIN_TOKEN:-}" ]]; then
    ADMIN_TOKEN_SALT="$(head -c 32 /dev/urandom | base64)"
    export ADMIN_TOKEN="$(printf '%s' "$ADMIN_TOKEN_VALUE" \
        | argon2 "$ADMIN_TOKEN_SALT" -e -id -k 65540 -t 3 -p 4)"
fi
# Bind Vaultwarden's Rocket server to loopback so only the auth-proxy
# can reach it.  (Vaultwarden's docker default is 0.0.0.0:80; we keep
# 0.0.0.0 because the container's network namespace is private to
# this app, but listen on the non-privileged port 8088 to avoid
# requiring CAP_NET_BIND_SERVICE.)
export ROCKET_PORT="${ROCKET_PORT:-8088}"
export ROCKET_ADDRESS="${ROCKET_ADDRESS:-127.0.0.1}"
# The websocket endpoint /notifications/hub is mounted in-process by
# Vaultwarden in recent versions (no separate WEBSOCKET_PORT needed
# since 1.29.x).  Just ensure WEBSOCKET_ENABLED=true so push
# notifications work — Bitwarden clients depend on this for
# multi-device sync prompts.
export WEBSOCKET_ENABLED="${WEBSOCKET_ENABLED:-true}"

# Trust the loopback X-Forwarded-* headers from the auth-proxy so
# Vaultwarden honours X-Forwarded-Proto (which we set to https).
# This affects how it logs request origins and how it generates
# self-referential URLs for U2F/WebAuthn.
export ROCKET_PROXY_PROTO_HEADER="${ROCKET_PROXY_PROTO_HEADER:-X-Forwarded-Proto}"

mkdir -p "$DATA_FOLDER"

echo "[start.sh] Configuration:"
echo "[start.sh]   DOMAIN              = $DOMAIN"
echo "[start.sh]   DATA_FOLDER         = $DATA_FOLDER"
echo "[start.sh]   SIGNUPS_ALLOWED     = $SIGNUPS_ALLOWED"
echo "[start.sh]   WEB_VAULT_ENABLED   = $WEB_VAULT_ENABLED"
echo "[start.sh]   ROCKET_ADDRESS:PORT = $ROCKET_ADDRESS:$ROCKET_PORT"
echo "[start.sh]   WEBSOCKET_ENABLED   = $WEBSOCKET_ENABLED"

# ----------------------------------------------------------------------
# Launch Vaultwarden upstream
#
# The vaultwarden upstream image's entrypoint binary lives at
# /vaultwarden (or /usr/local/bin/vaultwarden depending on the build).
# Rather than guess, we delegate to the upstream image's startup
# command via `start-vaultwarden.sh` if present, else exec the binary
# directly.  The image's CMD is /start.sh historically but newer
# tags use the binary directly.
# ----------------------------------------------------------------------

VW_BIN=""
for candidate in /start.sh /vaultwarden /usr/local/bin/vaultwarden \
                 /usr/bin/vaultwarden; do
    if [[ -x "$candidate" ]]; then
        VW_BIN="$candidate"
        break
    fi
done
if [[ -z "$VW_BIN" ]]; then
    echo "[start.sh] FATAL: cannot locate vaultwarden binary" >&2
    exit 1
fi
echo "[start.sh] Launching vaultwarden via $VW_BIN"

"$VW_BIN" &
VW_PID=$!

# Wait briefly for vaultwarden's HTTP listener.  We poll the loopback
# address so we know Rocket has finished its startup migrations
# before we let traffic in via the auth-proxy.  If vaultwarden takes
# longer than ~30s the auth-proxy will return 502s during the gap;
# the OpenHost healthcheck hits /_healthz (served by the auth-proxy
# itself) so a slow upstream cold-start doesn't get the container
# marked failed.
echo "[start.sh] Waiting for vaultwarden on $ROCKET_ADDRESS:$ROCKET_PORT ..."
READY=0
for i in $(seq 1 60); do
    if ! kill -0 "$VW_PID" 2>/dev/null; then
        echo "[start.sh] FATAL: vaultwarden exited during startup (probe $i)" >&2
        export VAULTWARDEN_STARTUP_ERROR="Vaultwarden crashed during startup. The container will restart — check the logs for details."
        break
    fi
    if python3 -c "
import socket, sys
s = socket.socket()
s.settimeout(0.5)
sys.exit(0 if s.connect_ex(('127.0.0.1', $ROCKET_PORT)) == 0 else 1)
" 2>/dev/null; then
        READY=1
        echo "[start.sh] vaultwarden is up after ${i} probe(s)"
        break
    fi
    sleep 1
done
if [[ $READY -eq 0 && -z "${VAULTWARDEN_STARTUP_ERROR:-}" ]]; then
    echo "[start.sh] WARNING: vaultwarden did not respond on :$ROCKET_PORT after 60 probes" >&2
    export VAULTWARDEN_STARTUP_ERROR="Vaultwarden is taking longer than expected to start. Try refreshing in a moment."
fi

# ----------------------------------------------------------------------
# Launch auth-proxy
# ----------------------------------------------------------------------

echo "[start.sh] Starting auth-proxy on 0.0.0.0:8080 -> 127.0.0.1:$ROCKET_PORT"
export AUTH_PROXY_LISTEN_PORT="${AUTH_PROXY_LISTEN_PORT:-8080}"
export AUTH_PROXY_UPSTREAM_HOST="127.0.0.1"
export AUTH_PROXY_UPSTREAM_PORT="$ROCKET_PORT"
python3 /opt/openhost-vaultwarden/auth_proxy.py &
PROXY_PID=$!

# ----------------------------------------------------------------------
# Supervise
# ----------------------------------------------------------------------

trap 'kill -TERM "$VW_PID" "$PROXY_PID" 2>/dev/null; wait' TERM INT

set +e
wait -n "$VW_PID" "$PROXY_PID"
EXIT_CODE=$?
set -e

echo "[start.sh] Child exited (code=$EXIT_CODE); shutting down"
kill -TERM "$VW_PID" "$PROXY_PID" 2>/dev/null || true
wait || true
exit "$EXIT_CODE"
