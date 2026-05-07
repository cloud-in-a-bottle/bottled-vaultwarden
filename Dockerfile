# openhost-vaultwarden — Vaultwarden (self-hosted Bitwarden) for OpenHost.
#
# Topology:
#
#   browser → https://vaultwarden.<zone>/  → container :8080
#                                          → 127.0.0.1:8088 (vaultwarden / Rocket)
#
# Pattern E — no auto-SSO.  The OpenHost zone_auth gate keeps the
# subdomain private; the user logs in to Vaultwarden with their
# MASTER PASSWORD because vaults are end-to-end encrypted and the
# master password is the vault key.  Server-side SSO would be
# meaningless: even if we minted a Bitwarden session, the vault
# contents would still be ciphertext until the master password
# unlocked them client-side.
#
# The auth-proxy sidecar is a defence-in-depth pass-through:
# strips inbound X-OpenHost-* / X-Remote-User headers (the router
# also strips them, but cheap belt-and-braces), serves /_healthz
# locally as a static 200, and otherwise forwards everything
# verbatim — including WebSocket upgrades for the Bitwarden
# notifications channel — to upstream Vaultwarden.

FROM docker.io/vaultwarden/server:latest

# Install python3 (for the auth-proxy sidecar) + tini (PID-1 signal
# forwarder).  The vaultwarden upstream image is Debian-based.
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends \
        python3 \
        tini \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY auth_proxy.py /opt/openhost-vaultwarden/auth_proxy.py
COPY start.sh      /opt/openhost-vaultwarden/start.sh

# OpenHost-routed port.
EXPOSE 8080

# tini as PID 1 so SIGTERM forwards to start.sh's children cleanly.
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/openhost-vaultwarden/start.sh"]
