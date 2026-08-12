# bottled-vaultwarden

[Vaultwarden](https://github.com/dani-garcia/vaultwarden) — a self-hosted
Bitwarden-compatible password manager — packaged for Cloud in a Bottle.

## What this gives you

- A Vaultwarden server reachable at `https://vaultwarden.<your-zone>/`.
- The Cloud in a Bottle zone_auth gate keeps the subdomain private to the owner —
  anonymous visitors are bounced to Cloud in a Bottle's `/login` and never reach
  the Vaultwarden web vault.
- Persistent state (database, attachments, RSA signing key, admin token)
  under `$OPENHOST_APP_DATA_DIR` (`/data/app_data/vaultwarden/`), so the
  vault survives container rebuilds and Cloud in a Bottle upgrades.
- A pre-generated `/admin` panel token printed to the container logs
  on first boot.

## Auth model — Pattern E (no auto-SSO), and why

Vaultwarden / Bitwarden's auth model is fundamentally different from
typical web apps. **Each user's vault is end-to-end encrypted with a
key derived from the user's MASTER PASSWORD, and the master password
NEVER touches the server in a form that could decrypt the vault.**
The Bitwarden client derives the encryption key locally and the server
only ever sees a "stretched" hash of the master password used purely
for authentication.

This means: **traditional SSO patterns cannot give the user access to
their vault.** Even if we forged a perfect Bitwarden session cookie
(Pattern B2 — DB-direct INSERT into the device/session table), the
user's vault items would still be ciphertext until the master password
unlocked them client-side. The session would be authenticated but
useless.

So this Cloud in a Bottle package uses **Pattern E** from the
[openhost-app skill](https://opencode.ai/docs):

- **Owner gating** is handled entirely by the Cloud in a Bottle router. Anonymous
  visitors hit zone_auth and bounce to `/login` on the parent zone before
  they even reach this app.
- **Authentication into Vaultwarden** is the user's normal master-password
  login at the Vaultwarden web vault. There is **no auto-login dance**
  and **no magic** — the owner sees the standard Bitwarden web vault
  login screen and types their master password.
- **Vault decryption** happens client-side, as designed.

This is the right trade-off for a password manager: any "auto-unlock"
mechanism would either (a) require persisting the master password
somewhere on the server (a self-defeating compromise of the entire
threat model) or (b) only authenticate the user without decrypting the
vault (giving the user a logged-in but empty-looking vault and a
confusing UX).

If you want true SSO into Vaultwarden, the upstream community fork
[Timshel/vaultwarden](https://github.com/Timshel/vaultwarden) adds
OpenIDConnect support, but even that requires the user to enter their
master password after SSO — the SSO step gates *who can attempt to
authenticate*, but the master password gates *who can actually decrypt
the vault*. That's a layered model the official Vaultwarden upstream
hasn't merged, and a more invasive integration than Pattern E.

## First-time setup (operator)

1. **Deploy this app** via `oh app deploy` (see the bottom of this README
   for the exact command).

2. **Find the admin token.** Tail the container logs after first boot
   and look for the block that prints
   `Vaultwarden /admin token (for the diagnostic panel):` — copy the
   token. It's also persisted to
   `$OPENHOST_APP_DATA_DIR/admin_token.txt` so you can `cat` it later.

   You don't *need* the admin token for normal use — it only protects
   `/admin`, the server-side diagnostic panel. It is **not** a vault
   credential and granting it to someone does **not** give vault
   access.

3. **Configure Bitwarden clients.** In the Bitwarden mobile app /
   browser extension / desktop app, change the **Server URL** to
   `https://vaultwarden.<your-zone>/`. By default, it shows
   `Accessing: bitwarden.com`. 
   
   Then, proceed with a typical registration, setting a strong
   master password. 

   ⚠ **Your master password is the ONLY way to decrypt your vault.
   Vaultwarden cannot reset or recover it. Write it down somewhere
   safe (offline) before you trust it with real secrets.**

4. **Disable signups.** Once you (and any people you want to give
   accounts to) have registered, set `SIGNUPS_ALLOWED=false`. The
   easiest way is via `/admin` → General Settings → toggle "Allow
   new signups" off → Save. (Alternatively, redeploy with the env
   override, which the Cloud in a Bottle manifest supports per-instance.)

## Useful URLs

| Path | What |
|---|---|
| `/` | Web vault (login form) |
| `/admin` | Server-admin diagnostic panel (admin-token gated) |
| `/api/version` | Plain-text Vaultwarden version (for verification) |
| `/_healthz` | Auth-proxy local health endpoint (used by the Cloud in a Bottle router) |

## Container topology

```
browser → https://vaultwarden.<zone>/  (zone_auth gate)
       → container :8080  (auth_proxy.py — Pattern E pass-through)
       → 127.0.0.1:8088  (vaultwarden / Rocket)
```

The auth-proxy:
- Strips inbound `X-OpenHost-Is-Owner`, `X-OpenHost-User`, `X-Remote-User`
  headers as defence-in-depth (the Cloud in a Bottle router strips them too,
  but cheap insurance).
- Rewrites `Host:` from `X-Forwarded-Host` so Vaultwarden's URL
  generation matches the public hostname.
- Forces `X-Forwarded-Proto: https` upstream so Vaultwarden knows the
  public scheme is HTTPS.
- Sets `X-Real-IP` (Vaultwarden's default `IP_HEADER`) to the real
  client IP, derived from the **trusted** `X-Forwarded-For` that the
  Cloud in a Bottle compute space sets, and **drops any client-supplied**
  `X-Real-IP`. This matters for security: Vaultwarden rate-limits login
  attempts per client IP on the public `/identity/` endpoint. Without
  this, Vaultwarden would either see every client as `127.0.0.1` (so one
  user's failed logins could trip the global limiter and lock everyone
  out) or — worse — honour a client-spoofable `X-Real-IP`, letting an
  attacker rotate the header to bypass brute-force rate limiting
  entirely. Deriving it from the unspoofable `X-Forwarded-For` fixes
  both.
- Tunnels WebSocket upgrades for `/notifications/hub` (Bitwarden's push
  channel for "new item added on another device" prompts).
- Serves `/_healthz` locally as a static 200 so cold-start doesn't get
  the container marked failed before Rocket finishes binding.

There is **no** auto-login, **no** session minting, **no** REMOTE_USER
header injection, and **no** OIDC bridge — by design.

## Persistent data layout

All under `$OPENHOST_APP_DATA_DIR` (`/data/app_data/vaultwarden/`):

| File | What |
|---|---|
| `db.sqlite3` | Vault metadata, users, ciphers, organizations |
| `attachments/` | Encrypted file attachments per cipher |
| `sends/` | Bitwarden Send (encrypted file/text shares) |
| `rsa_key.pem`, `rsa_key.pub` | Vaultwarden's JWT signing key |
| `admin_token.txt` | The `/admin` panel access token (mode 0600) |
| `icon_cache/` | Cached favicons for vault entries |

`admin_token.txt` is intentionally persisted so it survives image
rebuilds — otherwise every redeploy would invalidate the token you
saved in your password manager. It's mode 0600 to make it harder for
co-located apps with `app_data` permission to read it. Even if they
could, it only grants access to `/admin`, never to vault data.

## Deployment

```
oh app deploy --wait --name vaultwarden \
  https://github.com/imbue-openhost/bottled-vaultwarden
```

Reload after a code change:

```
oh app reload --update --wait vaultwarden
```

## Verification

```bash
TOKEN=<your-zone-bearer-token>
HOST=vaultwarden.<your-zone>

# Owner request: should land on the Vaultwarden web vault login form
# (NOT OpenHost's /login).  This is Pattern E in action — the owner is
# admitted past zone_auth, and Vaultwarden serves its native login UI.
rm -f /tmp/jar
curl -sk -H "Authorization: Bearer $TOKEN" -H "Accept: text/html" \
  -L --max-redirs 10 -c /tmp/jar -b /tmp/jar -o /tmp/r.html \
  "https://$HOST/" -w 'HTTP=%{http_code}\nFINAL=%{url_effective}\n'
grep -oE '<title>[^<]+</title>' /tmp/r.html
# Expect: HTTP=200, FINAL=https://$HOST/#/login (or similar), title
# containing "Vaultwarden" or "Bitwarden".

# Anonymous request: should bounce to OpenHost /login.
curl -sk -H "Accept: text/html" \
  -L --max-redirs 10 -o /tmp/anon.html \
  "https://$HOST/" -w 'HTTP=%{http_code}\nFINAL=%{url_effective}\n'
# Expect: FINAL ending in /login on the parent zone.

# /api/version: plain-text Vaultwarden version.
curl -sk -H "Authorization: Bearer $TOKEN" "https://$HOST/api/version"
```
