import hashlib
import hmac
import re
import subprocess
import time
from urllib.parse import urlparse

import requests
from openhost_test_harness import OpenhostStack


def _anonymous(
    stack: OpenhostStack, method: str, path: str, headers: dict[str, str] | None = None, json: object = None
) -> requests.Response:
    """A request without the owner cookie, retrying while Vaultwarden finishes booting behind the proxy."""
    deadline = time.monotonic() + 90
    while True:
        try:
            response = requests.request(
                method, f"{stack.url}{path}", headers=headers, json=json, allow_redirects=False, timeout=30
            )
            if response.status_code < 500 or time.monotonic() > deadline:
                return response
        except requests.ConnectionError:
            if time.monotonic() > deadline:
                raise
        time.sleep(2)


def test_web_vault_and_admin_are_owner_only(stack: OpenhostStack) -> None:
    """Only the Bitwarden client APIs are in public_paths; the web vault and /admin redirect to the router login."""
    router = urlparse(stack.router_url).netloc
    for path in ("/", "/admin"):
        response = _anonymous(stack, "GET", path, headers={"Accept": "text/html"})
        location = urlparse(response.headers.get("Location", ""))
        assert response.status_code in (302, 303, 307) and (location.netloc, location.path) == (router, "/login"), (
            f"anonymous GET {path}: {response.status_code} Location={response.headers.get('Location')!r}"
        )


def test_native_clients_reach_the_api_anonymously(stack: OpenhostStack) -> None:
    """Bitwarden apps carry their own tokens, not the owner cookie: /api/ and /identity/ must work without it."""
    config = _anonymous(stack, "GET", "/api/config")
    assert config.status_code == 200, f"anonymous /api/config: {config.status_code}: {config.text[:300]}"
    prelogin = _anonymous(stack, "POST", "/identity/accounts/prelogin", json={"email": "someone@example.com"})
    assert prelogin.status_code == 200 and "kdf" in prelogin.json(), f"{prelogin.status_code}: {prelogin.text[:300]}"


def test_config_derived_from_the_zone(stack: OpenhostStack) -> None:
    """DOMAIN (the URL clients are told to use) comes from the zone, and signups are open for the owner's account."""
    config = stack.owner_session.get(f"{stack.url}/api/config", timeout=30)
    assert config.status_code == 200, f"/api/config: {config.status_code}: {config.text[:300]}"
    vault_url = config.json()["environment"]["vault"]
    # Production zones are https; the harness serves http, so compare only the host (and port).
    assert urlparse(vault_url).netloc == urlparse(stack.url).netloc, f"DOMAIN {vault_url!r} vs app {stack.url!r}"
    assert config.json()["settings"]["disableUserRegistration"] is False, config.text[:500]


# Vaultwarden's KDF for new accounts (User::CLIENT_KDF_TYPE_DEFAULT / CLIENT_KDF_ITER_DEFAULT): PBKDF2-SHA256, 600000.
DEFAULT_KDF = {"kdf": 0, "kdfIterations": 600_000, "kdfMemory": None, "kdfParallelism": None}
WEAK_FAKE_KDF_INDEX = 3  # PBKDF2 5000 in unknown_email_kdf's list (src/api/core/accounts.rs, 1.37.x)


def _fake_kdf_index(rsa_key_pem: bytes, email: str) -> int:
    """Which of unknown_email_kdf's six settings Vaultwarden gives `email` (src/auth.rs prelogin_kdf_index)."""
    key = hmac.new(rsa_key_pem, b"prelogin-kdf", hashlib.sha256).digest()
    tag = hmac.new(key, email.encode(), hashlib.sha256).digest()
    return int.from_bytes(tag[:2], "big") % 6


def test_get_prelogin_shim_returns_the_default_kdf(stack: OpenhostStack) -> None:
    """auth_proxy.py answers GET prelogin/password with Vaultwarden's default KDF, never a per-instance fake one.

    Vaultwarden >= 1.37 answers prelogin for an unknown email with one of six KDF settings picked by an HMAC keyed
    from rsa_key.pem, one of them PBKDF2 at 5000 iterations. To exercise that case on every run, pad the key file
    (OpenSSL ignores trailing newlines) until the empty email maps to it, restart, and check upstream agrees.
    """
    key_file = stack.data_dir / "rsa_key.pem"
    pem = key_file.read_bytes().rstrip(b"\n") + b"\n"
    while _fake_kdf_index(pem, "") != WEAK_FAKE_KDF_INDEX:
        pem += b"\n"
    key_file.write_bytes(pem)
    subprocess.run(["podman", "restart", stack.container_name], check=True, capture_output=True, timeout=120)

    upstream = _anonymous(stack, "POST", "/identity/accounts/prelogin", json={"email": ""})
    assert upstream.status_code == 200, f"{upstream.status_code}: {upstream.text[:300]}"
    assert (upstream.json()["kdf"], upstream.json()["kdfIterations"]) == (0, 5000), (
        f"seeding the weak fake KDF didn't take; did upstream change unknown_email_kdf? {upstream.text[:300]}"
    )

    shim = stack.owner_session.get(f"{stack.url}/identity/accounts/prelogin/password", timeout=30)
    assert shim.status_code == 200, f"{shim.status_code}: {shim.text[:300]}"
    body = shim.json()
    assert {k: body.get(k) for k in DEFAULT_KDF} == DEFAULT_KDF, f"GET prelogin/password: {shim.text[:300]}"
    settings = body.get("kdfSettings") or {}
    assert (settings.get("kdfType"), settings.get("iterations")) == (0, 600_000), f"kdfSettings: {shim.text[:300]}"


def test_admin_token_from_the_logs_opens_the_admin_panel(stack: OpenhostStack) -> None:
    """start.sh generates an admin token, prints it to the logs and passes Vaultwarden an Argon2 hash of it."""
    tokens = re.findall(r"\[start\.sh\]\s+([A-Za-z0-9_-]{43})\s*$", stack.app_logs(), re.MULTILINE)
    assert tokens, f"no admin token in the app logs:\n{stack.app_logs()[-3000:]}"
    response = stack.owner_session.post(
        f"{stack.url}/admin", data={"token": tokens[-1]}, allow_redirects=False, timeout=30
    )
    assert response.status_code in (200, 303) and "VW_ADMIN=" in response.headers.get("Set-Cookie", ""), (
        f"admin login with the logged token: {response.status_code}: {response.text[:500]}"
    )


def test_data_is_stored_in_app_data(stack: OpenhostStack) -> None:
    """DATA_FOLDER is the app data dir, so vaults, keys and attachments survive redeploys and updates."""
    _anonymous(stack, "GET", "/api/config")
    names = sorted(p.name for p in stack.data_dir.iterdir())
    assert "db.sqlite3" in names and "admin_token.txt" in names, f"app data dir: {names}"
