"""OpenHost auth-proxy for Vaultwarden — Pattern E (no auto-SSO).

Vaultwarden is a self-hosted Bitwarden-compatible password
manager.  Bitwarden's auth model is fundamentally different from
typical web apps: each user's vault is encrypted end-to-end with a
key derived from their **master password**, and the server NEVER
sees the master password in a form that could decrypt the vault.
The client derives the encryption key locally; the server only
sees a "stretched" hash for authentication.

Consequence: traditional SSO patterns (REMOTE_USER injection,
sidecar minting sessions, OIDC bridge, etc.) cannot give the user
access to their vault — even if we forged a perfect Bitwarden
session cookie, the vault would still be ciphertext until the
master password unlocked it client-side.  So we do **NOT** auto-
login.  This is Pattern E from the openhost-app skill.

What this proxy does:

  1. Owner-gating is handled entirely by the OpenHost router (the
     subdomain is private; anonymous visitors get 302'd to the
     parent zone's /login by the router before they reach us).

  2. Defence-in-depth header stripping: client-supplied
     ``X-OpenHost-Is-Owner``, ``X-OpenHost-User``, and
     ``X-Remote-User`` headers are dropped before forwarding to
     Vaultwarden.  Vaultwarden doesn't consult these headers, but
     stripping them shields any future use from header injection.

  3. ``/_healthz`` is served locally as a static 200 — used for
     the OpenHost container health probe so cold-start doesn't
     mark the app as failed while Rocket is still binding.

  4. ``Host`` header is rewritten from ``X-Forwarded-Host`` so
     Vaultwarden's URL generation matches the public hostname.

  5. ``X-Forwarded-Proto: https`` is enforced upstream so
     Vaultwarden knows the public-facing scheme is HTTPS (relevant
     for cookies marked Secure and for the DOMAIN env var
     consistency check).

  6. WebSocket upgrades are tunneled — Vaultwarden's notifications
     channel (push messages to logged-in clients) uses ws:// to
     ``/notifications/hub``.  The proxy detects ``Upgrade:
     websocket`` and switches into raw-socket bridging mode.

  7. Streaming-response forwarding for arbitrarily-large bodies
     (vault attachments, Send file uploads).  We do NOT buffer the
     whole body in memory.

The user experience: the owner navigates to vaultwarden.<zone>/,
the router admits them (X-OpenHost-Is-Owner: true), this proxy
forwards to Vaultwarden, and Vaultwarden serves its normal web-
vault login page.  The owner enters their master password.
That's it — by design.
"""

from __future__ import annotations

import http.client
import logging
import os
import select
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import AbstractSet, Iterable

# Header names we strip from inbound requests.  None of these are
# trusted by Vaultwarden, but stripping them is cheap insurance
# against future code that might consult them.
OWNER_HEADER_NAME = "X-OpenHost-Is-Owner"
USER_HEADER_NAME = "X-OpenHost-User"
REMOTE_USER_HEADER_NAME = "X-Remote-User"

HOP_BY_HOP_HEADERS = frozenset(
    h.lower()
    for h in (
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
        "Host",
        "Content-Length",
    )
)

# Headers a hostile client must never inject.  ALWAYS stripped.
ALWAYS_STRIP_HEADERS = frozenset(
    h.lower()
    for h in (
        OWNER_HEADER_NAME,
        USER_HEADER_NAME,
        REMOTE_USER_HEADER_NAME,
        "Remote-User",
    )
)

CLIENT_READ_TIMEOUT_SECONDS = 300
WEBSOCKET_IDLE_TIMEOUT_SECONDS = 600
STREAM_CHUNK_SIZE = 64 * 1024

logging.basicConfig(
    level=os.environ.get("AUTH_PROXY_LOG_LEVEL", "INFO"),
    format="[auth-proxy] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("auth_proxy")


def _strip_headers(
    headers: Iterable[tuple[str, str]], drop: AbstractSet[str]
) -> list[tuple[str, str]]:
    drop_lower = {h.lower() for h in drop}
    return [(k, v) for k, v in headers if k.lower() not in drop_lower]


class AuthProxyHandler(BaseHTTPRequestHandler):
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 8088
    # Override the default HTTP/1.0 — Vaultwarden's Rocket runtime
    # supports HTTP/1.1 keep-alive, and the Bitwarden web vault
    # SPA holds many parallel requests open.  We don't rely on
    # keep-alive between proxy<->upstream, but we DO need to speak
    # HTTP/1.1 to the client so chunked streaming works.
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:  # noqa: A002, N802
        path = getattr(self, "path", "")
        if path.startswith("/_healthz"):
            return
        log.info("%s - " + format, self.address_string(), *args)

    # All HTTP verbs route through _dispatch.  We list the common
    # ones; vaultwarden uses GET/POST/PUT/DELETE for its API and
    # OPTIONS for CORS preflight (relevant for the browser
    # extension hitting /api/* across origins).
    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch()

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._dispatch()

    def _safe_send_error(self, code: int, message: str) -> None:
        try:
            self.send_error(code, message)
        except OSError as exc:
            log.debug("client disconnected before error response: %s", exc)

    def _is_websocket_upgrade(self) -> bool:
        connection = self.headers.get("Connection", "").lower()
        upgrade = self.headers.get("Upgrade", "").lower().strip()
        return "upgrade" in connection and upgrade == "websocket"

    def _dispatch(self) -> None:
        try:
            self.connection.settimeout(CLIENT_READ_TIMEOUT_SECONDS)
        except OSError:
            pass

        path_only = self.path.split("?", 1)[0]
        if path_only == "/_healthz":
            try:
                body = b'{"status":"ok"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
            except OSError as exc:
                log.debug("/_healthz client disconnected: %s", exc)
            return

        if self._is_websocket_upgrade():
            self._proxy_websocket()
            return

        self._proxy()

    # ------------------------------------------------------------
    # Plain HTTP forwarding (streaming bodies in both directions)
    # ------------------------------------------------------------

    def _build_upstream_headers(self) -> list[tuple[str, str]]:
        cleaned_headers = _strip_headers(
            self.headers.items(),
            HOP_BY_HOP_HEADERS | ALWAYS_STRIP_HEADERS,
        )
        # Rewrite Host from X-Forwarded-Host so Vaultwarden's
        # generated URLs (password reset links, attachment URLs)
        # match the public hostname.
        forwarded_host = self.headers.get("X-Forwarded-Host", "").strip()
        if forwarded_host:
            cleaned_headers.append(("Host", forwarded_host))
        # Force X-Forwarded-Proto: https so Vaultwarden knows the
        # public scheme.  The OpenHost router terminates TLS, so
        # the loopback connection is plain HTTP — without this
        # header Vaultwarden would mis-attribute the scheme.
        # If the client sent its own X-Forwarded-Proto the cleaned
        # list still contains it; we ALSO append our authoritative
        # value, and rely on the upstream to take the last one.
        # (Rocket uses the last X-Forwarded-Proto header.)
        cleaned_headers = [
            (k, v)
            for k, v in cleaned_headers
            if k.lower() != "x-forwarded-proto"
        ]
        cleaned_headers.append(("X-Forwarded-Proto", "https"))
        return cleaned_headers

    def _proxy(self) -> None:
        cleaned_headers = self._build_upstream_headers()

        transfer_encoding = (
            self.headers.get("Transfer-Encoding", "").lower().strip()
        )
        is_chunked = transfer_encoding == "chunked"

        content_length: int | None = None
        if not is_chunked:
            cl_header = self.headers.get("Content-Length")
            if cl_header is not None:
                try:
                    content_length = int(cl_header)
                except ValueError:
                    self._safe_send_error(400, "invalid Content-Length")
                    return
                if content_length < 0:
                    self._safe_send_error(400, "negative Content-Length")
                    return
            elif self.command in ("POST", "PUT", "PATCH"):
                content_length = 0

        try:
            conn = http.client.HTTPConnection(
                self.upstream_host, self.upstream_port, timeout=300
            )
        except OSError as exc:
            log.warning("upstream connect error: %s", exc)
            self._safe_send_error(502, "Bad Gateway")
            return

        try:
            try:
                conn.putrequest(
                    self.command,
                    self.path,
                    skip_host=True,
                    skip_accept_encoding=True,
                )
                for key, value in cleaned_headers:
                    if key.lower() == "host":
                        conn.putheader(key, value)
                # Add explicit Host if it wasn't supplied via
                # X-Forwarded-Host (loopback fallback).
                if not any(k.lower() == "host" for k, _ in cleaned_headers):
                    conn.putheader(
                        "Host", f"{self.upstream_host}:{self.upstream_port}"
                    )
                for key, value in cleaned_headers:
                    if key.lower() == "host":
                        continue
                    conn.putheader(key, value)
                if is_chunked:
                    conn.putheader("Transfer-Encoding", "chunked")
                elif content_length is not None:
                    conn.putheader("Content-Length", str(content_length))
                conn.endheaders()

                # Stream request body upstream.
                if is_chunked:
                    self._stream_chunked_body_upstream(conn)
                elif content_length is not None and content_length > 0:
                    self._stream_fixed_body_upstream(conn, content_length)

                upstream = conn.getresponse()
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream error during request: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return

            # Stream the upstream response back to the client.
            try:
                self.send_response(upstream.status, upstream.reason or "")
                resp_headers_lower = {
                    k.lower() for k, _ in upstream.getheaders()
                }
                for key, value in upstream.getheaders():
                    kl = key.lower()
                    if kl in HOP_BY_HOP_HEADERS:
                        continue
                    self.send_header(key, value)
                # If the upstream didn't supply Content-Length and
                # didn't supply Transfer-Encoding, force chunked so
                # we can stream without knowing the size in advance.
                upstream_has_cl = "content-length" in resp_headers_lower
                upstream_has_te = any(
                    k.lower() == "transfer-encoding"
                    for k, v in upstream.getheaders()
                    if v.lower().strip() != "identity"
                )
                if not upstream_has_cl and not upstream_has_te:
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    if self.command != "HEAD":
                        self._stream_response_chunked_to_client(upstream)
                else:
                    self.end_headers()
                    if self.command != "HEAD":
                        self._stream_response_to_client(upstream)
            except OSError as exc:
                log.debug("client disconnected mid-response: %s", exc)
            finally:
                try:
                    upstream.close()
                except Exception as exc:  # noqa: BLE001
                    log.debug("upstream.close() raised (ignored): %s", exc)
        finally:
            conn.close()

    def _stream_fixed_body_upstream(
        self, conn: http.client.HTTPConnection, length: int
    ) -> None:
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(STREAM_CHUNK_SIZE, remaining))
            if not chunk:
                raise OSError("client closed before sending full body")
            conn.send(chunk)
            remaining -= len(chunk)

    def _stream_chunked_body_upstream(
        self, conn: http.client.HTTPConnection
    ) -> None:
        # http.client doesn't expose a chunked-write helper that
        # plays nicely with putrequest(), so we manually frame.
        while True:
            size_line = self.rfile.readline().strip()
            if not size_line:
                raise OSError("client sent empty chunk size line")
            try:
                size = int(size_line.split(b";", 1)[0], 16)
            except ValueError as exc:
                raise OSError(f"invalid chunk size {size_line!r}") from exc
            conn.send(size_line + b"\r\n")
            if size == 0:
                # Optional trailers, terminated by empty line.
                while True:
                    trailer = self.rfile.readline()
                    conn.send(trailer)
                    if trailer in (b"\r\n", b"\n", b""):
                        break
                return
            remaining = size
            while remaining > 0:
                chunk = self.rfile.read(min(STREAM_CHUNK_SIZE, remaining))
                if not chunk:
                    raise OSError("client closed mid-chunk")
                conn.send(chunk)
                remaining -= len(chunk)
            tail = self.rfile.read(2)  # trailing \r\n after chunk data
            conn.send(tail)

    def _stream_response_to_client(
        self, upstream: http.client.HTTPResponse
    ) -> None:
        while True:
            chunk = upstream.read(STREAM_CHUNK_SIZE)
            if not chunk:
                break
            self.wfile.write(chunk)

    def _stream_response_chunked_to_client(
        self, upstream: http.client.HTTPResponse
    ) -> None:
        while True:
            chunk = upstream.read(STREAM_CHUNK_SIZE)
            if not chunk:
                self.wfile.write(b"0\r\n\r\n")
                break
            self.wfile.write(f"{len(chunk):x}\r\n".encode("ascii"))
            self.wfile.write(chunk)
            self.wfile.write(b"\r\n")

    # ------------------------------------------------------------
    # WebSocket tunneling
    #
    # Vaultwarden uses a WebSocket connection from each logged-in
    # client to /notifications/hub for push notifications (vault
    # changed, item added by another device, etc.).  Once Vaultwarden
    # responds with 101 Switching Protocols we go into raw-socket
    # bridging mode: bytes from the client get written to the
    # upstream socket and vice versa, indefinitely, until either
    # side closes.
    # ------------------------------------------------------------

    def _proxy_websocket(self) -> None:
        cleaned_headers = self._build_upstream_headers()

        try:
            upstream_sock = socket.create_connection(
                (self.upstream_host, self.upstream_port), timeout=30
            )
        except OSError as exc:
            log.warning("websocket upstream connect failed: %s", exc)
            self._safe_send_error(502, "Bad Gateway")
            return

        try:
            # Forward the original handshake verbatim (with sanitised
            # headers) using raw sockets — http.client's getresponse
            # consumes the response body, which is wrong for the
            # 101 handshake.
            request_lines = [f"{self.command} {self.path} HTTP/1.1"]
            for key, value in cleaned_headers:
                request_lines.append(f"{key}: {value}")
            request_lines.append("")
            request_lines.append("")
            handshake = "\r\n".join(request_lines).encode("iso-8859-1")
            upstream_sock.sendall(handshake)

            # Read the 101 response into a buffer up to \r\n\r\n.
            response_buf = b""
            upstream_sock.settimeout(30)
            while b"\r\n\r\n" not in response_buf:
                more = upstream_sock.recv(4096)
                if not more:
                    raise OSError("upstream closed before 101 handshake")
                response_buf += more
                if len(response_buf) > 65536:
                    raise OSError("upstream handshake too large")

            header_end = response_buf.index(b"\r\n\r\n") + 4
            handshake_resp = response_buf[:header_end]
            leftover = response_buf[header_end:]

            try:
                self.wfile.write(handshake_resp)
                if leftover:
                    self.wfile.write(leftover)
                self.wfile.flush()
            except OSError as exc:
                log.debug("client disconnected before 101 forwarded: %s", exc)
                return

            status_line = handshake_resp.split(b"\r\n", 1)[0]
            if b" 101 " not in status_line:
                # Upstream rejected the upgrade; we already forwarded
                # the response, no further bridging needed.
                return

            self._bridge_sockets(self.connection, upstream_sock)
        finally:
            try:
                upstream_sock.close()
            except OSError:
                pass

    @staticmethod
    def _bridge_sockets(client_sock: socket.socket, upstream_sock: socket.socket) -> None:
        client_sock.settimeout(None)
        upstream_sock.settimeout(None)
        sockets = [client_sock, upstream_sock]
        try:
            while True:
                readable, _, errored = select.select(
                    sockets, [], sockets, WEBSOCKET_IDLE_TIMEOUT_SECONDS
                )
                if not readable and not errored:
                    # idle timeout; keep going (Bitwarden sends pings
                    # roughly every 30s once a vault is unlocked).
                    continue
                if errored:
                    return
                for src in readable:
                    try:
                        data = src.recv(STREAM_CHUNK_SIZE)
                    except OSError:
                        return
                    if not data:
                        return
                    dst = upstream_sock if src is client_sock else client_sock
                    try:
                        dst.sendall(data)
                    except OSError:
                        return
        except (OSError, ValueError):
            return


class IPv4ThreadingServer(ThreadingHTTPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True


def _port_from_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name}={raw!r} is not an integer: {exc}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{name}={raw!r} is out of range (1-65535)")
    return port


def main() -> int:
    try:
        listen_port = _port_from_env("AUTH_PROXY_LISTEN_PORT", 8080)
        upstream_port = _port_from_env("AUTH_PROXY_UPSTREAM_PORT", 8088)
    except ValueError as exc:
        log.error("invalid port configuration: %s", exc)
        return 1

    upstream_host = os.environ.get(
        "AUTH_PROXY_UPSTREAM_HOST", "127.0.0.1"
    ).strip()

    AuthProxyHandler.upstream_host = upstream_host
    AuthProxyHandler.upstream_port = upstream_port

    try:
        server = IPv4ThreadingServer(
            ("0.0.0.0", listen_port), AuthProxyHandler
        )
    except OSError as exc:
        log.error(
            "failed to bind auth-proxy listener on 0.0.0.0:%d: %s",
            listen_port,
            exc,
        )
        return 1

    log.info(
        "listening on 0.0.0.0:%d -> %s:%d (Pattern E: no auto-SSO)",
        listen_port,
        upstream_host,
        upstream_port,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


# Ensure thread reference is unused-removed by the linter (some
# stdlib stubs flag `threading` as unused if we don't reference it).
_ = threading.Lock

if __name__ == "__main__":
    sys.exit(main())
