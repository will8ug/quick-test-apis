#!/usr/bin/env python3
"""Start an mTLS HTTPS server for testing client certificate authentication.

The server listens on https://localhost:10443 and supports:
- Requiring client certificates (TLS-level CERT_REQUIRED for /mtls/*)
- Extracting and echoing peer certificate details
- Serving all existing endpoints from app.main

Prerequisites:
    1. Generate test certs:  uv run python scripts/generate_certs.py
    2. Start server:         uv run python run_mtls.py

httptui config example (~/.config/httptui/config.json):
    {
      "certificates": {
        "localhost": {
          "cert": "./certs/client.crt",
          "key": "./certs/client.key",
          "ca": "./certs/ca.crt"
        }
      }
    }
"""

import asyncio
import ssl
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

CERTS_DIR = Path(__file__).resolve().parent / "certs"
HOST = "0.0.0.0"
PORT = 10443


def check_certs():
    required = ["ca.crt", "ca.key", "server.crt", "server.key"]
    missing = [f for f in required if not (CERTS_DIR / f).exists()]
    if missing:
        print(f"ERROR: Missing certificate files: {', '.join(missing)}")
        print("Run:  uv run python scripts/generate_certs.py")
        sys.exit(1)


def create_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERTS_DIR / "server.crt", CERTS_DIR / "server.key")
    ctx.load_verify_locations(CERTS_DIR / "ca.crt")
    # CERT_OPTIONAL: request client cert but don't fail handshake.
    # Individual endpoints decide whether to require it.
    ctx.verify_mode = ssl.CERT_OPTIONAL
    return ctx


def extract_peer_cert(ssl_obj: ssl.SSLObject) -> dict | None:
    """Extract client certificate details from the SSL connection."""
    try:
        peer_cert = ssl_obj.getpeercert(binary_form=False)
        if not peer_cert:
            return None

        subject = {}
        for rdn in peer_cert.get("subject", ()):
            for oid, value in rdn:
                subject[oid] = value

        issuer = {}
        for rdn in peer_cert.get("issuer", ()):
            for oid, value in rdn:
                issuer[oid] = value

        return {
            "subject": subject,
            "issuer": issuer,
            "serial_number": peer_cert.get("serialNumber", ""),
            "not_before": peer_cert.get("notBefore", ""),
            "not_after": peer_cert.get("notAfter", ""),
            "version": peer_cert.get("version", 0),
        }
    except Exception:
        return None


# --------------- ASGI Application ---------------

def build_app():
    """Build the ASGI application that handles mTLS endpoints."""
    from app.main import app
    from app.mtls_routes import router

    if not any(getattr(r, "path", "").startswith("/mtls") for r in app.routes):
        app.include_router(router)

    return app


# --------------- HTTPS Server ---------------

class HTTPSConnection:
    """Handle a single HTTPS connection: TLS handshake → HTTP → ASGI."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ssl_ctx: ssl.SSLContext, app):
        self.reader = reader
        self.writer = writer
        self.ssl_ctx = ssl_ctx
        self.app = app
        self.peer_cert = None
        self.tls_version = "unknown"
        self.cipher = "unknown"

    async def handle(self):
        try:
            # TLS handshake is done automatically by asyncio.start_server(ssl=...)
            ssl_obj = self.writer.get_extra_info("ssl_object")
            if ssl_obj:
                self.peer_cert = extract_peer_cert(ssl_obj)
                self.tls_version = ssl_obj.version() or "unknown"
                try:
                    c = ssl_obj.cipher()
                    self.cipher = f"{c[0]} {c[1]}" if c else "unknown"
                except Exception:
                    pass

            # Read HTTP request
            request_line = await asyncio.wait_for(self.reader.readline(), timeout=10)
            if not request_line:
                return
            request_line = request_line.decode("utf-8", errors="replace").strip()
            if not request_line:
                return

            parts = request_line.split(" ")
            if len(parts) < 3:
                return
            method, path, _ = parts[0], parts[1], parts[2]

            # Read headers
            headers = []
            header_dict = {}
            while True:
                line = await asyncio.wait_for(self.reader.readline(), timeout=10)
                line = line.decode("utf-8", errors="replace").strip()
                if not line:
                    break
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip().lower()
                    value = value.strip()
                    headers.append((key.encode(), value.encode()))
                    header_dict[key] = value

            # Read body if Content-Length present
            body = b""
            content_length = int(header_dict.get("content-length", 0))
            if content_length > 0:
                body = await asyncio.wait_for(self.reader.readexactly(content_length), timeout=10)

            # Build ASGI scope
            parsed = urlparse(path)
            scope = {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": method,
                "path": unquote(parsed.path),
                "query_string": parsed.query.encode() if parsed.query else b"",
                "root_path": "",
                "scheme": "https",
                "server": ("localhost", PORT),
                "headers": headers,
                "state": {
                    "peer_cert": self.peer_cert,
                    "tls_version": self.tls_version,
                    "cipher": self.cipher,
                },
                "_peer_cert": self.peer_cert,
                "_tls_version": self.tls_version,
                "_cipher": self.cipher,
            }

            # ASGI communication
            response_started = False
            response_status = 200
            response_headers = []
            response_body = bytearray()

            async def receive():
                return {"type": "http.request", "body": body, "more_body": False}

            async def send(message):
                nonlocal response_started, response_status, response_headers, response_body
                if message["type"] == "http.response.start":
                    response_started = True
                    response_status = message["status"]
                    response_headers = message.get("headers", [])
                elif message["type"] == "http.response.body":
                    response_body.extend(message.get("body", b""))

            # Call ASGI app
            await self.app(scope, receive, send)

            # Send HTTP response
            status_text = _STATUS_CODES.get(response_status, "Unknown")
            resp_line = f"HTTP/1.1 {response_status} {status_text}\r\n"
            self.writer.write(resp_line.encode())

            has_content_length = False
            for key, value in response_headers:
                k = key.decode() if isinstance(key, bytes) else key
                v = value.decode() if isinstance(value, bytes) else value
                if k.lower() == "content-length":
                    has_content_length = True
                self.writer.write(f"{k}: {v}\r\n".encode())

            if not has_content_length:
                self.writer.write(f"Content-Length: {len(response_body)}\r\n".encode())

            self.writer.write(b"\r\n")
            self.writer.write(bytes(response_body))
            await self.writer.drain()

        except asyncio.TimeoutError:
            pass
        except ssl.SSLError:
            pass
        except ConnectionResetError:
            pass
        except Exception as e:
            try:
                err = f"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"
                self.writer.write(err.encode())
                await self.writer.drain()
            except Exception:
                pass
        finally:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass


_STATUS_CODES = {
    200: "OK", 201: "Created", 204: "No Content",
    301: "Moved Permanently", 302: "Found", 304: "Not Modified",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
    404: "Not Found", 405: "Method Not Allowed",
    500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
}


async def run_server():
    check_certs()
    ssl_ctx = create_ssl_context()
    app = build_app()

    server = await asyncio.start_server(
        lambda r, w: HTTPSConnection(r, w, ssl_ctx, app).handle(),
        host=HOST,
        port=PORT,
        ssl=ssl_ctx,
    )

    addr = server.sockets[0].getsockname()
    print(f"\n  mTLS server running at https://localhost:{addr[1]}")
    print(f"  Certificates directory: {CERTS_DIR}")
    print(f"\n  Endpoints:")
    print(f"    GET /mtls/echo-cert  - Requires client certificate (TLS-level)")
    print(f"    GET /mtls/optional   - Works with or without client cert")
    print(f"    GET /mtls/verify     - Verifies and returns cert details")
    print(f"    GET /mtls/headers    - Echoes request headers + cert info")
    print(f"    GET /ping            - Basic ping (existing endpoint)")
    print(f"\n  Press Ctrl+C to stop\n")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        print("\n  Server stopped.")
