#!/usr/bin/env python3
"""Real protocol-level XHTTP data-plane test.

Starts the actual Lumen app (real FastAPI + Uvicorn wheels) on an ephemeral
port, then speaks both uplink shapes and the auto alias end to end against a
local TCP target. Also verifies the HTTP CONNECT hop, invalid
credentials/session handling, and cleanup. An HTTP 200 alone is not accepted:
the test asserts the exact byte stream, the session-ID contract, and
active-connection accounting.
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import os
import secrets
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="lumen-xhttp-e2e-")
os.environ["PORT"] = "0"  # unused by this test; uvicorn picks the port directly

import main     # noqa: E402
import relay_xhttp  # noqa: E402

failures = []


def check(name, cond, detail=""):
    print(("  ok   " if cond else "  FAIL ") + name + (("  " + detail) if detail and not cond else ""))
    if not cond:
        failures.append(name)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


STREAM_PREFIX = b"\x00\x00"


def build_vless_header(uid: str, host: str, port: int, payload: bytes = b"") -> bytes:
    header = bytearray()
    header.append(0)                                    # version
    header.extend(bytes.fromhex(uid.replace("-", "")))  # uuid (16 bytes)
    header.append(0)                                    # addon length
    header.append(1)                                    # command TCP
    header.extend(port.to_bytes(2, "big"))
    header.append(1)                                    # address type 1 = IPv4
    header.extend(ipaddress.IPv4Address(host).packed)
    return bytes(header) + payload


ECHO_PORT = free_port()
APP_PORT = free_port()


async def echo_server():
    async def handle(reader, writer):
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", ECHO_PORT)
    async with server:
        await server.serve_forever()


def start_app():
    import uvicorn

    config = uvicorn.Config(
        main.app, host="127.0.0.1", port=APP_PORT, log_level="error", workers=1,
        ws="auto", lifespan="off",
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", APP_PORT), timeout=0.2):
                return server
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("uvicorn did not start")


# ── echo target in a background thread ───────────────────────────────────────
echo_thread_loop = asyncio.new_event_loop()

def _run_echo():
    asyncio.set_event_loop(echo_thread_loop)
    echo_thread_loop.run_until_complete(echo_server())

echo_thread = threading.Thread(target=_run_echo, daemon=True)
echo_thread.start()
time.sleep(0.2)

UUID = "3b2e5f60-9c1d-4c4a-8b0e-7d2f6a1b9c3d"
main.LINKS[UUID] = {
    "label": "xhttp-e2e",
    "limit_bytes": 0,
    "used_bytes": 0,
    "active": True,
    "expires_at": None,
    "protocol": "xhttp-packet-up",
    "transport_settings": {},
    "ip_limit": 0,
    "speed_limit_bytes": 0,
    "address": "",
    "sni": "",
    "exit_proxy_mode": "direct", "proxy_id": "", "custom_proxy": "",
}
main.ensure_default_link()

start_app()
BASE_HOST = "127.0.0.1"
BASE = f"http://{BASE_HOST}:{APP_PORT}"

CRLF = b"\r\n"


def _dechunk(data: bytes) -> bytes:
    body = b""
    while True:
        line_end = data.find(CRLF)
        if line_end < 0:
            return body
        size_hex = data[:line_end].split(b";")[0].strip()
        try:
            size = int(size_hex, 16)
        except ValueError:
            return data  # not chunked
        if size == 0:
            return body
        body += data[line_end + 2 : line_end + 2 + size]
        data = data[line_end + 2 + size + 2 :]


def http_raw_stream(
    method: str,
    path: str,
    body: bytes | None = None,
    headers: dict | None = None,
    first_timeout: float = 5.0,
    idle_timeout: float = 1.5,
    max_bytes: int = 1 << 20,
):
    """Raw HTTP/1.1 that stops reading after an idle gap instead of waiting for
    an unbounded stream to end."""
    req = (f"{method} {path} HTTP/1.1\r\n"
           f"Host: {BASE_HOST}:{APP_PORT}\r\n"
           "Connection: close\r\n"
           "Accept: */*\r\n"
           f"Content-Length: {len(body or b'')}\r\n")
    for k, v in (headers or {}).items():
        req += f"{k}: {v}\r\n"
    req += "\r\n"
    sock = socket.create_connection((BASE_HOST, APP_PORT), timeout=first_timeout)
    sock.sendall(req.encode() + (body or b""))
    buf = b""
    sock.settimeout(first_timeout)
    while b"\r\n\r\n" not in buf:
        data = sock.recv(65536)
        if not data:
            break
        buf += data
    header, _, rest = buf.partition(b"\r\n\r\n")
    lines = header.split(b"\r\n")
    status = int(lines[0].split()[1])
    hdrs = {}
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            hdrs[k.decode().strip().lower()] = v.decode().strip()
    sock.settimeout(idle_timeout)
    while len(rest) < max_bytes:
        try:
            data = sock.recv(65536)
        except (socket.timeout, ConnectionError, OSError):
            break
        if not data:
            break
        rest += data
    sock.close()
    if hdrs.get("transfer-encoding", "").lower() == "chunked":
        rest = _dechunk(rest)
    return status, hdrs, rest


def http_json(method: str, path: str, body: bytes | None = None, headers: dict | None = None, timeout: float = 10):
    """Full-body (buffered) request for endpoints that terminate normally."""
    req = urllib.request.Request(BASE + path, data=body, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


# ── 1. packet-up full cycle ───────────────────────────────────────────────────
print("[packet-up]")
# 1.1 POST-first flow (as real XHTTP clients behave): the client allocates the
# session id and opens the upstream with the VLESS header packet (seq 0).
payload = b"ping-over-packet-up"
sess_id = base64.urlsafe_b64encode(secrets.token_bytes(9)).decode().rstrip("=")
vh = build_vless_header(UUID, "127.0.0.1", ECHO_PORT, payload)
status, hdr, body = http_json("POST", f"/v2/xhtx/packet-up/{UUID}/0", body=vh, headers={"X-Session-Id": sess_id})
check("seq0 returns connected/ok", status == 200 and json.loads(body).get("ok") is True, f"{status} {body!r}")
check("session registered, counted in active connections", any(
    c.get("transport") == "xhttp-packet-up" for c in main.connections.values()), "")

# 1.2 POST second packet seq=1
status, hdr, body = http_json("POST", f"/v2/xhtx/packet-up/{UUID}/1", body=b"ping-2", headers={"X-Session-Id": sess_id})
check("seq1 ok", status == 200 and json.loads(body).get("ok") is True, f"{status} {body!r}")

# 1.3 one GET stays attached and reads the whole downstream stream: the
# two-byte stream prefix first, then both echoes in order.
status, hdr, body = http_raw_stream("GET", f"/v2/xhtx/packet-up/{UUID}", headers={"X-Session-Id": sess_id}, idle_timeout=2.5)
check("downlink 200 + streaming content-type", status == 200 and hdr.get("content-type") == "application/grpc", f"{status} {hdr.get('content-type')}")
check("byte stream begins with the 2-byte stream prefix", body[:2] == STREAM_PREFIX, repr(body[:4]))
check("stream echoes payloads in order",
      body[2:].startswith(payload), repr(body[:24]) + " want " + repr(payload[:12]))
check("stream echoes packet 2", b"ping-2" in body)

# 1.4 server-advertised session id contract for a standalone GET
status, hdr, body = http_raw_stream("GET", f"/v2/xhtx/packet-up/{UUID}", first_timeout=0.8, idle_timeout=0.4, max_bytes=4096)
check("standalone GET advertises a session id", bool(hdr.get("x-session-id")), str(dict(hdr)))

# 1.5 idle-session cleanup: shorten the reaper window, post one more packet,
# then assert the idle session is reaped (no client FIN required in XHTTP).
sess_before = len(relay_xhttp.xhttp_sessions)
os.environ["XHTTP_SESSION_IDLE_SECONDS"] = "2"
status, hdr, body = http_json("POST", f"/v2/xhtx/packet-up/{UUID}/2", body=b"srv-close", headers={"X-Session-Id": sess_id})
check("post-teardown write accepted pre-close", status == 200, f"{status}")
time.sleep(13)
os.environ.pop("XHTTP_SESSION_IDLE_SECONDS", None)
after = len(relay_xhttp.xhttp_sessions)
check("idle session reaped by the reaper", after < sess_before, f"{after} vs {sess_before}")

# ── 2. stream-up cycle ───────────────────────────────────────────────────────
print("[stream-up]")
status, hdr, body = http_raw_stream("GET", f"/v2/xhtx/stream-up/{UUID}")
sess2 = hdr.get("x-session-id")
check("stream-up downlink advertises session id", bool(sess2))

vh2 = build_vless_header(UUID, "127.0.0.1", ECHO_PORT, b"stream-handshake")
import http.client
conn = http.client.HTTPConnection(BASE_HOST, APP_PORT, timeout=10)
conn.request("POST", f"/v2/xhtx/stream-up/{UUID}", body=vh2, headers={"X-Session-Id": sess2})
resp = conn.getresponse()
resp.read()
check("stream-up upload accepted", resp.status == 200, str(resp.status))
conn.close()

status, hdr, body = http_raw_stream("GET", f"/v2/xhtx/stream-up/{UUID}", headers={"X-Session-Id": sess2}, idle_timeout=2.0)
check("stream-up echo returned", b"stream-handshake" in body, repr(body[:60]))

# ── 3. auto route ────────────────────────────────────────────────────────────
print("[auto]")
status, hdr, body = http_raw_stream("GET", f"/v2/xhtx/auto/{UUID}")
sess3 = hdr.get("x-session-id")
check("auto session allocated", bool(sess3))
vh3 = build_vless_header(UUID, "127.0.0.1", ECHO_PORT, b"auto-packet")
status, hdr, body = http_json("POST", f"/v2/xhtx/auto/{UUID}/0", body=vh3, headers={"X-Session-Id": sess3})
check("auto packet-up POST accepted", status == 200 and json.loads(body).get("ok"), f"{status} {body!r}")
status, hdr, body = http_raw_stream("GET", f"/v2/xhtx/auto/{UUID}", headers={"X-Session-Id": sess3}, idle_timeout=2.0)
check("auto stream echoes", b"auto-packet" in body, repr(body[:60]))

# ── 4. auth / session enforcement ────────────────────────────────────────────
print("[security]")
status, hdr, body = http_json("GET", f"/v2/xhtx/packet-up/{UUID.replace('9', 'a', 1)}")
check("unknown uuid rejected", status == 403, f"{status} {body!r}")
status, hdr, body = http_json("POST", f"/v2/xhtx/packet-up/{UUID}/0", body=b"x", headers={})
check("missing session header rejected", status == 400, f"{status} {body!r}")
status, hdr, body = http_json("POST", f"/v2/xhtx/packet-up/{UUID}/0", body=b"x", headers={"X-Session-Id": "nosuch-session"})
check("garbage handshake rejected (invalid vless header)", status == 400, f"{status} {body!r}")
status, hdr, body = http_json("POST", f"/v2/xhtx/stream-up/{UUID}", body=b"x", headers={"X-Session-Id": "no-such-stream-session"})
check("stream-up garbage handshake rejected", status in (400,), f"{status} {body!r}")

# ── 5. HTTP CONNECT hop ──────────────────────────────────────────────────────
print("[connect proxy]")
# A minimal HTTP CONNECT proxy: reads "CONNECT host:port HTTP/1.1", answers
# 200, then pipes bytes both ways.
CONNECT_PORT = free_port()


async def connect_proxy():
    async def handle(reader, writer):
        try:
            # Buffer until the blank line of the CONNECT request, then answer.
            head = b""
            while b"\r\n\r\n" not in head:
                head += await reader.readuntil(b"\r\n\r\n") if b"\r\n\r\n" not in head and head.count(b"\r\n") < 2 else await reader.read(4096)
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await writer.drain()
            try:
                while True:
                    data = await reader.read(65536)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            except (ConnectionError, OSError):
                pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", CONNECT_PORT)
    async with server:
        await server.serve_forever()

proxy_loop = asyncio.new_event_loop()

def _run_proxy():
    asyncio.set_event_loop(proxy_loop)
    proxy_loop.run_until_complete(connect_proxy())

proxy_thread = threading.Thread(target=_run_proxy, daemon=True)
proxy_thread.start()
time.sleep(0.2)

# Route the app's upstream dials through the CONNECT proxy.
os.environ["XHTTP_CONNECT_PROXY"] = f"http://{BASE_HOST}:{CONNECT_PORT}"
relay_xhttp.cache_connect_proxy()

status, hdr, body = http_raw_stream("GET", f"/v2/xhtx/packet-up/{UUID}")
sess4 = hdr.get("x-session-id")
vh4 = build_vless_header(UUID, "127.0.0.1", ECHO_PORT, b"via-connect")
status, hdr, body = http_json("POST", f"/v2/xhtx/packet-up/{UUID}/0", body=vh4, headers={"X-Session-Id": sess4})
check("packet-up via CONNECT proxy accepted", status == 200 and json.loads(body).get("ok"), f"{status} {body!r}")
status, hdr, body = http_raw_stream("GET", f"/v2/xhtx/packet-up/{UUID}", headers={"X-Session-Id": sess4}, idle_timeout=2.0)
check("stream via CONNECT proxy echoes", b"via-connect" in body, repr(body[:60]))

# Restore direct dialing afterwards.
os.environ.pop("XHTTP_CONNECT_PROXY", None)
relay_xhttp.cache_connect_proxy()

# ── 6. accounting ─────────────────────────────────────────────────────────────
link = main.LINKS[UUID]
check("usage accounting counted bytes", int(link.get("used_bytes", 0)) > 0, str(link.get("used_bytes")))

print()
if failures:
    print(f"FAILURES: {len(failures)} -> {failures}")
    sys.exit(1)
print("xhttp e2e: ALL OK")
