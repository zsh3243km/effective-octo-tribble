#!/usr/bin/env python3
"""WebSocket regression test for the pre-existing VLESS/WS relay.

Runs the real app (FastAPI + Uvicorn with the project's WS stack), performs a
real WebSocket handshake on /ws/{uuid} with an unregistered UUID (must be
denied 1008), then with a registered UUID: sends a valid VLESS header +
payload, asserts the two-byte downstream stream prefix and exact echo, checks
the active-connection accounting, and verifies a clean disconnect leaves no
lingering connection entries.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="lumen-ws-e2e-")
os.environ["PORT"] = "0"

import main  # noqa: E402

failures = []


def check(name, cond, detail=""):
    print(("  ok   " if cond else "  FAIL ") + name + (("  " + detail) if detail and not cond else ""))
    if not cond:
        failures.append(name)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def build_vless_header(uid: str, host: str, port: int, payload: bytes = b"") -> bytes:
    header = bytearray()
    header.append(0)
    header.extend(bytes.fromhex(uid.replace("-", "")))
    header.append(0)
    header.append(1)
    header.extend(port.to_bytes(2, "big"))
    header.append(1)
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


echo_loop = asyncio.new_event_loop()
threading.Thread(
    target=lambda: (asyncio.set_event_loop(echo_loop), echo_loop.run_until_complete(echo_server())),
    daemon=True,
).start()
time.sleep(0.2)

UUID = "5f1c8a72-31b6-4f0e-9c2d-8a4b7e6d5f31"
main.LINKS[UUID] = {
    "label": "ws-e2e",
    "limit_bytes": 0,
    "used_bytes": 0,
    "active": True,
    "expires_at": None,
    "protocol": "vless-ws",
    "transport_settings": {},
    "ip_limit": 0,
    "speed_limit_bytes": 0,
    "address": "",
    "sni": "",
    "exit_proxy_mode": "direct", "proxy_id": "", "custom_proxy": "",
}
main.ensure_default_link()
start_app()

import websockets  # noqa: E402


async def ws_flow() -> None:
    bad_uuid = "00000000-0000-4000-8000-000000000000"
    try:
        async with websockets.connect(f"ws://127.0.0.1:{APP_PORT}/ws/{bad_uuid}", open_timeout=5) as ws:
            first = await asyncio.wait_for(ws.recv(), timeout=5)
            check("unregistered uuid denied", False, str(first)[:60])
    except Exception as exc:
        check("unregistered uuid denied", "1008" in str(exc) or "policy" in str(exc) or "denied" in str(exc), str(exc)[:80])

    payload = b"ping-over-ws"
    vh = build_vless_header(UUID, "127.0.0.1", ECHO_PORT, payload)
    async with websockets.connect(f"ws://127.0.0.1:{APP_PORT}/ws/{UUID}", open_timeout=5) as ws:
        check("registered uuid handshake accepted", True, "")
        await ws.send(vh)
        alive = any(c.get("transport", "").startswith("vless-ws") for c in main.connections.values())
        check("ws connection tracked with vless-ws transport", alive, str(list(main.connections)))
        first = await asyncio.wait_for(ws.recv(), timeout=5)
        check("downlink starts with 2-byte stream prefix", bytes(first)[:2] == b"\x00\x00", repr(bytes(first)[:6]))
        body = bytes(first)[2:]
        if not body:
            body = bytes(await asyncio.wait_for(ws.recv(), timeout=5))
        check("echo payload matches", body == payload, repr(body[:40]))

        await ws.send(b"ws-packet-2")
        rest = bytes(await asyncio.wait_for(ws.recv(), timeout=5))
        check("second message echoed", rest == b"ws-packet-2", repr(rest[:40]))

    time.sleep(1.0)
    lingering = [c for c in main.connections.values() if c.get("transport", "").startswith("vless-ws")]
    check("connections cleaned after ws close", not lingering, str(lingering))

    check("ws accounting counted bytes", int(main.LINKS[UUID].get("used_bytes", 0)) > 0,
          str(main.LINKS[UUID].get("used_bytes")))


asyncio.get_event_loop().run_until_complete(ws_flow())

print()
if failures:
    print(f"FAILURES: {len(failures)} -> {failures}")
    sys.exit(1)
print("ws e2e: ALL OK")
