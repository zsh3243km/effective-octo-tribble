# relay_xhttp.py
# VLESS XHTTP transport — adapted from the NewYork reference implementation
# (xhttp_siz10.py, the "Siz10a XHTTP Ultra" module) onto Lumen's native data
# plane.
#
# Deployed protocol contract:
#   * downlink: GET /v2/xhtx/{mode}/{uuid}            (mode = packet-up |
#     stream-up | auto)
#   * uplink (packet-up and auto): POST /v2/xhtx/{mode}/{uuid}/{seq}
#   * uplink (stream-up): POST /v2/xhtx/{mode}/{uuid} (single streaming body)
#   * the server generates the session id on the first request of a session and
#     returns it in the X-Session-Id response header; the client sends that
#     value back as the X-Session-Id request header on every later request of
#     the session.
#   * when served over plain HTTP the upstream hop is dialed directly. When
#     XHTTP_CONNECT_PROXY is configured (a plain-HTTP proxy URL, optionally with
#     basic auth), every upstream dial first builds an HTTP CONNECT tunnel
#     through that hop and the tunneled byte stream is then treated as the
#     target TCP stream.
#   * usage accounting uses Lumen's batched QuotaGate and check_and_use, and
#     exit-proxy selection reuses the same resolve_exact_selection pipeline as
#     the WebSocket relay.
#   * a client that stops reading its downlink is torn down promptly instead of
#     half-leaking the upstream until its own EOF.
from __future__ import annotations

import asyncio
import base64
import secrets
import socket
import time
from datetime import datetime
from urllib.parse import unquote, urlsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from main import (
    LINKS,
    LINKS_LOCK,
    stats,
    connections,
    error_logs,
    logger,
    is_link_allowed,
    is_ip_allowed,
    save_state,
    log_activity,
    now_ir,
)
import main as _main
from speed_limit import QuotaGate, throttle
import relay_vless
from relay_vless import (
    WRITE_HW_MAX,
    WRITE_HW_START,
    _parse_vless_header,
    _resolve_exact_selection,
)
from outbound import open_outbound

router = APIRouter()

# ── Path + session-contract constants ────────────────────────────────────────
PATH_PREFIX = "/v2/xhtx"
SESSION_HEADER = "X-Session-Id"

# ── Tuning (reference defaults, kept so behavior matches NewYork) ────────────
XHTTP_BUF = 512 * 1024
DOWNLINK_QUEUE_MAX = 512
SESSION_IDLE_TIMEOUT = 30
REAPER_INTERVAL = 10
TCP_CONNECT_TIMEOUT = 10.0
PACKET_UP_HIGH_WATER = 2 * 1024 * 1024

URL_MODES = ("packet-up", "stream-up", "auto")
XHTTP_SESSION_CAP = 4096

# ── HTTP CONNECT hop between this server and the upstream target ─────────────
# XHTTP_CONNECT_PROXY accepts one URL per deployment: "http://host:port" or
# "http://user:pass@host:port". Empty/unset dials the upstream directly.
CONNECT_PROXY_URL = ""


def cache_connect_proxy() -> None:
    """Refresh the cached CONNECT hop URL from the environment."""
    global CONNECT_PROXY_URL
    CONNECT_PROXY_URL = str(
        (_main.os.environ.get("XHTTP_CONNECT_PROXY", "") or "").strip()
    )


cache_connect_proxy()


def _resp_headers(fp: str) -> dict:
    return dict(FINGERPRINT_HEADERS.get(fp, FINGERPRINT_HEADERS[DEFAULT_FINGERPRINT]))


FINGERPRINT_HEADERS = {
    "chrome": {
        "content-type": "application/grpc",
        "cache-control": "no-cache, no-store",
        "x-accel-buffering": "no",
        "server": "cloudflare",
    },
    "plain": {
        "content-type": "application/octet-stream",
        "cache-control": "no-store",
        "x-accel-buffering": "no",
    },
}
DEFAULT_FINGERPRINT = "chrome"

xhttp_sessions: dict = {}
XHTTP_LOCK = asyncio.Lock()


def _req_client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "نامشخص"


def _req_session_id(request: Request) -> str:
    """Client-echoed session id for an active session."""
    return str(request.headers.get(SESSION_HEADER, "") or "").strip()


def _req_location_id(request: Request) -> str:
    """Multi-Location hint from the request query string, mirroring the WS ?loc=."""
    try:
        return str(request.query_params.get("loc", "") or "")[:24]
    except Exception:
        return ""


def _effective_mode(url_mode: str, handler_shape: str) -> str:
    """Map a URL mode token to the concrete data-plane mode for this handler.

    ``auto`` defers to the shape of the request that actually carries data:
    a sequence-numbered POST is packet-up, a streaming POST is stream-up.
    A bare GET with no session yet also defaults to packet-up (a later
    stream-up POST still adopts that session; the downlink queue is shared).
    Explicit tokens must agree with the handler shape, or the request is
    rejected.
    """
    if url_mode not in URL_MODES:
        raise HTTPException(status_code=404, detail="unknown mode")
    if url_mode == "auto":
        return handler_shape
    if url_mode != handler_shape:
        raise HTTPException(status_code=400, detail="mode does not match this route")
    return url_mode


async def _open_connect_tunnel(address: str, port: int):
    """Build an HTTP CONNECT tunnel through the configured hop and return the
    raw bidirectional stream (reader, writer) to the target."""
    parsed = urlsplit(CONNECT_PROXY_URL)
    if parsed.scheme not in ("http", ""):
        raise HTTPException(status_code=502, detail="CONNECT proxy scheme must be http")
    proxy_host = parsed.hostname
    proxy_port = parsed.port or 80
    if not proxy_host:
        raise HTTPException(status_code=502, detail="invalid CONNECT proxy")

    proxy_reader, proxy_writer = await asyncio.wait_for(
        asyncio.open_connection(proxy_host, proxy_port), timeout=TCP_CONNECT_TIMEOUT
    )
    try:
        headers = [
            f"CONNECT {address}:{port} HTTP/1.1",
            f"Host: {address}:{port}",
        ]
        if parsed.username:
            headers.append(
                "Proxy-Authorization: Basic "
                + base64.b64encode(
                    f"{unquote(parsed.username)}:{unquote(parsed.password or '')}".encode()
                ).decode("ascii")
            )
        wire = ("\r\n".join(headers) + "\r\n\r\n").encode("latin-1")
        proxy_writer.write(wire)
        await proxy_writer.drain()

        status_line = await asyncio.wait_for(
            proxy_reader.readline(), timeout=TCP_CONNECT_TIMEOUT
        )
        fields = status_line.split()
        if len(fields) < 2 or fields[1] != b"200":
            proxy_writer.write_eof()
            raise HTTPException(status_code=502, detail="CONNECT tunnel refused")
        # Consume and discard the remaining response headers of the CONNECT
        # reply, bounded by the same timeout.
        while True:
            line = await asyncio.wait_for(
                proxy_reader.readline(), timeout=TCP_CONNECT_TIMEOUT
            )
            if line in (b"\r\n", b"\n", b""):
                break
        return proxy_reader, proxy_writer
    except HTTPException:
        proxy_writer.close()
        raise
    except Exception:
        proxy_writer.close()
        raise


async def _open_upstream_from_header(uuid: str, link: dict, location_id: str, first_chunk: bytes):
    """Parse the VLESS v0 header and open the target — via the configured
    CONNECT hop when set, else Lumen's outbound pipeline (exact exit-proxy
    selection, Happy-Eyeballs, tuning)."""
    try:
        _command, address, port, payload = _parse_vless_header(first_chunk)
    except ValueError:
        # Not a VLESS request: reject the handshake cleanly rather than
        # surfacing it as an upstream write failure (and drop the session the
        # request created, so garbage traffic cannot pin accounting state).
        raise HTTPException(status_code=400, detail="invalid vless header")

    if CONNECT_PROXY_URL:
        reader, writer = await _open_connect_tunnel(address, port)
        if payload:
            writer.write(payload)
            await writer.drain()
        return reader, writer, address, port

    exit_selection = await _resolve_exact_selection(link, location_id)
    exit_endpoints = [exit_selection["endpoint"]] if exit_selection else []
    selected_proxy_id = exit_selection["proxy_id"] if exit_selection else ""

    reader, writer, payload_sent = await open_outbound(
        address,
        port,
        payload,
        uuid=uuid,
        endpoints=exit_endpoints,
        proxy_id=selected_proxy_id,
    )
    relay_vless._tune_socket(writer, WRITE_HW_START)
    if payload and not payload_sent:
        try:
            writer.transport.set_write_buffer_limits(
                high=WRITE_HW_START, low=max(WRITE_HW_START // 4, 64 * 1024)
            )
        except Exception:
            pass
        writer.write(payload)
        await writer.drain()
    return reader, writer, address, port


async def _check_link(uuid: str):
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
    if not is_link_allowed(link):
        raise HTTPException(status_code=403, detail="not authorized")
    return link


async def _get_or_create_session(
    uuid: str,
    mode: str,
    session_id: str = "",
    ip: str = "نامشخص",
    advertise_id: str = "",
) -> dict:
    """Fetch (by client-echoed id) or create (under advertise_id) a session."""
    async with XHTTP_LOCK:
        total = len(xhttp_sessions)
        sess = xhttp_sessions.get(session_id) if session_id else None
        if sess is not None:
            sess["last_seen"] = time.time()
            return sess

        async with LINKS_LOCK:
            link = LINKS.get(uuid)
        if not is_ip_allowed(link, uuid, ip):
            logger.warning("🚫 XHTTP[%s] rejected uuid=%s ip=%s (ip limit reached)", mode, uuid[:8], ip)
            raise HTTPException(status_code=403, detail="ip limit reached")
        if total >= XHTTP_SESSION_CAP:
            logger.warning("🚫 XHTTP[%s] rejected uuid=%s ip=%s (session cap)", mode, uuid[:8], ip)
            raise HTTPException(status_code=503, detail="session limit reached")

        store_id = session_id or advertise_id
        if not store_id:
            raise HTTPException(status_code=400, detail="session id required")

        conn_id = secrets.token_urlsafe(6)
        connections[conn_id] = {
            "uuid": uuid,
            "ip": ip,
            "connected_at": datetime.now().isoformat(),
            "bytes": 0,
            "transport": f"xhttp-{mode}",
        }
        sess = {
            "uuid": uuid,
            "mode": mode,
            "writer": None,
            "downlink_task": None,
            "down_q": asyncio.Queue(maxsize=DOWNLINK_QUEUE_MAX),
            "last_seen": time.time(),
            "conn_id": conn_id,
            "tcp_open": False,
            "closed": False,
            "seq_buf": {},
            "next_seq": 0,
            "gate": None,   # lazily created QuotaGate for stream-up
        }
        xhttp_sessions[store_id] = sess
        logger.info(f"new XHTTP[{mode}] session [{store_id[:8]}] uuid={uuid[:8]} ip={ip}")
        return sess


async def _teardown(session_id: str):
    async with XHTTP_LOCK:
        sess = xhttp_sessions.pop(session_id, None)
    if not sess:
        return
    sess["closed"] = True
    task = sess.get("downlink_task")
    if task:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
    writer = sess.get("writer")
    if writer:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    connections.pop(sess.get("conn_id"), None)
    dq = sess.get("down_q")
    if dq:
        try:
            dq.put_nowait(None)
        except Exception:
            pass
    logger.info(f"closed XHTTP[{sess.get('mode')}] [{session_id[:8]}] total={len(xhttp_sessions)}")


def _idle_window() -> float:
    """Idle window before the reaper closes an established session.

    Sessions that never opened upstream are reaped fast (SESSION_IDLE_TIMEOUT);
    established sessions keep the reference's window by default so a quiet SSH
    or WebSocket-in-TCP session is not dropped mid-conversation, but an
    operator can shorten/lengthen it with XHTTP_SESSION_IDLE_SECONDS.
    """
    import os
    try:
        window = float(os.environ.get("XHTTP_SESSION_IDLE_SECONDS", ""))
    except ValueError:
        window = 0.0
    return window if window > 0 else SESSION_IDLE_TIMEOUT


async def _reaper():
    while True:
        await asyncio.sleep(REAPER_INTERVAL)
        now = time.time()
        window = _idle_window()
        async with XHTTP_LOCK:
            stale = [
                sid for sid, s in xhttp_sessions.items()
                if now - s["last_seen"] >
                (SESSION_IDLE_TIMEOUT if not s.get("tcp_open") else window)
            ]
        for sid in stale:
            await _teardown(sid)


_reaper_started = False


def ensure_reaper():
    global _reaper_started
    if not _reaper_started:
        asyncio.create_task(_reaper())
        _reaper_started = True


async def shutdown_sessions() -> None:
    """App shutdown: drop every live XHTTP session cleanly."""
    async with XHTTP_LOCK:
        ids = list(xhttp_sessions)
    for sid in ids:
        await _teardown(sid)


async def _pump_tcp_to_queue(session_id: str, uuid: str, reader: asyncio.StreamReader, down_q: asyncio.Queue):
    first = True
    gate = QuotaGate(uuid, relay_vless.check_and_use)
    try:
        while True:
            data = await reader.read(XHTTP_BUF)
            if not data:
                break
            if not await gate.add(len(data)):
                break
            await throttle(uuid, len(data))
            async with XHTTP_LOCK:
                sess = xhttp_sessions.get(session_id)
            if sess:
                c = connections.get(sess["conn_id"])
                if c:
                    c["bytes"] += len(data)
            payload = (b"\x00\x00" + data) if first else data
            first = False
            await down_q.put(payload)
    except (asyncio.CancelledError, Exception):
        pass
    finally:
        try:
            await gate.flush()
        except Exception:
            pass
        await _teardown(session_id)


async def _open_tcp_for_session(
    session_id: str,
    uuid: str,
    sess: dict,
    link: dict,
    location_id: str,
    first_chunk: bytes,
):
    """Open the tunneled TCP stream from the VLESS header and start the
    downstream pump."""
    reader, writer, address, port = await _open_upstream_from_header(
        uuid, link, location_id, first_chunk
    )
    logger.info(f"connect XHTTP[{sess['mode']}] [{session_id[:8]}] -> {address}:{port}")
    sess["writer"] = writer
    sess["tcp_open"] = True
    sess["downlink_task"] = asyncio.create_task(
        _pump_tcp_to_queue(session_id, uuid, reader, sess["down_q"])
    )
    asyncio.create_task(save_state())


def _downstream_gen(session_id: str, sess: dict):
    async def gen():
        while True:
            chunk = await sess["down_q"].get()
            if chunk is None:
                break
            sess["last_seen"] = time.time()
            yield chunk
        # Do NOT teardown here: XHTTP clients legitimately close and reopen
        # their downlink GET within one session; killing the session at
        # generator exit (as this port originally did) drops queued upstream
        # data and breaks re-attachment. Cleanup is owned by the upstream EOF
        # (the pump finalizer) and the idle reaper, as in the reference.
    return gen()


def _resolve_effective(mode: str, handler_shape: str) -> str:
    effective = _effective_mode(mode, handler_shape)
    if effective not in ("packet-up", "stream-up"):
        raise HTTPException(status_code=404, detail="unknown mode")
    return effective


# ════ GET downlink (shared by all modes) ══════════════════════════════════════
@router.get(f"{PATH_PREFIX}/{{mode}}/{{uuid}}")
async def xhttp_downlink(mode: str, uuid: str, request: Request):
    # The downlink carries no framing of its own, so the URL token only needs
    # to be a known mode; `auto` inherits packet-up for session bookkeeping.
    if mode not in URL_MODES:
        raise HTTPException(status_code=404, detail="unknown mode")
    effective = mode if mode in ("packet-up", "stream-up") else "packet-up"
    link = await _check_link(uuid)
    ensure_reaper()

    session_id = _req_session_id(request)
    if session_id:
        sess = await _get_or_create_session(uuid, effective, session_id, _req_client_ip(request))
        if sess.get("closed"):
            raise HTTPException(status_code=404, detail="session closed")
    else:
        # No session id echoed: allocate one here and advertise it to the
        # client on this response.
        advertise_id = secrets.token_urlsafe(12)
        sess = await _get_or_create_session(
            uuid, effective, "", _req_client_ip(request), advertise_id=advertise_id
        )
        session_id = advertise_id

    headers = _resp_headers(request.query_params.get("fp", DEFAULT_FINGERPRINT))
    headers[SESSION_HEADER] = session_id
    return StreamingResponse(
        _downstream_gen(session_id, sess),
        headers=headers,
        media_type=headers["content-type"],
    )


def _uplink_guard(uuid: str, url_mode: str, handler_shape: str, request: Request):
    ensure_reaper()
    effective = _effective_mode(url_mode, handler_shape)
    session_id = _req_session_id(request)
    if not session_id:
        raise HTTPException(status_code=400, detail=f"{SESSION_HEADER} header required")
    return effective, session_id


def _url_mode(request: Request) -> str:
    """URL token after /v2/xhtx/ (packet-up | stream-up | auto)."""
    token = request.url.path[len(PATH_PREFIX) + 1 :].split("/", 2)
    return token[0] if token else "auto"


# ════ PACKET-UP (upload with a per-packet sequence number) ════════════════════
async def _packet_up_impl(uuid: str, seq: int, request: Request):
    effective, session_id = _uplink_guard(uuid, _url_mode(request), "packet-up", request)
    link = await _check_link(uuid)
    sess = await _get_or_create_session(uuid, effective, session_id, _req_client_ip(request))
    if sess.get("closed"):
        raise HTTPException(status_code=404, detail="session closed")

    sess["last_seen"] = time.time()
    body = await request.body()
    if not body:
        return {"ok": True}

    if not await relay_vless.check_and_use(uuid, len(body)):
        await _teardown(session_id)
        raise HTTPException(status_code=403, detail="quota/disabled/unknown")
    await throttle(uuid, len(body))

    stats["total_requests"] = int(stats.get("total_requests", 0) or 0) + 1
    connection = connections.get(sess["conn_id"])
    if connection is not None:
        connection["bytes"] += len(body)

    try:
        if sess["writer"] is None:
            # The first packet carrying the VLESS header need not arrive as
            # seq=0 when packets arrive out of order; buffer early sequences
            # until the header packet has been processed.
            if seq != 0:
                sess["seq_buf"][seq] = body
                return {"ok": True, "buffered": True}
            await _open_tcp_for_session(session_id, uuid, sess, link, _req_location_id(request), body)
            nxt = 1
            while nxt in sess["seq_buf"]:
                pending = sess["seq_buf"].pop(nxt)
                sess["writer"].write(pending)
                nxt += 1
            sess["next_seq"] = nxt
            return {"ok": True, "connected": True}

        if seq == sess["next_seq"]:
            sess["writer"].write(body)
            sess["next_seq"] += 1
            while sess["next_seq"] in sess["seq_buf"]:
                pending = sess["seq_buf"].pop(sess["next_seq"])
                sess["writer"].write(pending)
                sess["next_seq"] += 1
        else:
            sess["seq_buf"][seq] = body

        if sess["writer"].transport.get_write_buffer_size() > PACKET_UP_HIGH_WATER:
            await sess["writer"].drain()
    except HTTPException:
        # Invalid handshakes etc.: keep the precise status/detail, drop the
        # session the failed request created.
        await _teardown(session_id)
        raise
    except Exception as exc:
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        await _teardown(session_id)
        raise HTTPException(status_code=502, detail="write failed")

    return {"ok": True}


# ════ STREAM-UP (one continuous POST body) ════════════════════════════════════
async def _stream_up_impl(uuid: str, request: Request):
    effective, session_id = _uplink_guard(uuid, _url_mode(request), "stream-up", request)
    link = await _check_link(uuid)
    sess = await _get_or_create_session(uuid, effective, session_id, _req_client_ip(request))
    if sess.get("closed"):
        raise HTTPException(status_code=404, detail="session closed")

    gate = sess.get("gate")
    if gate is None:
        gate = QuotaGate(uuid, relay_vless.check_and_use)
        sess["gate"] = gate

    connection = connections.get(sess["conn_id"])
    writer = sess["writer"]   # may still be None

    try:
        async for chunk in request.stream():
            if not chunk:
                continue
            sess["last_seen"] = time.time()

            if not await gate.add(len(chunk)):
                raise HTTPException(status_code=403, detail="quota/disabled/unknown")
            await throttle(uuid, len(chunk))

            stats["total_requests"] = int(stats.get("total_requests", 0) or 0) + 1
            if connection is not None:
                connection["bytes"] += len(chunk)

            if writer is None:
                await _open_tcp_for_session(
                    session_id, uuid, sess, link, _req_location_id(request), chunk
                )
                writer = sess["writer"]
                continue

            writer.write(chunk)
            if writer.transport.get_write_buffer_size() > WRITE_HW_MAX:
                await writer.drain()
    except HTTPException:
        try:
            await gate.flush()
        except Exception:
            pass
        await _teardown(session_id)
        raise
    except Exception as exc:
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        try:
            await gate.flush()
        except Exception:
            pass
        await _teardown(session_id)
        raise HTTPException(status_code=502, detail="stream error")

    try:
        await gate.flush()
    except Exception:
        pass
    return {"ok": True}


# ── Route registrations ───────────────────────────────────────────────────────
# The URL token decides which uplink shape the client speaks:
#   packet-up → /packet-up/{uuid}/{seq}   stream-up → /stream-up/{uuid}
#   auto      → /auto/{uuid}/{seq}   or   /auto/{uuid}
@router.post(f"{PATH_PREFIX}/packet-up/{{uuid}}/{{seq}}")
async def packet_up_upload(uuid: str, seq: int, request: Request):
    return await _packet_up_impl(uuid, seq, request)

@router.post(f"{PATH_PREFIX}/auto/{{uuid}}/{{seq}}")
async def auto_packet_up_upload(uuid: str, seq: int, request: Request):
    return await _packet_up_impl(uuid, seq, request)

@router.post(f"{PATH_PREFIX}/stream-up/{{uuid}}")
async def stream_up_upload(uuid: str, request: Request):
    return await _stream_up_impl(uuid, request)

@router.post(f"{PATH_PREFIX}/auto/{{uuid}}")
async def auto_stream_up_upload(uuid: str, request: Request):
    return await _stream_up_impl(uuid, request)
