# XHTTP Transport Integration Technical Notes

The reference XHTTP implementation in NewYork (`xhttp_siz10.py`, the
"Siz10a Ultra" data plane) was adapted into Lumen's native relay. This
document records the exact integration decisions.

## Path contract

```
GET  /v2/xhtx/{mode}/{uuid}                 downlink (any mode token)
POST /v2/xhtx/packet-up/{uuid}/{seq}        packet-up uplink
POST /v2/xhtx/stream-up/{uuid}              stream-up uplink
POST /v2/xhtx/auto/{uuid}/{seq}             auto uplink, packet-shaped
POST /v2/xhtx/auto/{uuid}                   auto uplink, stream-shaped
```

The first request of a session allocates/adopted the session id:

* an uplink POST may carry its own random `X-Session-Id` request header — the
  session is created under that id (POST-first, as most real XHTTP clients
  behave);
* a standalone GET observes the id in the `X-Session-Id` response header and
  echoes it back afterwards (GET-first flow).

Session bookkeeping therefore does not need `{session_id}` in the URL.

## Modes

* `packet-up` — one short POST per packet, carries `/{seq}`; the
  seq=0 body contains the VLESS v0 request header and any payload; future
  packets arrive in sequence-numbered POSTs with a small reorder buffer.
* `stream-up` — one single continuous POST per direction; the first streamed
  body chunk contains the VLESS header; all later chunks are written through.
* `auto` — resolves per-request: whichever uplink route the client uses
  decides the concrete mode for that session's uplink shape (packet or
  stream). `auto` is exposed both in API answers and in generated URIs;
  the downlink behaves identically for all modes.

Every session keeps its own `asyncio.Queue` (`DOWNLINK_QUEUE_MAX = 512`),
quota gate, reorder buffer, and TCP stream handle; state never leaks across
sessions.

## What was imported from the reference (unchanged semantics)

* Two-byte `\x00\x00` downstream prefix in the first streamed body chunk.
* Reorder buffer + `next_seq` continuation rules for packet-up.
* Byte-stream building blocks from Lumen's shared relay (`relay_vless`):
  `_parse_vless_header` (VLESS v0 header parsing), exact exit-proxy
  selection (`_resolve_exact_selection`), the `open_outbound` pipeline,
  `check_and_use` + `QuotaGate` accounting, `throttle` speed limiting.
* The same app-wide domain of `connections`, `stats`, `LINKS`,
  `error_logs`, `is_ip_allowed`, `is_link_allowed`, and `save_state`.

## Resource management

Sessions are cleaned by three independent mechanisms; all of them run against
the same `XHTTP_LOCK`-guarded session table, so accounting remains consistent:

1. Upstream EOF: when the target TCP stream ends, `_pump_tcp_to_queue`
   finalizes and tears the session down.
2. Idle reaper (`XHTTP_SESSION_IDLE_SECONDS`, default 30 s): a session with
   no traffic for that many seconds is dropped (with upstream, if any). The
   unbounded-stream leak that the reference had (downstream generator never
   scheduled a teardown) is bounded by reaping.
3. Graceful app shutdown (`relay_xhttp.shutdown_sessions`) tears everything
   down on event-loop shutdown.

`XHTTP_SESSION_CAP` (default 4096) bounds the number of live sessions; further
requests receive HTTP 503.

## Tubes of connection

`XHTTP_CONNECT_PROXY` (env, plain HTTP form like
`http://user:pass@host:port`) forces every upstream dial through that
signaling hop using the HTTP CONNECT framing. When it is unset, the
Lumen `outbound` dialer is used directly. A CONNECT that yields an
anything-but-200 answer fails the session cleanly with HTTP 502.

## Response header contract to clients

The first response of every session contains the `X-Session-Id` header
carrying the live session's id. Content-Type is the reference's
`application/grpc` (chrome) or `application/octet-stream` (plain,
`?fp=plain`); `Cache-Control` and `X-Accel-Buffering` similarly follow the
reference's fingerprint table.

## Files added/modified

| File | Change |
| --- | --- |
| `relay_xhttp.py` | **added** — XHTTP data plane (routes, sessions, quota, CONNECT hop) |
| `main.py` | register `relay_xhttp.router`; add `xhttp-*` protocols and ALPN defaults; teardown at shutdown |
| `transports.py` | `XHTTPAdapter` and `xhttp-packet-up/xhttp-stream-up/xhttp-auto` capability entries with serializers |
| `pages.py` | transport-cards and select options for the three XHTTP modes, chip rendering |
| `tests/ws_only_contract.py` | covers XHTTP availability, serializers, route shape |
| `tests/startup_cycle.py`, `tests/ml_contract.py`, `tests/transport_registry_contract.py` | upgraded stubs for `APIRouter`/`StreamingResponse`/`include_router` |
| `tests/xhttp_e2e.py` | **added** — real end-to-end XHTTP test (both uplink shapes, auto, CONNECT hop, teardown, accounting, security) |
| `tests/ws_e2e.py` | **added** — real WebSocket regression test (handshake deny/accept, echo, cleanup, accounting) |

## Testing result summary

* `tests/xhttp_e2e.py` — **ALL OK** (22 checks, real Uvicorn app; local stack)
* `tests/ws_e2e.py` — **ALL OK** (8 checks, real Uvicorn app; local stack)
* `tests/ws_only_contract.py` (source contract) — ALL OK
* `tests/api_routes.py`, `protocol_contract.py`, `ml_contract.py`,
  `startup_cycle.py`, `transport_registry_contract.py`,
  `state_persistence_v28.py`, `exact_proxy_path_e2e.py`,
  `startup_symbol_contract.py`, `ws_page_latency.py` — ALL OK
* pre-existing failures on the pristine baseline are listed in
  [TESTING.md](TESTING.md); none are XHTTP-related.
