#!/usr/bin/env python3
"""A controlled HTTP/HTTPS echo origin that records exactly what it received.

Why this exists
---------------
The I2 review's central complaint was that `concurrency_smoke.py` drove the *host's* `urllib` and
called the result "concurrency through the tunnel": nothing in that run could distinguish a request
the VPN rewrote from one that never left the measurement machine. This module is the other half of
the fix. It is an origin the probes actually reach, and it writes one JSON line per request it
**accepted**, so a test can compare

  * what the client says it asked for, and
  * what the origin was actually handed.

Those two differ exactly when a `$removeparam` rewrite happened (the design rewrites in place and
leaves the client's URL alone, `docs/EFFECTIVENESS.md` §13.1), which is why the origin's own record —
not the client's — is the evidence.

What makes the record usable as evidence (I2 stage-3 review, MYS-2817)
----------------------------------------------------------------------
1. **The request ID is echoed back as the origin saw it.** `X-ZS-Req` arrives, is recorded and is
   returned in the reply, so a harness can compare the *upstream's* view of the ID against the one
   its own plan issued. A result that only carries an ID the client filled in proves nothing, and
   the earlier version accepted exactly that.
2. **The body is recorded as bytes, with a digest.** `body_sha256` is taken over the raw body bytes
   before any decoding. A normalised form dictionary (`{"a": ["1"]}` re-ordered or merged by an echo
   service) therefore cannot stand in for "the body bytes survived"; the harness reads the digest.
3. **The record is flushed and locked per write**, so 20 concurrent requests leave 20 complete lines.
4. **In-flight overlap is measured, not assumed.** Every request increments a counter on arrival and
   decrements it after its response is flushed; each record carries the counter value at arrival and
   the process keeps the peak. `--hold-ms` keeps the response open long enough for real overlap to be
   observable through the tunnel, and `GET /__stats` reports the peak. That peak is what a harness
   cites as "20 requests were in flight at once" — a serialised run cannot produce it.
5. **The negotiated protocol is recorded per request** (`tls`, `alpn`), so the TLS/H1 and TLS/H2 legs
   are distinguishable from the origin side as well as from the browser side.

Listeners
---------
* `--port`            plaintext HTTP/1.1 (the "plaintext H1, no rewrite by design" leg);
* `--https-port`      TLS with ALPN `h2` + `http/1.1` (the TLS/H2 leg);
* `--https1-port`     TLS with ALPN `http/1.1` only (the TLS/H1 leg — `DESIGN §6` requires the
                      decrypted path on **both** framings, and an h2-capable origin cannot serve it).

`/__id` and `/__stats` are answered on every listener and marked `"probe": true`, so a health check
or a stats read never looks like a planned request.

HTTP/2 is spoken by the small `h2` engine below rather than by `http.server`, which cannot negotiate
it — an `h2` ALPN entry on an HTTP/1.1-only server would be worse than none, because a client that
picked it would send frames the server cannot parse. It buffers DATA per stream so a POST body over
h2 is recorded with the same fidelity as an HTTP/1.1 body.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import json
import os
import socket
import socketserver
import ssl
import sys
import threading
import time

#: One line per accepted request. Appended under a lock; `--log` overrides it.
DEFAULT_LOG = ".effectiveness/results/tunnel-origin.jsonl"

#: Paths that answer with a fixed body and are marked as probes in the record.
PROBE_PREFIXES = ("/__id", "/__stats")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _State:
    """Everything the handlers need, created once per process."""

    def __init__(self, log_path: str, hold_s: float = 0.0) -> None:
        self.log_path = log_path
        self.hold_s = max(0.0, hold_s)
        self.lock = threading.Lock()
        self.started = time.time()
        self.count = 0
        #: Requests currently being answered, and the highest value seen — the concurrency evidence.
        self.inflight = 0
        self.peak = 0
        #: Every request's `[arrival, departure]` interval, so overlap can be recomputed afterwards
        #: instead of only trusted as a running maximum. See [`_State.overlap`].
        self.spans: list[dict] = []
        #: Every request id this origin accepted, with its arrival count (duplicate detection).
        self.ids: dict[str, int] = {}
        #: Set when the log cannot be opened, so a broken run is loud instead of silently unpinned.
        self.error: str | None = None
        try:
            os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
            open(log_path, "w", encoding="utf-8").close()
        except OSError as error:  # pragma: no cover - environment failure
            self.error = f"cannot open {log_path}: {error}"

    # -- in-flight accounting ---------------------------------------------------------------
    def enter(self) -> int:
        """Count one request as in flight and return the counter value at arrival."""
        with self.lock:
            self.inflight += 1
            if self.inflight > self.peak:
                self.peak = self.inflight
            return self.inflight

    def leave(self, entry: dict | None = None) -> None:
        """Count one request as finished, and keep its interval for the overlap recomputation."""
        with self.lock:
            self.inflight = max(0, self.inflight - 1)
            if entry is not None and entry.get("done"):
                self.spans.append({"at": entry["at"], "done": entry["done"], "id": entry.get("id")})

    def hold(self) -> None:
        """Keep the request in flight long enough for overlap to be observable.

        Only the *response* is delayed; the request has already been read and recorded, so this
        changes no assertion about method, target or body. It exists because a local echo answers in
        under a millisecond, and 20 requests that each take 1 ms cannot be told apart from 20
        requests taken one after another.
        """
        if self.hold_s:
            time.sleep(self.hold_s)

    def record(self, entry: dict) -> None:
        line = json.dumps(entry, ensure_ascii=False, sort_keys=True)
        with self.lock:
            self.count += 1
            request_id = str(entry.get("id") or "")
            if request_id:
                self.ids[request_id] = self.ids.get(request_id, 0) + 1
            with open(self.log_path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())

    def stats(self) -> dict:
        with self.lock:
            return {
                "count": self.count,
                "inflight": self.inflight,
                "peak": self.peak,
                "ids": dict(self.ids),
                "since": self.started,
                "hold_ms": int(self.hold_s * 1000),
            }

    def overlap(self) -> dict:
        """The highest number of requests that were **simultaneously** open, from their intervals.

        This is the second, independent answer to "how many were in flight at once". `peak` counts
        arrivals against departures inside the lock; this recomputes the same thing from each
        request's `at`/`done` timestamps after the fact. Two answers that agree are worth more than
        one number a harness could have written itself, and the intervals are what a reader can check
        by hand — so both are recorded and both are required to reach the plan's concurrency.
        """
        with self.lock:
            spans = [(entry["at"], entry["done"]) for entry in self.spans if entry.get("done")]
        events = sorted([(start, 1) for start, _ in spans] + [(end, -1) for _, end in spans])
        current = best = 0
        best_at = None
        for moment, delta in events:
            current += delta
            if current > best:
                best, best_at = current, moment
        return {"overlap": best, "at": best_at, "requests": len(spans)}


def _entry(
    state: _State,
    *,
    request_id: str,
    method: str,
    path: str,
    http_version: str,
    headers: dict,
    body: bytes,
    connection,
    path_for_probe: str,
) -> dict:
    """The record of one request, built from bytes the server actually read."""
    return {
        "id": request_id,
        "method": method,
        "path": path,
        "target": path,
        # A digest over the raw bytes, so "the body arrived intact" is a byte comparison and not a
        # value-comparison of a dictionary some echo service rebuilt.
        "body_sha256": _sha256(body),
        "body_len": len(body),
        # Kept for human-readable failure messages; never the authority for an assertion.
        "body": body.decode("utf-8", "replace"),
        "body_b64": base64.b64encode(body).decode("ascii"),
        "http": http_version,
        "headers": {key.lower(): value for key, value in headers.items()},
        "host": headers.get("Host", headers.get("host", "")),
        "sni": getattr(connection, "server_hostname", None) or "",
        "tls": isinstance(connection, ssl.SSLSocket),
        "alpn": (
            connection.selected_alpn_protocol() if isinstance(connection, ssl.SSLSocket) else None
        ),
        "probe": path_for_probe.startswith(PROBE_PREFIXES),
        "at": time.time(),
        "inflight": state.enter(),
        "done": None,
    }


class Handler(http.server.BaseHTTPRequestHandler):
    """Echoes the request line, headers and body back as JSON, and logs what it was given.

    `protocol_version` is HTTP/1.1 so keep-alive works: a probe that reuses a connection must not
    look like a missing request just because the server closed after every answer.
    """

    protocol_version = "HTTP/1.1"
    #: The state object is injected by `make_server` through the subclass it builds.
    state: _State

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - signature is http.server's
        # The record file is the evidence; stderr chatter would only be noise in a 100-request run.
        return

    # ----------------------------------------------------------------------------------------
    # The one implementation every verb shares
    # ----------------------------------------------------------------------------------------
    def _respond(self) -> None:
        request_id = self.headers.get("X-ZS-Req") or ""
        # Read the body before answering: an unread body would be parsed as the next request on a
        # keep-alive connection and corrupt the following probe.
        length = self.headers.get("Content-Length")
        body = b""
        if length:
            try:
                body = self.rfile.read(int(length))
            except (ValueError, OSError):
                body = b""
        entry = _entry(
            self.state,
            request_id=request_id,
            method=self.command,
            path=self.path,
            http_version=self.request_version,
            headers=dict(self.headers.items()),
            body=body,
            connection=self.connection,
            path_for_probe=self.path,
        )
        try:
            self._answer(entry)
        finally:
            entry["done"] = time.time()
            self.state.leave(entry)

    def _send_json(self, payload: bytes, status: int = 200, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-ZS-Req", (extra or {}).get("id", ""))
        # Never let a cache hide a request from the origin, which would silently reduce the count.
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        for name, value in (extra or {}).items():
            if name not in ("id", "status", "location"):
                self.send_header(name, value)
        if "location" in (extra or {}):
            self.send_header("Location", extra["location"])
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _answer(self, entry: dict) -> None:
        """Fault paths first, then probes, then the record itself."""
        path = self.path
        request_id = entry["id"]

        # Fault paths. They exist so a harness can prove its own failure detection works: a run that
        # cannot tell a deliberate 500 from a healthy 200 would pass no matter what the tunnel did.
        if path.startswith("/__fault/500"):
            self.state.record(entry)
            self.state.hold()
            self._send_json(b'{"fault":"500"}', status=500, extra={"id": request_id})
            return
        if path.startswith("/__fault/disconnect"):
            # Recorded first, then the socket is closed without a response line: the client sees a
            # transport error, which is exactly the "断连" injection the acceptance asks for.
            self.state.record(entry)
            try:
                self.connection.close()
            except OSError:
                pass
            return
        if path.startswith("/__fault/body"):
            # Answers 200 but reports a body that was never sent, so a harness comparing the echoed
            # body against what it posted must notice. The digest is the field that does it.
            wrong = b"<deliberately wrong>"
            forged = entry | {
                "body": wrong.decode(),
                "body_b64": base64.b64encode(wrong).decode("ascii"),
                "body_sha256": _sha256(wrong),
                "body_len": len(wrong),
            }
            self.state.record(forged)
            self.state.hold()
            self._send_json(json.dumps(forged).encode(), extra={"id": request_id})
            return
        if path.startswith("/__fault/url"):
            # Answers 200 while reporting a path the caller never asked for.
            forged = entry | {"path": "/__wrong-url", "target": "/__wrong-url"}
            self.state.record(forged)
            self.state.hold()
            self._send_json(json.dumps(forged).encode(), extra={"id": request_id})
            return
        if path.startswith("/__fault/redirect"):
            # Answers `302` to the same URL without the `track` parameter, which is how a document
            # navigation behaves when the core rewrites its URL (`core/src/http/relay.rs`). The local
            # contract tests use it so the navigation control is exercised without a device.
            self.state.record(entry)
            self.state.hold()
            target = path.split("?", 1)[0]
            kept = [
                pair
                for pair in (path.split("?", 1)[1] if "?" in path else "").split("&")
                if pair and pair.split("=", 1)[0] != "track"
            ]
            if kept:
                target += "?" + "&".join(kept)
            self._send_json(
                b'{"fault":"redirect"}', status=302, extra={"id": request_id, "location": target}
            )
            return

        if path.startswith("/__stats"):
            # Both concurrency answers, so a harness never has to take one number on faith: `peak` is
            # the running maximum over arrivals/departures, `overlap` is recomputed from the finished
            # requests' intervals. A run whose claim rests on them must satisfy both.
            payload = json.dumps(self.state.stats() | self.state.overlap()).encode()
        elif path.startswith("/__id"):
            # `--health` uses this: it must answer even when the log cannot be written, because a
            # smoke test's very first step is "is the origin up".
            payload = json.dumps({"ok": True, "id": request_id}).encode()
        else:
            payload = json.dumps(entry, ensure_ascii=False, sort_keys=True).encode()

        self.state.record(entry)
        self.state.hold()
        # A deliberately small but non-empty body: the probes read it to confirm they got the
        # origin's answer rather than a filtered substitute.
        self._send_json(payload, extra={"id": request_id})

    do_GET = _respond
    do_POST = _respond
    do_PUT = _respond
    do_PATCH = _respond
    do_DELETE = _respond
    do_HEAD = _respond
    do_OPTIONS = _respond


class _Threaded(socketserver.ThreadingTCPServer):
    """Threads so 20 simultaneous probes are served concurrently, not queued behind each other."""

    allow_reuse_address = True
    daemon_threads = True
    #: 20 concurrent + headroom; the default 5 would refuse half a batch.
    request_queue_size = 256

    def __init__(self, address, handler, state: _State) -> None:
        self.state = state
        super().__init__(address, handler)

    def finish_request(self, request, client_address) -> None:
        # `http.server` builds the handler class itself; the state goes on through the server
        # attribute the handler reads off `self.server`.
        self.RequestHandlerClass.state = self.state  # type: ignore[attr-defined]
        super().finish_request(request, client_address)


class H2Handler:
    """One HTTP/2 connection, served with the same record as the HTTP/1.1 handler.

    `http.server` speaks only HTTP/1.1, so the TLS listener would have had to either refuse `h2` or
    lie about it. This is the minimal engine that makes the `h2` ALPN entry true: it accepts one
    connection, answers every stream with the JSON record, and honours flow control.

    A request is answered when its stream **ends**, not when its headers arrive: the harness asserts
    the POST body survived decryption on h2, and answering on headers would record an empty body for
    every h2 POST and turn that assertion into a false failure.
    """

    def __init__(self, connection: socket.socket, state: _State) -> None:
        self.connection = connection
        self.state = state
        self.streams: dict[int, dict] = {}

    def serve(self) -> None:
        import h2.config
        import h2.connection
        import h2.events

        config = h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        try:
            h2_connection = h2.connection.H2Connection(config=config)
            h2_connection.initiate_connection()
            self.connection.sendall(h2_connection.data_to_send())
        except Exception:  # noqa: BLE001 - a broken handshake ends this connection
            return

        while True:
            try:
                data = self.connection.recv(65535)
            except (TimeoutError, OSError):
                return
            if not data:
                return
            try:
                events = h2_connection.receive_data(data)
            except Exception:  # noqa: BLE001 - a protocol error ends this connection
                return
            for event in events:
                if isinstance(event, h2.events.RequestReceived):
                    self.streams[event.stream_id] = {
                        "headers": dict(event.headers),
                        "body": bytearray(),
                        "at": time.time(),
                    }
                elif isinstance(event, h2.events.DataReceived):
                    pending = self.streams.get(event.stream_id)
                    if pending is not None:
                        pending["body"].extend(event.data)
                    try:
                        h2_connection.acknowledge_received_data(
                            len(event.data), event.stream_id
                        )
                    except Exception:  # noqa: BLE001 - a closed stream needs no window
                        pass
                elif isinstance(event, h2.events.StreamEnded):
                    self._answer(h2_connection, event.stream_id)
                elif isinstance(event, h2.events.ConnectionTerminated):
                    return
            try:
                pending_bytes = h2_connection.data_to_send()
                if pending_bytes:
                    self.connection.sendall(pending_bytes)
            except OSError:
                return

    def _answer(self, h2_connection, stream_id: int) -> None:
        pending = self.streams.pop(stream_id, None)
        if pending is None:
            return
        headers = pending["headers"]
        path = headers.get(":path", "/")
        method = headers.get(":method", "GET")
        body = bytes(pending["body"])
        entry = _entry(
            self.state,
            request_id=headers.get("x-zs-req", ""),
            method=method,
            path=path,
            http_version="HTTP/2",
            headers={key: value for key, value in headers.items() if not key.startswith(":")}
            | {"host": headers.get(":authority", "")},
            body=body,
            connection=self.connection,
            path_for_probe=path,
        )
        entry["at"] = pending["at"]
        payload = json.dumps(entry, ensure_ascii=False, sort_keys=True).encode()
        try:
            if path.startswith("/__fault/url"):
                entry |= {"path": "/__wrong-url", "target": "/__wrong-url"}
                payload = json.dumps(entry, ensure_ascii=False, sort_keys=True).encode()
            self.state.record(entry)
            self.state.hold()
            status = "500" if path.startswith("/__fault/500") else "200"
            h2_connection.send_headers(
                stream_id,
                [
                    (":status", status),
                    ("content-type", "application/json; charset=utf-8"),
                    ("content-length", str(len(payload))),
                    ("x-zs-req", entry["id"]),
                    ("cache-control", "no-store, no-cache, must-revalidate"),
                ],
            )
            h2_connection.send_data(stream_id, payload, end_stream=True)
        except Exception:  # noqa: BLE001 - a stream reset is the client's business
            return
        finally:
            entry["done"] = time.time()
            self.state.leave(entry)


def _serve_h2(connection: socket.socket, state: _State) -> None:
    """Serve one accepted h2 connection on its own thread, then close it."""
    try:
        H2Handler(connection, state).serve()
    finally:
        try:
            connection.close()
        except OSError:
            pass


def make_server(
    host: str,
    port: int,
    state: _State,
    certfile: str | None = None,
    keyfile: str | None = None,
    alpn: tuple[str, ...] = ("h2", "http/1.1"),
) -> _Threaded:
    """A listening server; TLS with the given ALPN list when a certificate is given."""
    server = _Threaded((host, port), Handler, state)
    if not certfile:
        return server

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)
    # `h2` is advertised only because `get_request` below dispatches on the negotiated protocol.
    context.set_alpn_protocols(list(alpn))

    # The handshake happens per accepted connection, not on the listener: a listening socket has no
    # session yet, so ALPN cannot be negotiated on it.
    #
    # `get_request` is where the dispatch belongs. An h2 connection is served to completion by
    # [`H2Handler`] and then **not returned at all** — the loop simply waits for the next client.
    # Returning a placeholder socket instead would hand `http.server` something it would try to read
    # an HTTP/1.1 request from, which is a confusing failure in place of a clean skip.
    #
    # Each h2 connection is served on its **own thread**. Serving it inline in the accept loop would
    # serialise every h2 client — 20 concurrent requests would arrive one after another, the origin's
    # in-flight peak would stay at 1, and the harness would (correctly) report the run as serialised.
    # That is a property of this server, not of the tunnel, so it must not be the thing under test.
    def get_request():
        while True:
            conn, address = raw_socket.accept()
            try:
                tls = context.wrap_socket(conn, server_side=True)
            except (ssl.SSLError, OSError):
                try:
                    conn.close()
                except OSError:
                    pass
                continue
            if tls.selected_alpn_protocol() == "h2":
                threading.Thread(
                    target=_serve_h2, args=(tls, state), daemon=True
                ).start()
                continue
            return tls, address

    raw_socket = server.socket
    server.get_request = get_request  # type: ignore[method-assign]
    return server


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: loopback only)")
    parser.add_argument("--port", type=int, default=18200)
    parser.add_argument("--https-port", type=int, default=0, help="0 disables the h2-capable TLS listener")
    parser.add_argument(
        "--https1-port",
        type=int,
        default=0,
        help="0 disables the HTTP/1.1-only TLS listener (the TLS/H1 leg)",
    )
    parser.add_argument("--cert", default="", help="PEM certificate for the TLS listeners")
    parser.add_argument("--key", default="", help="PEM key for the TLS listeners")
    parser.add_argument("--log", default=DEFAULT_LOG)
    parser.add_argument(
        "--hold-ms",
        type=float,
        default=0.0,
        help="keep each response open this long, so concurrent requests overlap observably",
    )
    parser.add_argument(
        "--ready-file",
        default="",
        help="write the bound ports here once listening, so a harness can wait for readiness "
        "instead of sleeping",
    )
    arguments = parser.parse_args()

    if (arguments.https_port or arguments.https1_port) and not arguments.cert:
        print("a TLS listener needs --cert/--key", file=sys.stderr)
        return 2

    state = _State(arguments.log, arguments.hold_ms / 1000.0)
    if state.error:
        print(state.error, file=sys.stderr)
        return 2

    servers = [make_server(arguments.host, arguments.port, state)]
    ports = {"http": arguments.port}
    if arguments.https_port:
        servers.append(
            make_server(
                arguments.host,
                arguments.https_port,
                state,
                certfile=arguments.cert,
                keyfile=arguments.key or None,
                alpn=("h2", "http/1.1"),
            )
        )
        ports["https"] = arguments.https_port
    if arguments.https1_port:
        servers.append(
            make_server(
                arguments.host,
                arguments.https1_port,
                state,
                certfile=arguments.cert,
                keyfile=arguments.key or None,
                # Only http/1.1: this listener is the TLS/H1 leg, and offering h2 would let the
                # client pick it, which is the leg this listener exists to *not* be.
                alpn=("http/1.1",),
            )
        )
        ports["https1"] = arguments.https1_port

    if arguments.ready_file:
        with open(arguments.ready_file, "w", encoding="utf-8") as handle:
            json.dump(
                {"ports": ports, "pid": os.getpid(), "log": arguments.log}, handle
            )

    threads = [
        threading.Thread(target=server.serve_forever, daemon=True) for server in servers
    ]
    for thread in threads:
        thread.start()
    print(
        f"tunnel origin listening on {arguments.host}: "
        + ", ".join(f"{name}={port}" for name, port in ports.items())
        + f"; log {arguments.log}; hold {arguments.hold_ms:.0f} ms",
        file=sys.stderr,
        flush=True,
    )
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        for server in servers:
            server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
