"""Fixtures the harness contract tests share: a real controlled origin, a fake, and a page double.

The point of this module is that **most tests use a real origin over a real socket**, not a canned
string. The two I2 reviews both found the same class of defect — a check that "passed" because the
thing it was checking had never happened — and a fixture that returns hand-written JSON cannot catch a
harness that never sends a request, keys on the wrong field, or accepts a replayed record. The fake
exists only where a real origin cannot produce the fault (a TLS/H1 leg through the core, a page that
returns an empty batch).

Everything here is loopback: no device, no tunnel, no network. `docs/TESTING.md` §14 says why the
device legs cannot be proven this way, and those are recorded as unverified rather than faked.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent
REPO = SCRIPTS.parent

sys.path.insert(0, str(SCRIPTS))

import tunnel_concurrency as harness  # noqa: E402  - the module under test
import tunnel_origin as origin  # noqa: E402  - the controlled origin the harness reads


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class OriginFixture:
    """The real `tunnel_origin.py` server, on loopback ports, in a subprocess.

    A subprocess rather than an in-process thread: the harness talks to it over the network and reads
    its record file, and running it as its own process is what the acceptance run does. An in-process
    server would share the harness's interpreter and could hide an import or startup failure.
    """

    def __init__(self, *, tls: bool = False, tls1: bool = False, hold_ms: float = 0.0) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="zs-origin-"))
        self.log = self.dir / "origin.jsonl"
        self.ready = self.dir / "ready.json"
        self.http_port = free_port()
        self.https_port = free_port() if tls else 0
        self.https1_port = free_port() if tls1 else 0
        self.cert = self.dir / "cert.pem"
        self.key = self.dir / "key.pem"
        self.proc: subprocess.Popen | None = None
        self.hold_ms = hold_ms
        if tls or tls1:
            self._make_cert()

    def _make_cert(self) -> None:
        """A self-signed certificate for 127.0.0.1, made once per fixture.

        `openssl` rather than a Python library: the repository already depends on it for the build,
        and this keeps the test suite on the standard library plus `h2`.
        """
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-subj", "/CN=127.0.0.1",
                "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
                "-keyout", str(self.key), "-out", str(self.cert),
            ],
            check=True,
            capture_output=True,
        )

    def start(self) -> "OriginFixture":
        command = [
            sys.executable,
            str(SCRIPTS / "tunnel_origin.py"),
            "--port", str(self.http_port),
            "--log", str(self.log),
            "--ready-file", str(self.ready),
            "--hold-ms", str(self.hold_ms),
        ]
        if self.https_port:
            command += ["--https-port", str(self.https_port), "--cert", str(self.cert),
                        "--key", str(self.key)]
        if self.https1_port:
            command += ["--https1-port", str(self.https1_port), "--cert", str(self.cert),
                        "--key", str(self.key)]
        self.proc = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        deadline = time.time() + 20
        while time.time() < deadline:
            if self.ready.exists():
                with urllib.request.urlopen(f"{self.base}/__id", timeout=2) as response:
                    if response.status == 200:
                        return self
            if self.proc.poll() is not None:
                out, err = self.proc.communicate()
                raise RuntimeError(f"the origin exited: {err.decode()[:400]}")
            time.sleep(0.1)
        raise RuntimeError("the origin did not become ready")

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.http_port}"

    @property
    def base_tls(self) -> str:
        return f"https://127.0.0.1:{self.https_port}"

    @property
    def base_tls1(self) -> str:
        return f"https://127.0.0.1:{self.https1_port}"

    def records(self) -> list[dict]:
        """Every request record the origin wrote, in order."""
        if not self.log.exists():
            return []
        return [
            json.loads(line)
            for line in self.log.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def stats(self) -> dict:
        with urllib.request.urlopen(f"{self.base}/__stats", timeout=5) as response:
            return json.load(response)

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover - a stuck process
                self.proc.kill()
                self.proc.wait(timeout=5)
        if self.proc is not None and self.proc.stderr is not None:
            self.proc.stderr.close()
        shutil.rmtree(self.dir, ignore_errors=True)


def h2_request(
    url: str,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict | None = None,
    timeout: float = 20.0,
) -> tuple[int, str, str]:
    """One HTTP/2 request with `h2` as ALPN, returning `(status, body text, negotiated alpn)`.

    Needed because `urllib` cannot speak h2: a host-side client that only offered http/1.1 would
    make the TLS/H2 leg untestable, and asserting h2 from a client that never negotiated it is
    exactly the kind of claim this stage removes. One stream per connection keeps it small; the
    controlled origin serves a connection until it closes.
    """
    import h2.config
    import h2.connection
    import h2.events

    split = urllib.parse.urlsplit(url)
    port = split.port or 443
    context = ssl._create_unverified_context()  # noqa: S323 - a loopback test certificate
    context.set_alpn_protocols(["h2"])
    request_headers = [
        (":method", method),
        (":path", split.path + (("?" + split.query) if split.query else "")),
        (":authority", f"{split.hostname}:{port}" if port != 443 else split.hostname),
        (":scheme", "https"),
    ]
    for name, value in (headers or {}).items():
        request_headers.append((name.lower(), value))
    payload = body or b""
    request_headers.append(("content-length", str(len(payload))))

    with socket.create_connection((split.hostname, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=split.hostname) as tls:
            alpn = tls.selected_alpn_protocol() or ""
            connection = h2.connection.H2Connection(
                config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
            )
            connection.initiate_connection()
            tls.sendall(connection.data_to_send())
            connection.send_headers(1, request_headers)
            connection.send_data(1, payload, end_stream=True)
            tls.sendall(connection.data_to_send())

            status = 0
            chunks = bytearray()
            deadline = time.time() + timeout
            while time.time() < deadline:
                data = tls.recv(65535)
                if not data:
                    break
                for event in connection.receive_data(data):
                    if isinstance(event, h2.events.ResponseReceived):
                        status = int(dict(event.headers).get(":status", 0))
                    elif isinstance(event, h2.events.DataReceived):
                        chunks.extend(event.data)
                        connection.acknowledge_received_data(len(event.data), event.stream_id)
                    elif isinstance(event, h2.events.StreamEnded):
                        return status, chunks.decode("utf-8", "replace"), alpn
                pending = connection.data_to_send()
                if pending:
                    tls.sendall(pending)
            return status, chunks.decode("utf-8", "replace"), alpn


def request(
    url: str,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict | None = None,
    timeout: float = 10.0,
    insecure: bool = False,
    alpn: tuple[str, ...] | None = None,
    prefer_h2: bool = False,
) -> tuple[int, str, dict]:
    """One HTTP(S) request on the host, returning `(status, body text, response headers)`.

    `alpn` is offered explicitly: `urllib`'s default context offers no ALPN at all, so a plain call
    would negotiate nothing and the origin would legitimately record `alpn: null`. A test that wants
    to prove "this listener only offers http/1.1" must offer `h2` itself and see it refused.
    """
    request_headers = dict(headers or {})
    if body is not None and "Content-Type" not in request_headers:
        request_headers["Content-Type"] = "application/x-www-form-urlencoded"
    if prefer_h2 and url.startswith("https://"):
        # Speak h2 when the caller needs the TLS/H2 leg: `urllib` cannot, and a client that only
        # offered http/1.1 would make an h2 assertion pass or fail for the wrong reason.
        status, text, negotiated = h2_request(url, method, body, headers, timeout)
        return status, text, {"X-Negotiated-ALPN": negotiated}
    req = urllib.request.Request(url, data=body, headers=request_headers, method=method)
    context = None
    if url.startswith("https://"):
        context = ssl._create_unverified_context()  # noqa: S323 - a loopback test certificate
        if alpn:
            context.set_alpn_protocols(list(alpn))
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
            return response.status, response.read().decode("utf-8", "replace"), dict(response.headers)
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace"), dict(error.headers)


def batch_result(
    *,
    url: str,
    request_id: str,
    method: str = "GET",
    protocol: str = "http/1.1",
    body: bytes = b"",
    status: int = 200,
    scenario: str = "probe",
    index: int = 0,
) -> dict:
    """A batch member shaped exactly as `batch_script` returns one."""
    return {
        "id": request_id,
        "index": index,
        "scenario": scenario,
        "status": status,
        "url": url,
        "redirected": False,
        "type": "basic",
        "protocol": protocol,
        "ms": 1.0,
        "body": body.decode("utf-8", "replace"),
    }


class PageDouble:
    """A page that answers with a prepared batch, and records what it was asked to run.

    `target` is a real dict because isolation is checked by target id: a double without one would let
    the isolation check pass by absence, which is the defect it exists to catch.
    """

    def __init__(self, target_id: str, payload, *, protocol: str = "http/1.1") -> None:
        self.target = {"id": target_id, "type": "page"}
        self.payload = payload
        self.protocol = protocol
        self.scripts: list[str] = []
        self.started: list[str] = []

    def evaluate(self, script: str, **kwargs):
        self.scripts.append(script)
        if script == "location.href":
            return "http://origin.invalid/"
        if "nextHopProtocol" in script:
            return self.protocol
        if "location.assign" in script:
            if callable(self.payload):
                return json.dumps(self.payload(script))
            return json.dumps(self.payload)
        if callable(self.payload):
            return json.dumps(self.payload(script))
        return json.dumps(self.payload)

    # The start/collect split, so a test can prove the legs are *started* before any is collected.
    def evaluate_start(self, script: str) -> tuple[int, float]:
        self.started.append(script)
        return (len(self.started), time.time() + 30)

    def evaluate_collect(self, message_id: int, deadline: float):
        del deadline
        return self.evaluate(self.started[message_id - 1], await_promise=True)


class BrowserDouble:
    """A browser with a fixed set of page targets, handed out one at a time."""

    def __init__(self, pages: list[PageDouble]) -> None:
        self._pages = pages
        self.opened: list[str] = []

    @staticmethod
    def attach(*args, **kwargs) -> "BrowserDouble":  # pragma: no cover - classmethod shape
        raise AssertionError("attach is not used by these tests")

    def page_targets(self) -> list[dict]:
        return [page.target for page in self._pages]

    def open(self, url: str, timeout: float = 45.0, settle: float = 3.0, avoid=None):
        del timeout, settle
        avoid = avoid or set()
        for page in self._pages:
            if page.target["id"] not in avoid:
                self.opened.append(page.target["id"])
                return page
        self.opened.append(self._pages[0].target["id"])
        return self._pages[0]


class ParsingPage:
    """A page that only records scripts; the test parses them with Node itself.

    Deliberately *not* a `PageDouble`: `PageDouble.evaluate` answers whatever it was asked, so a
    syntactically invalid script looks identical to a valid one. The whole stage-4 defect was that
    kind of answer — the harness never noticed, because nothing ever parsed the script.
    """

    def __init__(self, target_id: str) -> None:
        self.target = {"id": target_id, "type": "page"}
        self.scripts: list[str] = []

    def evaluate(self, script: str, **kwargs):
        self.scripts.append(script)
        if script == "location.href":
            return "http://origin.test/"
        # Any non-navigation expression is answered with a plausible protocol string; the *parse* is
        # the assertion, not the value.
        return "http/1.1"


class ParsingBrowser:
    """Drives `open_page` down both of its branches, so each branch's script is parsed.

    `targeted=True` exposes `page_targets` + `open_target` (the independent-target path the real
    three-leg run needs); `targeted=False` exposes only `open`, which is the single-target fallback
    `open_page` uses when the browser has fewer pages than legs.
    """

    last_page: "ParsingPage | None" = None

    def __init__(self, *, targeted: bool) -> None:
        self._page = ParsingPage("target-1" if targeted else "shared-target")
        ParsingBrowser.last_page = self._page
        if targeted:
            self.page_targets = lambda: [dict(self._page.target)]  # type: ignore[method-assign]
            self.open_target = self._open_target  # type: ignore[attr-defined]

    def _open_target(self, target, url: str, timeout: float = 45.0, settle: float = 3.0):
        del target, url, timeout, settle
        return self._page

    def open(self, url: str, timeout: float = 45.0, settle: float = 3.0, avoid=None):
        del url, timeout, settle, avoid
        return self._page


def origin_record(**fields) -> str:
    """One origin record as the harness receives it (the echo body), with sane defaults."""
    record = {
        "id": "req-1",
        "method": "GET",
        "path": "/anything/get?keep=1&zs_rid=run",
        "target": "/anything/get?keep=1&zs_rid=run",
        "body": "",
        "body_sha256": hashlib.sha256(b"").hexdigest()[:16],
        "body_len": 0,
        "alpn": None,
        "tls": False,
        "inflight": 3,
        "probe": False,
    }
    record.update(fields)
    return json.dumps(record)


def run_script(args: list[str], env: dict | None = None, timeout: float = 120.0):
    """Run one of the repository's scripts and return `(returncode, stdout, stderr)`."""
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, **(env or {})},
        cwd=str(REPO),
    )
    return result.returncode, result.stdout, result.stderr


class SnapshotFixture:
    """A results directory with a `before` and a `settled` snapshot, written directly.

    The defaults describe a **usable** sample of one run: a run id, a timestamp, a readable socket
    table and a complete field set. Every test that wants a refusal overrides exactly the field it is
    about, so a refusal can only come from the field under test.

    `at` defaults to "now" rather than to a fixed number: `check` refuses a snapshot older than its
    window, so a fixture written once into a directory and read later would otherwise fail for
    staleness instead of for the reason the test is about.
    """

    #: The run this fixture's snapshots name, so `check` can be told to require it.
    RUN = "run-fixture"

    def __init__(self, directory: Path, label: str = "accept") -> None:
        self.dir = directory
        self.label = label
        self.run = self.RUN

    def write(self, phase: str, *, pid: str = "4242", uid: str = "10123",
              sockets: str = " 4 01 ", rss: str = "120000", threads: str = "30",
              run: str | None = None, ok: str = "yes", readable: str = "yes",
              collected: str = "7/7", at: int | None = None,
              sockstat: str = "TCP: inuse 40 orphan 0 tw 5 alloc 60 mem 3",
              omit: tuple[str, ...] = ()) -> Path:
        """Write one snapshot. `omit` drops named fields, for the "missing observation" cases."""
        fields = {
            "run": run if run is not None else self.run,
            "at": str(at if at is not None else int(time.time())),
            "pid": pid,
            "uid": uid,
            "readable": readable,
            "sockets": sockets,
            "rss_kb": rss,
            "threads": threads,
            "sockstat": sockstat,
            "collected": collected,
            "ok": ok,
        }
        body = "".join(
            f"{key}={value}\n" for key, value in fields.items() if key not in omit
        )
        path = self.dir / f"tunnel-snapshot-{self.label}-{phase}.txt"
        path.write_text(
            f"# phase={phase} label={self.label}\n{body}", encoding="utf-8"
        )
        return path

    def check(self, *, run: str | None = None) -> subprocess.CompletedProcess:
        env = {**os.environ, "OUT": str(self.dir)}
        wanted = self.run if run is None else run
        if wanted:
            env["RUN_ID"] = wanted
        return subprocess.run(
            ["bash", str(SCRIPTS / "tunnel_snapshot.sh"), "check", self.label],
            capture_output=True,
            text=True,
            env=env,
            cwd=str(REPO),
        )
