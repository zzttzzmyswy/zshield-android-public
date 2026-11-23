#!/usr/bin/env python3
"""Drive a WebView in an Android browser over the Chrome DevTools Protocol.

The M3b milestone could not read a test page's JavaScript results: `uiautomator` sees only the
address bar because WebView content is not in the accessibility tree unless the app exposes it. The
unlock is CDP, and it needs two things this module owns:

1. the `webview_devtools_remote_<pid>` abstract socket, which exists only while an app that enabled
   `WebView.setWebContentsDebuggingEnabled` is running, and
2. an `adb forward` bound to *that pid's* socket — the name carries the pid, so the forward has to be
   recreated every time the app restarts. A stale forward silently hangs, which is why
   [`Browser.attach`] verifies the tunnel with a real request instead of trusting `adb forward`'s
   exit code.

Everything here is deliberately standard-library plus `websocket-client`, because this runs from a
plain host shell next to `adb`, not inside the app.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

import websocket


class CdpError(RuntimeError):
    """A CDP call, or the setup it needs, failed."""


#: How many times one `adb` invocation is retried before it is treated as a real failure.
#:
#: The measurement link is Wi-Fi to a phone, and a single `adb shell` call times out for no reason a
#: few times an hour — measured on 2026-11-10, when a 15-minute QUnit pass died with
#: `TimeoutExpired: ['adb', '-s', '<serial>', 'shell', 'cat /proc/net/unix']` after 30 s
#: and lost every page it had measured (`testpages.py` now also saves after each page). A transport
#: hiccup is not a measurement result, so it is retried; a non-zero exit is, and is never retried.
ADB_ATTEMPTS = 3
ADB_RETRY_BACKOFF = 2.0


def adb(serial: str, *args: str, timeout: float = 30.0, check: bool = True) -> str:
    """Run one `adb -s <serial> ...` command and return its stdout, retrying a timeout."""
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += list(args)
    last: subprocess.TimeoutExpired | None = None
    for attempt in range(ADB_ATTEMPTS):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            last = error
            if attempt + 1 < ADB_ATTEMPTS:
                time.sleep(ADB_RETRY_BACKOFF * (attempt + 1))
            continue
        if check and result.returncode != 0:
            raise CdpError(f"{' '.join(cmd)} failed ({result.returncode}): {result.stderr.strip()}")
        return result.stdout
    raise CdpError(f"{' '.join(cmd)} timed out {ADB_ATTEMPTS} times: {last}")


def shell(serial: str, command: str, timeout: float = 30.0, check: bool = True) -> str:
    return adb(serial, "shell", command, timeout=timeout, check=check)


def package_pid(serial: str, package: str) -> int | None:
    out = shell(serial, f"pidof {package}", check=False).strip()
    if not out:
        return None
    # `pidof` may print several pids; the remote socket belongs to the first (the main process).
    return int(out.split()[0])


@dataclass
class Browser:
    """One browser's WebView devtools endpoint, attached over an adb forward."""

    serial: str
    package: str
    #: The local TCP port the forward listens on. Chosen per run so two measurements cannot collide.
    port: int
    pid: int = 0
    _socket: websocket.WebSocket | None = field(default=None, repr=False)

    SOCKET_PREFIXES = ("webview_devtools_remote_", "chrome_devtools_remote")

    @staticmethod
    def devtools_sockets(serial: str) -> dict[str, int]:
        """Every devtools abstract socket on the device, mapped to the pid in its name.

        The name is the only way to find the endpoint: the abstract socket is created by the
        WebView's own process, so the pid is part of it, and a forward must name the exact one.
        """
        out = shell(serial, "cat /proc/net/unix", check=False)
        sockets: dict[str, int] = {}
        for line in out.splitlines():
            if "@" not in line:
                continue
            name = line.rsplit("@", 1)[1].strip()
            for prefix in Browser.SOCKET_PREFIXES:
                if name.startswith(prefix):
                    suffix = name[len(prefix) :].lstrip("_")
                    if suffix.isdigit():
                        sockets[name] = int(suffix)
        return sockets

    @classmethod
    def attach(cls, serial: str, package: str, port: int = 9222) -> "Browser":
        """Forward and verify the devtools endpoint of a running app.

        Verification is a real `GET /json/list`: a forward that points at a dead or wrong socket
        accepts the connection and then never answers, so `adb forward`'s success proves nothing.

        The app is brought to the front *first*. A WebView whose activity is in the background
        throttles its devtools endpoint: the socket exists, the forward succeeds, and every request
        then times out — which reads as "CDP does not work on this device" when it is only asleep.
        """
        pid = package_pid(serial, package)
        if pid is None:
            # The browser was closed (either by a previous run's cleanup or by the platform). Starting
            # it is part of measuring with it: an automation that required the operator to leave a
            # browser open would fail every unattended run. A browser the caller did *not* name is
            # never started — only the one whose devtools endpoint is being measured.
            cls._bring_to_front(serial, package)
            deadline = time.time() + 20
            while time.time() < deadline and pid is None:
                time.sleep(1.0)
                pid = package_pid(serial, package)
            if pid is None:
                raise CdpError(f"{package} could not be started (no pid after 20 s)")

        cls._bring_to_front(serial, package)
        sockets = cls.devtools_sockets(serial)
        expected = f"webview_devtools_remote_{pid}"
        # The socket may be owned by a helper process rather than the pid `pidof` printed (the
        # WebView's sandbox process is a separate one), so prefer the exact expected name and fall
        # back to any socket whose pid is a *live* process of this package.
        candidates = [name for name in sockets if name == expected]
        if not candidates:
            candidates = list(sockets)
        if not candidates:
            raise CdpError(
                f"no devtools socket for {package}: the app has not enabled "
                "WebView.setWebContentsDebuggingEnabled, or has no live WebView"
            )

        last_error = ""
        for name in candidates:
            # Reuse an existing forward that already points at this exact socket. Tearing the forward
            # down and rebuilding it drops every open WebSocket with it, which kills a page a caller
            # is still reading — and two consecutive probes would then sabotage each other.
            if not cls._forward_matches(serial, port, name):
                adb(serial, "forward", "--remove-all", check=False)
                adb(serial, "forward", f"tcp:{port}", f"localabstract:{name}")
            try:
                targets = cls._list(port)
            except (urllib.error.URLError, TimeoutError, OSError) as error:
                # The forward may be stale from an earlier process with the same pid slot; rebuild it
                # once before giving up on this socket.
                adb(serial, "forward", f"tcp:{port}", f"localabstract:{name}", check=False)
                try:
                    targets = cls._list(port)
                except (urllib.error.URLError, TimeoutError, OSError) as retry:
                    last_error = f"{name}: {retry}"
                    continue
            if targets:
                return cls(serial=serial, package=package, port=port, pid=sockets[name])
            last_error = f"{name}: endpoint returned no targets"
        raise CdpError(f"could not attach CDP to {package}: {last_error}")

    @staticmethod
    def _forward_matches(serial: str, port: int, socket_name: str) -> bool:
        """Whether `tcp:<port>` is already forwarded to exactly `socket_name`."""
        listing = adb(serial, "forward", "--list", check=False)
        suffix = f"localabstract:{socket_name}"
        return any(
            f"tcp:{port} " in line and line.rstrip().endswith(suffix) for line in listing.splitlines()
        )

    @staticmethod
    def _bring_to_front(serial: str, package: str) -> None:
        """Wake the screen and launch the app's own launcher activity, then wait for focus.

        `am start -n <launcher activity>` (not a generic `VIEW` intent) is what keeps this from
        launching a *different* browser: a `VIEW` intent is resolved by the system's default handler,
        which on this device is not the browser being measured.

        The screen is woken first because an app cannot come to the front on a dozing device, and
        `svc power stayon true` is set by whoever owns the device session, not here.
        """
        shell(serial, "input keyevent KEYCODE_WAKEUP", check=False)
        resolve = shell(
            serial,
            f"cmd package resolve-activity --brief {package} | tail -1",
            check=False,
        ).strip()
        if "/" in resolve and not resolve.startswith("priority"):
            shell(
                serial,
                f"am start -n {resolve} -a android.intent.action.MAIN "
                f"-c android.intent.category.LAUNCHER",
                check=False,
            )
        else:
            shell(
                serial,
                f"monkey -p {package} -c android.intent.category.LAUNCHER 1",
                check=False,
            )
        # Focus is not instant, and the endpoint is throttled until it arrives.
        deadline = time.time() + 15
        while time.time() < deadline:
            focus = shell(serial, "dumpsys window | grep mCurrentFocus", check=False)
            if package in focus:
                time.sleep(0.5)
                return
            time.sleep(0.5)
        # Not fatal: a device with the lock screen up can still be measured if the app was already
        # foregrounded by the caller. The endpoint check below is the real gate.
        time.sleep(1.0)

    @staticmethod
    def _list(port: int, timeout: float = 8.0) -> list[dict[str, Any]]:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=timeout) as response:
            return json.load(response)

    def targets(self) -> list[dict[str, Any]]:
        """The browser's live page targets, re-establishing the forward if it went away.

        `adb forward` entries are lost when the adb server restarts, when the device reconnects, or
        when another process calls `adb forward --remove-all` — all of which happen during a
        multi-page run. The symptom is a bare `ConnectionRefusedError` from `/json/list`, measured on
        2026-11-10, in the middle of a pass. Rebuilding the forward here keeps every caller working
        without knowing about it.
        """
        try:
            return self._list(self.port)
        except (urllib.error.URLError, TimeoutError, OSError):
            self._reforward()
            return self._list(self.port)

    def _reforward(self) -> None:
        """Rebuild this browser's adb forward from the live devtools socket."""
        sockets = self.devtools_sockets(self.serial)
        name = f"webview_devtools_remote_{self.pid}"
        if name not in sockets:
            # The pid changed (the browser restarted): pick whatever socket is live now.
            if not sockets:
                raise CdpError(f"no devtools socket for {self.package} any more")
            name = next(iter(sockets))
            self.pid = sockets[name]
        adb(self.serial, "forward", "--remove-all", check=False)
        adb(self.serial, "forward", f"tcp:{self.port}", f"localabstract:{name}")

    def open(
        self, url: str, timeout: float = 45.0, settle: float = 3.0, avoid: set[str] | None = None
    ) -> "Page":
        """Navigate a page target to `url` and return a client bound to it.

        `avoid` names target ids a caller already holds. A caller that needs **independent** pages
        (two measurements that must be in flight at the same time) passes the ids it owns; picking
        `targets[0]` again would silently hand it the *same* page, so two `open()` calls were never
        two tabs. When no free target is left this raises instead of quietly reusing one — the
        caller then decides whether it can accept a shared page, and records that it did.

        # Why not `PUT /json/new`

        Android's WebView devtools endpoint does not implement it — it answers `500` — and it cannot:
        the embedding app owns the tab list, so the platform refuses to create one behind its back.
        Navigating an existing page target through CDP is the supported path, and it is equivalent
        for measurement as long as the page is reset first (see [`Page.reset`]), which is what stops
        one measurement's cache and service worker from leaking into the next.
        """
        # Re-asserting focus per page matters for a 20-site loop: a site that opens an external
        # intent can push the browser behind it, and every later reading would then come from a
        # throttled (or wrong) tab.
        self._bring_to_front(self.serial, self.package)
        return self.open_target(self._pick_target(avoid), url, timeout=timeout, settle=settle)

    def open_target(
        self, target: dict[str, Any], url: str, timeout: float = 45.0, settle: float = 3.0
    ) -> "Page":
        """Navigate an already-chosen page target to `url` and return a client bound to it.

        Split out of [`open`] so a caller that must own several *independent* pages can pick the
        targets itself (`page_targets()`) and then drive each one: choosing and navigating in one
        step is what let two calls silently land on the same target.
        """
        page = Page(self, target)
        page.attach()
        page.send("Network.enable")
        page.send("Page.enable")
        page.reset()
        page.final_url = page.navigate(url, timeout=timeout, settle=settle)["url"]
        return page

    def page_targets(self) -> list[dict[str, Any]]:
        """Every `page` target the app exposes, in the endpoint's own order."""
        return [target for target in self.targets() if target.get("type") == "page"]

    def _pick_target(self, avoid: set[str] | None = None) -> dict[str, Any]:
        """A page target of the app's foreground WebView, not one the caller already holds.

        Android browsers expose one `page` target per live WebView, and the first is the one the
        browser's own activity created — the visible tab. A target left over from a previous
        measurement is reused deliberately: navigating it resets everything that could leak.

        `avoid` is what makes isolation explicit rather than accidental: the same target id is never
        handed out twice to a caller that asked for a free one.
        """
        targets = self.page_targets()
        if not targets:
            raise CdpError(f"{self.package} has no page target to drive")
        avoid = avoid or set()
        free = [target for target in targets if str(target.get("id")) not in avoid]
        if not free:
            raise CdpError(
                f"no free page target in {self.package}: it exposes {len(targets)} page target(s) "
                f"and all are held ({sorted(avoid)}). Independent pages need one target each — "
                "open another tab in the browser, or accept a shared target explicitly"
            )
        return free[0]

    def close(self) -> None:
        adb(self.serial, "forward", "--remove-all", check=False)


@dataclass
class Page:
    """One CDP page target."""

    browser: Browser
    target: dict[str, Any]
    _ws: websocket.WebSocket | None = field(default=None, repr=False)
    _next_id: int = 0
    #: Events received while waiting for a response to something else, keyed by method.
    events: dict[str, list[dict[str, Any]]] = field(default_factory=dict, repr=False)
    #: Where the page ended up after the site's own redirects, set by [`Browser.open`].
    final_url: str | None = None

    def attach(self) -> None:
        # Chrome validates the WebSocket `Origin` header and rejects `http://127.0.0.1:<port>`
        # unless the browser was started with `--remote-allow-origins` — which a WebView never is.
        # Omitting the header is the documented way for a non-browser CDP client to connect, and
        # `suppress_origin=True` is what makes `websocket-client` omit it.
        self._ws = websocket.create_connection(
            self.target["webSocketDebuggerUrl"],
            timeout=25,
            max_size=None,
            enable_multithread=True,
            suppress_origin=True,
        )

    def detach(self) -> None:
        if self._ws is not None:
            try:
                self._ws.close()
            finally:
                self._ws = None

    def reset(self) -> None:
        """Clear a page target's caches before a measurement.

        Two measurements of the same site must not share a service worker or an HTTP cache entry: a
        second run would otherwise show the first run's requests as cache hits and report fewer
        requests, which reads as "the filter blocked more".

        `Storage.clearDataForOrigin` is asked for the *current* origin rather than `"*"`: Android's
        WebView endpoint rejects a wildcard origin with "No valid storage type specified", and after a
        navigation the current origin is exactly the one whose storage would leak.
        """
        origin = None
        try:
            href = self.evaluate("location.origin")
            if isinstance(href, str) and href.startswith("http"):
                origin = href
        except CdpError:
            pass
        if origin:
            try:
                self.send(
                    "Storage.clearDataForOrigin",
                    origin=origin,
                    storageTypes="cache_storage,cookies,file_systems,indexeddb,local_storage,"
                    "service_workers,websql",
                )
            except CdpError:
                # An origin that clears nothing is not a reason to fail the measurement: the cache
                # is also cleared below, and every page under test is navigated to fresh.
                pass
        self.send("Network.clearBrowserCache")
        self.send("Network.setCacheDisabled", cacheDisabled=True)

    def send(self, method: str, **params: Any) -> dict[str, Any]:
        """Send one command and return its result, buffering any events that arrive first."""
        if self._ws is None:
            raise CdpError("page is not attached")
        self._next_id += 1
        message_id = self._next_id
        self._ws.send(json.dumps({"id": message_id, "method": method, "params": params}))
        deadline = time.time() + 25
        while time.time() < deadline:
            try:
                raw = self._ws.recv()
            except websocket.WebSocketTimeoutException as error:
                # `websocket-client` raises its own type when the socket's own timeout fires, which is
                # shorter than the deadline above. Left uncaught it escapes as a
                # `WebSocketTimeoutException` in the middle of a run — measured on 2026-11-10, when a
                # whole 14-page pass died that way on the first page. Reported as a `CdpError` so the
                # per-page handler can record it and carry on with the next page.
                raise CdpError(f"{method}: the WebView stopped answering ({error})") from error
            message = json.loads(raw)
            if message.get("id") == message_id:
                if "error" in message:
                    raise CdpError(f"{method} failed: {message['error']}")
                return message.get("result", {})
            method_name = message.get("method")
            if method_name:
                self.events.setdefault(method_name, []).append(message.get("params", {}))
        raise CdpError(f"{method}: no response within 25 s")

    def evaluate(self, expression: str, await_promise: bool = False) -> Any:
        """Evaluate one JavaScript expression in the page and return its value."""
        result = self.send(
            "Runtime.evaluate",
            expression=expression,
            returnByValue=True,
            awaitPromise=await_promise,
            timeout=8000,
        )
        if "exceptionDetails" in result:
            raise CdpError(f"JS threw: {result['exceptionDetails'].get('text')}: {expression[:120]}")
        return result.get("result", {}).get("value")

    def evaluate_start(self, expression: str) -> tuple[int, float]:
        """Send a `Runtime.evaluate` **without** waiting for its reply.

        The point is overlap: a caller holding several pages writes all their scripts first and only
        then collects the answers, so N pages really do have their work in flight at the same time.
        [`evaluate`] blocks on the reply, which serialises such a caller into one page at a time —
        the defect the I2 review measured as "20 requests were never in flight together".

        Returns the message id and the deadline to pass to [`evaluate_collect`].
        """
        if self._ws is None:
            raise CdpError("page is not attached")
        self._next_id += 1
        message_id = self._next_id
        # The WebSocket's own timeout is the read timeout of the next `recv`; the connection was
        # opened with 25 s, which is right for a single command and far too short for a 20-request
        # batch. Raised here and restored by `evaluate_collect`.
        self._ws.settimeout(self.evaluate_deadline)
        self._ws.send(
            json.dumps(
                {
                    "id": message_id,
                    "method": "Runtime.evaluate",
                    "params": {
                        "expression": expression,
                        "returnByValue": True,
                        "awaitPromise": True,
                        "timeout": 240000,
                    },
                }
            )
        )
        return message_id, time.time() + self.evaluate_deadline

    #: How long [`evaluate_collect`] waits for a batch. A 20-request round through a userspace TCP
    #: stack on Wi-Fi takes seconds; a minute is generous without hiding a hang for the whole run.
    evaluate_deadline: float = 240.0

    def evaluate_collect(self, message_id: int, deadline: float) -> Any:
        """Wait for the reply to [`evaluate_start`] and return its value.

        Events that arrive first are buffered exactly as [`send`] does, so a batch that navigates a
        frame or logs a console message does not lose its own reply.
        """
        if self._ws is None:
            raise CdpError("page is not attached")
        try:
            while time.time() < deadline:
                try:
                    raw = self._ws.recv()
                except websocket.WebSocketTimeoutException as error:
                    raise CdpError(
                        f"batch {message_id}: the WebView stopped answering ({error})"
                    ) from error
                message = json.loads(raw)
                if message.get("id") == message_id:
                    if "error" in message:
                        raise CdpError(f"batch {message_id} failed: {message['error']}")
                    result = message.get("result", {})
                    if "exceptionDetails" in result:
                        raise CdpError(
                            f"JS threw: {result['exceptionDetails'].get('text')} (batch {message_id})"
                        )
                    return result.get("result", {}).get("value")
                method_name = message.get("method")
                if method_name:
                    self.events.setdefault(method_name, []).append(message.get("params", {}))
        finally:
            # Back to the per-command timeout every other caller relies on.
            self._ws.settimeout(25)
        raise CdpError(f"batch {message_id}: no response within {self.evaluate_deadline:.0f} s")

    def navigate(
        self, url: str, timeout: float = 45.0, settle: float = 2.0
    ) -> dict[str, Any]:
        """Navigate the page to `url` over CDP and report what the **new** document really did.

        Why this is CDP and not `location.assign` in a `Runtime.evaluate`: after `assign` the old
        document is torn down and the old execution context goes with it. Any script that assigns and
        then immediately reads `document.readyState` or `location.href` reads the *old* document — the
        reply arrives before the new page exists, so its "status" and "redirected" describe nothing.
        The review reproduced exactly that. CDP navigation instead gives the browser's own lifecycle:
        `Page.frameNavigated` carries the new `loaderId` and final URL, `Network.responseReceived`
        with `Document` type carries the real status, and `Network.requestWillBeSent` carries the
        redirect chain.

        Returns a dict with:

          url            the URL the new document is at (after any redirect)
          status         the HTTP status the browser actually received for the document
          redirects      the chain of URLs the browser was redirected through, in order
          protocol       `nextHopProtocol` reported for the navigation
          loader_id      the new document's loaderId, so a caller can prove the document changed
          body           the new document's `document.body.innerText` (the origin's echo)
        """
        previous_loader = self._loader_id()
        redirects: list[str] = []
        response: dict[str, Any] = {}
        navigation = self.send("Page.navigate", url=url)
        error = navigation.get("errorText")
        if error:
            raise CdpError(f"navigation to {url} failed: {error}")

        deadline = time.time() + timeout
        loader_id = navigation.get("loaderId")
        committed = False
        loaded = False
        while time.time() < deadline:
            try:
                raw = self._ws.recv() if self._ws is not None else None
            except websocket.WebSocketTimeoutException:
                continue
            if raw is None:
                break
            message = json.loads(raw)
            method = message.get("method")
            params = message.get("params", {})
            if method == "Page.frameNavigated":
                frame = params.get("frame", {})
                if frame.get("parentId") is None:  # top-level only
                    loader_id = frame.get("loaderId") or loader_id
                    # A new loaderId is the document identity changing, which is what a caller must
                    # be able to check: comparing URLs is not enough, because a redirect keeps one.
                    committed = bool(loader_id) and loader_id != previous_loader
            elif method == "Network.requestWillBeSent":
                request = params.get("request", {})
                if params.get("type") == "Document":
                    if request.get("url"):
                        redirects.append(request["url"])
                    if params.get("redirectResponse"):
                        response = {
                            "status": params["redirectResponse"].get("status"),
                            "url": request.get("url"),
                        }
            elif method == "Network.responseReceived":
                if params.get("type") == "Document":
                    got = params.get("response", {})
                    response = {"status": got.get("status"), "url": got.get("url")}
            elif method == "Page.loadEventFired":
                loaded = True
            if committed and loaded:
                break
        if not committed:
            raise CdpError(
                f"navigation to {url} never committed a new document within {timeout:.0f}s "
                f"(loaderId {previous_loader!r} -> {loader_id!r})"
            )
        if not loaded:
            # A blocked document can legitimately never fire `load`; that is a measurement result, not
            # a harness failure, so it is reported rather than raised. The caller's assertions decide.
            self.events.setdefault("Page.loadEventFired", [])
        time.sleep(settle)
        href = self.evaluate("location.href")
        protocol = self.evaluate(
            "(performance.getEntriesByType('navigation')[0]||{}).nextHopProtocol"
        )
        body = self.evaluate(
            "document.body ? document.body.innerText.slice(0, 65536) : ''"
        )
        return {
            "url": href,
            "status": response.get("status") or 0,
            "redirects": redirects,
            "protocol": protocol or "",
            "loader_id": loader_id,
            "body": body if isinstance(body, str) else "",
            "loaded": loaded,
        }

    def wait_for_load(
        self,
        expected_url: str,
        loader_id: str | None = None,
        timeout: float = 45.0,
        settle: float = 2.5,
    ) -> str:
        """Wait until the navigation `expected_url` is committed and settled.

        # Why the `loaderId` `Page.navigate` returned

        `readyState` alone is a lie right after `Page.navigate`: the *old* document is still there
        and still `complete`, so a poll that only checks `readyState` returns immediately and every
        reading then describes the previous page. That is not hypothetical — it made the first
        measurement of a run report the leftover error page from the site before it.

        Requiring the final URL to *equal* the requested one is also wrong, and cost more
        measurements than the bug it fixed: every mobile-first site redirects
        (`taobao.com` → `main.m.taobao.com`, `news.sina.com.cn` → `news.sina.cn`).

        And comparing against a `loaderId` read *before* navigating is wrong in a third way: this
        WebView sometimes leaves the frame tree reporting the old document for a moment, so the
        comparison can conclude "never navigated" while the new page is in fact loading.

        `Page.navigate`'s own reply carries the committed navigation's `loaderId`, and a server-side
        redirect keeps that same id. So the reply is the ground truth: wait until the frame reports
        that id *and* is `complete`. The final URL is returned rather than asserted, because the
        redirect is part of what the measurement reports.
        """
        previous = self.evaluate("location.href")
        deadline = time.time() + timeout
        location = current = None
        while time.time() < deadline:
            try:
                current = self.evaluate("document.readyState")
                location = self.evaluate("location.href")
            except CdpError:
                current, location = None, None
            if isinstance(location, str):
                if location.startswith("chrome-error://"):
                    # A navigation that failed throws away the document; the error page is what the
                    # caller is meant to record, so stop waiting and let it be read.
                    return location
                committed = loader_id is None or self._loader_id() == loader_id
                if committed and current == "complete":
                    time.sleep(settle)
                    return location
                # A page whose own content is *being filtered* may never reach `complete`: a blocked
                # sub-frame keeps the main document at `interactive` for as long as the browser waits
                # for it. That is the condition under test, not a failed measurement, so once the
                # document has been committed for a while its state is accepted as-is — the caller
                # records `readyState` alongside the reading, so a genuinely stuck page stays visible.
                if committed and current == "interactive" and time.time() > deadline - timeout * 0.4:
                    time.sleep(settle)
                    return location
            time.sleep(0.3)
        raise CdpError(
            f"page did not finish loading {expected_url} within {timeout:.0f}s "
            f"(at {location!r}, readyState {current!r}, was {previous!r})"
        )

    def _loader_id(self) -> str | None:
        """The `loaderId` of the main frame: the identity of the document currently loaded."""
        tree = self.send("Page.getFrameTree")
        return tree.get("frameTree", {}).get("frame", {}).get("loaderId")

    def shot(self, path: str) -> str:
        """Capture the visible viewport as a PNG and write it to `path`."""
        import base64

        result = self.send("Page.captureScreenshot", format="png", fromSurface=True)
        data = base64.b64decode(result["data"])
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def close(self) -> None:
        self.detach()
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.browser.port}/json/close/{self.target['id']}",
            method="PUT",
        )
        try:
            urllib.request.urlopen(request, timeout=5).read()
        except OSError:
            # `URLError` covers the HTTP-level failures, but a socket timeout raises a bare
            # `TimeoutError` (an `OSError`) that used to escape and kill the whole run — measured on
            # 2026-11-10, at the end of page 3 of a 14-page pass. Closing a target is bookkeeping;
            # the next `open` reuses whatever target the browser still has.
            pass


def require(tool: str) -> str:
    path = shutil.which(tool)
    if not path:
        raise SystemExit(f"required tool not found: {tool}")
    return path
