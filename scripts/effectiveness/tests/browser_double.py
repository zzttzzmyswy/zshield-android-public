"""A `cdp` stand-in whose pages perform **real** HTTP against the controlled origin.

Loaded by `test_acceptance_entry` through `ZS_CDP_MODULE` (see `tunnel_concurrency.load_cdp`), so the
whole acceptance wrapper — arguments, readiness gate, fault self-test, snapshots, summary, restore —
runs for real while only the browser is replaced. There is no Android browser on this host, and the
device is not touched.

What it must be faithful about, because the wrapper's verdicts depend on it:

  * **the document's origin decides the transport.** A page navigated to `http://…` speaks plaintext;
    to the TLS/H2 port, h2; to the `http/1.1`-only port, h1. A double that kept a fixed label would
    make "the plaintext leg" pass while its requests actually went over TLS.
  * **the rewrite the core performs.** On a decrypted connection the named parameters are dropped
    before the request leaves; on plaintext they are forwarded untouched, because the design forbids
    rewriting there.
  * **`evaluate_start` / `evaluate_collect`.** The batch must run from `start`, not from `collect`:
    that split is what puts several pages in flight at once, which is what the origin's overlap
    counter measures.
  * **both script shapes the harness emits.** `batch_script` sends a `calls` array; the fault
    self-test sends one `url` + `init`. Both are found by their JSON structure rather than by a fixed
    marker, so a change in either template does not silently turn into "no requests".
"""

import json
import ssl
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit, urlunsplit

#: The parameters the simulated core's rules remove on a decrypted connection.
DROP = {"track", "rxparam"}

#: Which leg a document belongs to, by scheme and port. The TLS/H1 listener is the one on :8443.
TRANSPORTS = ("plain", "tls-h1", "tls-h2")


#: The TLS/H1 listener's port, supplied by the test that starts the origin.
#:
#: Matching on ":8443" was a hard-coded guess: the fixture picks a free port, so every TLS document
#: looked like the h2 leg and the TLS/H1 scenarios then failed with "negotiated 'h2' != 'http/1.1'" —
#: a fixture defect that reads exactly like a protocol regression.
TLS1_PORT = int(__import__("os").environ.get("ZS_TLS1_PORT", "0"))


def transport_for(url):
    if url.startswith("http://"):
        return "plain"
    if TLS1_PORT:
        try:
            port = urlsplit(url).port or 443
        except ValueError:
            port = 0
        return "tls-h1" if port == TLS1_PORT else "tls-h2"
    return "tls-h1" if ":8443" in url else "tls-h2"


class CdpError(RuntimeError):
    pass


def _decode_array(script):
    """The `calls` array a batch script describes, or `None`."""
    decoder = json.JSONDecoder()
    index = script.find("[")
    while index != -1:
        try:
            value, _ = decoder.raw_decode(script[index:])
        except ValueError:
            index = script.find("[", index + 1)
            continue
        if (
            isinstance(value, list)
            and value
            and isinstance(value[0], dict)
            and "id" in value[0]
            and "url" in value[0]
        ):
            return value
        index = script.find("[", index + 1)
    return None


def _decode_single(script):
    """The one `url` + `init` a single-request script describes, or `None`."""
    marker = "const url = "
    if marker not in script:
        return None
    decoder = json.JSONDecoder()
    start = script.index(marker) + len(marker)
    url, _ = decoder.raw_decode(script[start:])
    init = {}
    init_marker = "const init = Object.assign({cache:'no-store'}, "
    if init_marker in script:
        init_start = script.index(init_marker) + len(init_marker)
        init, _ = decoder.raw_decode(script[init_start:])
    request_id = ""
    # The header key is written with single quotes in the template and the value is `json.dumps`-ed,
    # so the marker is matched on the key alone: pinning the surrounding quotes made the id silently
    # come back empty, and the `control` case then failed on "the echo carried no request id" — a
    # fixture bug that looked exactly like a harness detection miss.
    header_marker = "'X-ZS-Req': "
    if header_marker in script:
        id_start = script.index(header_marker) + len(header_marker)
        request_id, _ = decoder.raw_decode(script[id_start:])
    scenario = ""
    name_marker = "scenario: "
    if name_marker in script:
        name_start = script.index(name_marker) + len(name_marker)
        scenario, _ = decoder.raw_decode(script[name_start:])
    if request_id:
        # The template sets the header with a separate `init.headers = Object.assign(...)` statement,
        # so it is not part of the `init` literal. Folding it back in is what makes the request carry
        # the id the case asserts on — without it every case reports "the echo carried no request id".
        headers = dict(init.get("headers") or {})
        headers.setdefault("X-ZS-Req", request_id)
        init = dict(init) | {"headers": headers}
    return {"id": request_id, "index": 0, "scenario": scenario, "url": url, "init": init}


def calls_of(script):
    found = _decode_array(script)
    if found is not None:
        return found
    single = _decode_single(script)
    if single is not None:
        return [single]
    raise CdpError("the script carries neither a calls array nor a url")


class Page:
    """One page target: a document origin plus the code that drives it."""

    def __init__(self, target, transport):
        self.target = target
        self.transport = transport

    # -- the value surface ---------------------------------------------------------------
    def evaluate(self, script, **kwargs):
        if script == "location.href":
            return "http://origin.invalid/"
        if "nextHopProtocol" in script and "navigation" in script:
            return "h2" if self.transport == "tls-h2" else "http/1.1"
        # The **shape** follows the script: a batch answers with a list, a single-request script with
        # one object. Returning a list for both made the fault self-test unpack a list as a result and
        # die with `'list' object has no attribute 'get'` — a harness bug reported as a crash.
        if _decode_array(script) is not None:
            return json.dumps(self.perform(script))
        return json.dumps(self.perform(script)[0])

    def perform(self, script):
        results = []
        lock = threading.Lock()

        def one(call):
            results.append(self._one(call, lock))

        threads = [threading.Thread(target=one, args=(call,)) for call in calls_of(script)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        return results

    def _one(self, call, lock):
        split = urlsplit(call["url"])
        target = call["url"]
        if self.transport != "plain":
            kept = [pair for pair in split.query.split("&") if pair.split("=", 1)[0] not in DROP]
            target = urlunsplit(split._replace(query="&".join(kept)))
        context = None
        if target.startswith("https://"):
            context = ssl._create_unverified_context()  # noqa: S323 - a loopback test certificate
        body = (call["init"].get("body") or "").encode() or None
        # The fault self-test gives a case its own abort budget; honouring it is what makes the
        # disconnect case behave like the real page instead of hanging until the transport's timeout.
        budget = (call["init"].get("abort_ms") or 0) / 1000.0
        got = {
            "id": call["id"],
            "index": call.get("index", 0),
            "scenario": call["scenario"],
            "ms": 1.0,
        }
        try:
            with urllib.request.urlopen(
                urllib.request.Request(
                    target,
                    data=body,
                    headers=call["init"].get("headers", {}),
                    method=call["init"].get("method", "GET"),
                ),
                timeout=(budget or 20),
                context=context,
            ) as response:
                text = response.read().decode("utf-8", "replace")
                try:
                    protocol = json.loads(text).get("alpn") or (
                        "h2" if self.transport == "tls-h2" else "http/1.1"
                    )
                except (json.JSONDecodeError, AttributeError):
                    protocol = "http/1.1"
                got |= {
                    "status": response.status,
                    "url": call["url"],
                    "protocol": protocol,
                    "body": text,
                }
        except urllib.error.HTTPError as error:
            got |= {
                "status": error.code,
                "url": call["url"],
                "protocol": "http/1.1",
                "body": error.read().decode("utf-8", "replace"),
            }
        except Exception as error:  # noqa: BLE001 - every transport failure is a result
            got |= {"error": str(error)}
        return got

    # -- the start/collect split, so several pages can be in flight at once ---------------
    def evaluate_start(self, script):
        outcome = {}

        def run():
            try:
                outcome["value"] = self.evaluate(script)
            except Exception as error:  # noqa: BLE001 - reported by `evaluate_collect`
                outcome["error"] = error

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return (thread, outcome)

    def evaluate_collect(self, thread, outcome):
        thread.join()
        if "error" in outcome:
            raise outcome["error"]
        return outcome["value"]

    # -- a real CDP-style navigation -----------------------------------------------------
    def navigate(self, url, timeout=45.0, settle=2.0):
        """Navigate to `url`, reporting the browser's own status and redirect chain.

        The page's transport follows the document it lands on, which is what makes the wrapper's
        single-target fallback meaningful: it re-parks the shared tab on each leg's origin before the
        batch, and this method is how the double models that.
        """
        del timeout
        split = urlsplit(url)
        redirects = [url]
        target = url
        if self.transport != "plain":
            kept = [pair for pair in split.query.split("&") if pair.split("=", 1)[0] not in DROP]
            target = urlunsplit(split._replace(query="&".join(kept)))
            if target != url:
                redirects.append(target)
        context = None
        if target.startswith("https://"):
            context = ssl._create_unverified_context()  # noqa: S323 - a loopback test certificate
        self.transport = transport_for(url)
        time.sleep(settle)
        try:
            with urllib.request.urlopen(target, timeout=20, context=context) as response:
                return {
                    "url": response.url,
                    "status": response.status,
                    "redirects": redirects,
                    "protocol": "h2" if self.transport == "tls-h2" else "http/1.1",
                    "loader_id": "loader-nav",
                    "body": response.read().decode("utf-8", "replace"),
                    "loaded": True,
                }
        except urllib.error.HTTPError as error:
            location = error.headers.get("Location") or target
            redirects.append(location)
            body = ""
            try:
                with urllib.request.urlopen(location, timeout=20, context=context) as followed:
                    body = followed.read().decode("utf-8", "replace")
            except Exception:  # noqa: BLE001 - a failed follow is the checker's business
                pass
            return {
                "url": location,
                "status": 200,
                "redirects": redirects,
                "protocol": "h2" if self.transport == "tls-h2" else "http/1.1",
                "loader_id": "loader-nav",
                "body": body,
                "loaded": True,
            }

    def close(self):
        return None


PAGES = {name: Page({"id": "target-" + name, "type": "page"}, name) for name in TRANSPORTS}


class Browser:
    """A browser exposing one page target per transport."""

    pid = 4242

    @staticmethod
    def attach(*args, **kwargs):
        return Browser()

    def page_targets(self):
        return [page.target for page in PAGES.values()]

    def open_target(self, target, url, timeout=45.0, settle=3.0):
        del timeout, settle
        page = next(
            (p for p in PAGES.values() if p.target["id"] == target["id"]),
            next(iter(PAGES.values())),
        )
        page.transport = transport_for(url)
        return page

    def open(self, url, timeout=45.0, settle=3.0, avoid=None):
        del timeout, settle
        avoid = avoid or set()
        free = [p for p in PAGES.values() if p.target["id"] not in avoid]
        page = (free or list(PAGES.values()))[0]
        page.transport = transport_for(url)
        return page

    def close(self):
        return None


def adb(serial, *args, **kwargs):
    """Unused by the wrapper, but part of the real module's surface."""
    return ""


def shell(serial, command, **kwargs):
    return ""
