"""`main()` itself: a whole run, driven by a browser double against a real controlled origin.

`test_forward_path` exercises the checks with a host HTTP client. This file exercises the **program**:
it imports `tunnel_concurrency`, replaces `cdp` with a double whose pages perform real HTTP against a
real origin, and calls `main()` with a real argument list. What that proves and nothing else does:

  * the argument plumbing, the page parking, the group loop and the JSON report all run;
  * the browser double reports one target per transport, so the isolation check sees three real ids;
  * a run whose pages return nothing exits non-zero (the review's central finding);
  * a run with a page that answers with a *replayed* batch is caught by the plan comparison;
  * `--readiness` answers "in force" / "not in force" from behaviour, and exits non-zero when the
    named rule did not fire.

The double is a page object with the same surface `cdp.Page` has (`target`, `evaluate`,
`evaluate_start`, `evaluate_collect`), so the harness's own start/collect split is what runs — the
overlap accounting is real, not simulated.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import harness_fixtures as fixtures  # noqa: E402

harness = fixtures.harness


class OriginPage:
    """A page double that performs a real batch against the controlled origin over a real socket.

    `batch_script` is not parsed as JavaScript: the double reads the JSON `calls` array back out of the
    script the harness generated and performs those calls itself. That keeps the test on the harness's
    *contract* (the script carries ids, urls and inits) instead of on its JavaScript, and it means the
    overlap the origin measures is real overlap from real sockets.

    `transport` is which leg this page is, because it decides the framing: the TLS/H2 leg speaks h2,
    the TLS/H1 leg offers h2 and the listener refuses it, and the plaintext leg has no TLS at all.
    Deriving that from the URL would make the double's guess the thing under test.
    """

    def __init__(self, target_id: str, transport: str, *, rewrite: bool = True,
                 empty: bool = False, replay: list[dict] | None = None,
                 drop: set[str] | None = None) -> None:
        self.target = {"id": target_id, "type": "page"}
        self.transport = transport
        self.rewrite = rewrite
        self.empty = empty
        self.replay = replay
        #: The parameters the *simulated* core's rules remove. The acceptance rule set removes both
        #: `track` and `rxparam`; the readiness probe's control case assumes only `track` is named, so
        #: a double that always dropped `rxparam` would fail the control for its own reason.
        self.drop = {"track", "rxparam"} if drop is None else set(drop)
        self.scripts: list[str] = []
        self._started: dict[int, tuple] = {}
        self._next = 0

    # -- helpers -------------------------------------------------------------------------
    @staticmethod
    def _calls(script: str) -> list[dict]:
        marker = "const calls = "
        start = script.index(marker) + len(marker)
        # The JSON literal ends at the first `;\n` after the marker; the script is generated, so this
        # is exact rather than a heuristic.
        end = script.index(";\n", start)
        return json.loads(script[start:end])

    def _perform(self, script: str) -> list[dict]:
        if self.empty:
            return []
        if self.replay is not None:
            return list(self.replay)
        calls = self._calls(script)
        drop = self.drop
        results: list[dict] = []

        def one(call: dict) -> None:
            from urllib.parse import urlsplit, urlunsplit

            split = urlsplit(call["url"])
            # The core's rewrite, played by this double: a decrypted leg drops the named parameters,
            # a plaintext leg forwards them untouched (the design forbids rewriting there).
            if self.rewrite and self.transport != "plain":
                kept = [
                    pair for pair in split.query.split("&") if pair.split("=", 1)[0] not in drop
                ]
                target = urlunsplit(split._replace(query="&".join(kept)))
            else:
                target = call["url"]
            status, body, headersmap = fixtures.request(
                target,
                method=call["init"].get("method", "GET"),
                body=call["init"].get("body", "").encode() or None,
                headers=call["init"].get("headers", {}),
                prefer_h2=self.transport == "tls-h2",
                alpn=("h2", "http/1.1") if self.transport == "tls-h1" else None,
            )
            try:
                protocol = (
                    headersmap.get("X-Negotiated-ALPN")
                    or json.loads(body).get("alpn")
                    or "http/1.1"
                )
            except (json.JSONDecodeError, AttributeError):
                protocol = "http/1.1"
            results.append(
                {
                    "id": call["id"], "index": call["index"], "scenario": call["scenario"],
                    "status": status, "url": call["url"], "redirected": False, "type": "basic",
                    "protocol": protocol, "ms": 1.0, "body": body,
                }
            )

        threads = [threading.Thread(target=one, args=(call,)) for call in calls]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        return results

    # -- the surface the harness uses -----------------------------------------------------
    def evaluate(self, script: str, **kwargs):
        self.scripts.append(script)
        if script == "location.href":
            return "http://origin.invalid/"
        # `location.assign` is checked **before** `nextHopProtocol`: the navigation script contains
        # both (it reports the navigation entry), so a narrower match would answer the navigation with
        # the protocol string and the harness would rightly report it as unparseable.
        if "location.assign" in script:
            # `run_navigation` awaits the value `navigation_script` returns from JavaScript: a JSON
            # *string*. The double returns the same encoding, so the harness's own parsing is what
            # runs — returning a dict here would skip the step under test.
            return json.dumps(self._navigate(script))
        if "nextHopProtocol" in script and "navigation" in script:
            return "h2" if self.transport == "tls-h2" else "http/1.1"
        return json.dumps(self._perform(script))

    def _navigate(self, script: str) -> dict:
        """A real navigation to the scenario's URL, answered by the origin like any other request.

        A navigation **cannot** set a custom header, so this double does not invent one: the record it
        reads is the origin's, and the identity it is checked against is the `zs_rid` in the target.
        """
        import ssl
        import urllib.error
        import urllib.request

        marker = "const target = "
        start = script.index(marker) + len(marker)
        end = script.index(";\n", start)
        url = json.loads(script[start:end])
        context = None
        if url.startswith("https://"):
            context = ssl._create_unverified_context()  # noqa: S323 - a loopback test certificate
        # `track` is what the *core* strips from a rewritten navigation; this double plays the core,
        # so it applies the same rewrite and then follows to the clean URL — which is exactly what a
        # browser behind the tunnel ends up on.
        from urllib.parse import urlsplit, urlunsplit

        split = urlsplit(url)
        if self.rewrite and self.transport != "plain":
            kept = [pair for pair in split.query.split("&") if pair.split("=", 1)[0] not in self.drop]
            url = urlunsplit(split._replace(query="&".join(kept)))
        try:
            with urllib.request.urlopen(url, timeout=10, context=context) as response:
                return {
                    "status": response.status, "url": response.url, "redirected": True,
                    "protocol": "h2" if self.transport == "tls-h2" else "http/1.1",
                    "ms": 1.0, "body": response.read().decode("utf-8", "replace"),
                }
        except urllib.error.HTTPError as error:
            location = error.headers.get("Location") or url
            final = urllib.parse.urljoin(url, location)
            try:
                with urllib.request.urlopen(final, timeout=10, context=context) as followed:
                    body = followed.read().decode("utf-8", "replace")
            except Exception:  # noqa: BLE001 - a failed follow is reported by the checker
                body = ""
            return {
                "status": 200, "url": final, "redirected": True,
                "protocol": "h2" if self.transport == "tls-h2" else "http/1.1",
                "ms": 1.0, "body": body,
            }

    def navigate(self, url: str, timeout: float = 45.0, settle: float = 2.0) -> dict:
        """A real navigation against the origin, reporting the browser's own view of it.

        Same shape as `cdp.Page.navigate`: the status and redirect chain come from what actually
        happened, not from constants. The double applies the rewrite the core would (dropping the
        named parameters on a decrypted leg) and then follows the `302` the core would answer with, so
        the final URL and body are the origin's record of the clean request.
        """
        del timeout
        import ssl
        import urllib.error
        import urllib.request
        from urllib.parse import urljoin, urlsplit, urlunsplit

        split = urlsplit(url)
        redirects = [url]
        target = url
        if self.rewrite and self.transport != "plain":
            kept = [pair for pair in split.query.split("&") if pair.split("=", 1)[0] not in self.drop]
            target = urlunsplit(split._replace(query="&".join(kept)))
            if target != url:
                redirects.append(target)
        context = None
        if target.startswith("https://"):
            context = ssl._create_unverified_context()  # noqa: S323 - a loopback test certificate
        time.sleep(settle)
        try:
            with urllib.request.urlopen(target, timeout=15, context=context) as response:
                return {
                    "url": response.url,
                    "status": response.status,
                    "redirects": redirects,
                    "protocol": "h2" if self.transport == "tls-h2" else "http/1.1",
                    "loader_id": f"loader-{len(self.scripts)}",
                    "body": response.read().decode("utf-8", "replace"),
                    "loaded": True,
                }
        except urllib.error.HTTPError as error:
            location = error.headers.get("Location") or target
            final = urljoin(target, location)
            redirects.append(final)
            body = ""
            try:
                with urllib.request.urlopen(final, timeout=15, context=context) as followed:
                    body = followed.read().decode("utf-8", "replace")
            except Exception:  # noqa: BLE001 - a failed follow is the checker's business
                pass
            return {
                "url": final,
                "status": 200,
                "redirects": redirects,
                "protocol": "h2" if self.transport == "tls-h2" else "http/1.1",
                "loader_id": f"loader-{len(self.scripts)}",
                "body": body,
                "loaded": True,
            }

    def evaluate_start(self, script: str) -> tuple[int, float]:
        """Begin the batch **now**, returning a handle. This is what `cdp.Page.evaluate_start` does.

        The batch runs on its own thread from this call, so a caller that starts every leg before
        collecting any really has all of them in flight — which is what the origin's shared counter
        measures. Doing the work in `evaluate_collect` instead would serialise the legs, and the
        concurrency check would (correctly) report that they never overlapped.
        """
        self._next += 1
        message_id = self._next
        outcome: dict = {}

        def run() -> None:
            try:
                outcome["value"] = self.evaluate(script, await_promise=True)
            except Exception as error:  # noqa: BLE001 - reported by `evaluate_collect`
                outcome["error"] = error

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self._started[message_id] = (thread, outcome)
        return message_id, __import__("time").time() + 120

    def evaluate_collect(self, message_id: int, deadline: float):
        del deadline
        thread, outcome = self._started.pop(message_id)
        thread.join()
        if "error" in outcome:
            raise outcome["error"]
        return outcome["value"]


class BrowserDouble:
    """A browser whose page targets are real doubles against a real origin."""

    def __init__(self, pages: list[OriginPage]) -> None:
        self.pages = pages

    def page_targets(self) -> list[dict]:
        return [page.target for page in self.pages]

    def open_target(self, target: dict, url: str, timeout: float = 45.0, settle: float = 3.0):
        del url, timeout, settle
        for page in self.pages:
            if page.target["id"] == target["id"]:
                return page
        return self.pages[0]

    def open(self, url: str, timeout: float = 45.0, settle: float = 3.0, avoid=None):
        del url, timeout, settle
        avoid = avoid or set()
        for page in self.pages:
            if page.target["id"] not in avoid:
                return page
        return self.pages[0]


class MainEntryTest(unittest.TestCase):
    """`main()` with a stubbed `cdp`, against a real origin."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.origin = fixtures.OriginFixture(tls=True, tls1=True, hold_ms=120).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.origin.stop()

    def setUp(self) -> None:
        import tempfile

        self._temp = tempfile.TemporaryDirectory(prefix="zs-main-")
        self.dir = Path(self._temp.name)
        self._saved_modules = dict(sys.modules)
        self._saved_argv = sys.argv

    def tearDown(self) -> None:
        for name in ("cdp",):
            sys.modules.pop(name, None)
        sys.modules.update(
            {key: value for key, value in self._saved_modules.items() if key not in sys.modules}
        )
        sys.argv = self._saved_argv
        self._temp.cleanup()

    def _run(self, pages: list[OriginPage], argv: list[str]) -> tuple[int, str]:
        import contextlib
        import io

        orig = self.origin

        class Browser:
            @staticmethod
            def attach(*args, **kwargs):
                return BrowserDouble(pages)

        sys.modules["cdp"] = types.SimpleNamespace(Browser=Browser)
        sys.argv = ["tunnel_concurrency.py", *argv]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = harness.main()
        return code, output.getvalue()

    def _base_argv(self, json_path: Path, rounds: int = 1, concurrency: int = 6) -> list[str]:
        orig = self.origin
        return [
            "--origin", orig.base_tls,
            "--http-origin", orig.base,
            "--https-origin", orig.base_tls,
            "--tls1-origin", orig.base_tls1,
            "--rounds", str(rounds),
            "--concurrency", str(concurrency),
            "--serial", "stub",
            "--json", str(json_path),
        ]

    def test_a_whole_run_passes_and_reports_its_evidence(self) -> None:
        pages = [
            OriginPage("target-plain", "plain"),
            OriginPage("target-tls1", "tls-h1"),
            OriginPage("target-tls2", "tls-h2"),
        ]
        json_path = self.dir / "run.json"
        code, output = self._run(pages, self._base_argv(json_path))
        self.assertEqual(code, 0, output)
        self.assertIn("PASS", output)

        report = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertIn("http/1.1", report["protocols"])
        self.assertIn("h2", report["protocols"])
        # Three independent targets, named in the report.
        self.assertEqual(
            len({report["targets"][name] for name in harness.TRANSPORTS}), 3, report["targets"]
        )
        # The overlap is measured per group. A mixed group is split over three independent pages, so
        # each leg carries its share of the concurrency and the busiest leg's share is the bar the
        # harness holds it to (`validate_concurrency` passed, since the run passed).
        peaks = [group["peak"] for group in report["groups"]]
        share = 6 // len(harness.TRANSPORTS)
        self.assertTrue(all(peak and peak >= share for peak in peaks), peaks)

    def test_a_run_whose_pages_return_nothing_fails(self) -> None:
        # The review's first finding, through the real entry point: `[]` for every group.
        pages = [
            OriginPage("t-empty", "plain", empty=True),
            OriginPage("t-empty2", "tls-h1", empty=True),
            OriginPage("t-empty3", "tls-h2", empty=True),
        ]
        code, output = self._run(pages, self._base_argv(self.dir / "empty.json"))
        self.assertNotEqual(code, 0, output)
        self.assertIn("FAIL", output)

    def test_a_replayed_batch_fails(self) -> None:
        # A page that answers with a batch from "somewhere else": the ids do not match the plan.
        replayed = [
            {
                "id": "some-other-run-r0-0-deadbeef", "index": 0, "scenario": "h1-get",
                "status": 200, "url": "http://example/", "protocol": "http/1.1", "ms": 1.0,
                "body": "",
            }
        ]
        pages = [
            OriginPage("t-r1", "plain", replay=replayed),
            OriginPage("t-r2", "tls-h1", replay=replayed),
            OriginPage("t-r3", "tls-h2", replay=replayed),
        ]
        code, output = self._run(pages, self._base_argv(self.dir / "replay.json"))
        self.assertNotEqual(code, 0, output)
        self.assertIn("never issued", output)

    def test_a_run_without_both_framings_fails(self) -> None:
        # Only the h2 leg answers; the run must not pass on the strength of it.
        pages = [
            OriginPage("t-only-1", "plain", empty=True),
            OriginPage("t-only-2", "tls-h1", empty=True),
            OriginPage("t-only-3", "tls-h2"),
        ]
        code, output = self._run(pages, self._base_argv(self.dir / "half.json"))
        self.assertNotEqual(code, 0, output)
        self.assertIn("no request negotiated http/1.1", output)

    def test_readiness_reports_a_rule_in_force(self) -> None:
        page = OriginPage("readiness", "tls-h2", rewrite=True, drop={"track"})
        code, output = self._run(
            [page, page, page],
            ["--origin", self.origin.base_tls, "--serial", "stub", "--readiness", "track,rxparam"],
        )
        self.assertEqual(code, 0, output)
        self.assertIn("readiness-removed-track: OK", output)
        self.assertIn("readiness-control-", output)

    def test_readiness_fails_when_the_rule_does_not_fire(self) -> None:
        # The tunnel that rewrote nothing: the named parameter survives, so the run's rule set is not
        # in force and the acceptance script must not spend a full run on it.
        page = OriginPage("readiness-off", "tls-h2", rewrite=False, drop={"track"})
        code, output = self._run(
            [page, page, page],
            ["--origin", self.origin.base_tls, "--serial", "stub", "--readiness", "track,rxparam"],
        )
        self.assertNotEqual(code, 0, output)
        self.assertIn("readiness-removed-track: FAIL", output)
        self.assertIn("still carries 'track'", output)

    def test_readiness_needs_two_parameter_names(self) -> None:
        page = OriginPage("readiness-bad", "tls-h2", rewrite=True, drop={"track"})
        code, _output = self._run(
            [page, page, page],
            ["--origin", self.origin.base_tls, "--serial", "stub", "--readiness", "track"],
        )
        self.assertEqual(code, 2)

    def test_an_invalid_plan_is_refused(self) -> None:
        page = OriginPage("invalid", "tls-h2", rewrite=True)
        code, output = self._run(
            [page, page, page],
            ["--origin", self.origin.base_tls, "--serial", "stub", "--rounds", "0",
             "--concurrency", "0"],
        )
        self.assertEqual(code, 2, output)
        self.assertIn("must be positive", output)


if __name__ == "__main__":
    unittest.main()
