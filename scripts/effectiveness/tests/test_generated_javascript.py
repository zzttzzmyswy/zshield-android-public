"""Every JavaScript the harness generates must **parse**, checked by Node itself.

The stage-3 review found `open_page` evaluating a plain Python string that contained `||{{}}`: an
f-string escape had leaked into a literal, and Node rejected it with
`SyntaxError: Unexpected token '{'`. Every test in this suite used a page double, so nothing ever
parsed the script — the harness would have failed on the first real browser and no test noticed.

A regex or a "does it contain `{{`" check would be a second-hand approximation of "is this valid
JavaScript". This file hands each generated script to `node --check`, which is the same parser that
rejected the original. If Node is unavailable the tests skip with a reason rather than passing
silently; the delivery records that skip if it happens.
"""

from __future__ import annotations

import inspect
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import harness_fixtures as fixtures  # noqa: E402

harness = fixtures.harness

NODE = shutil.which("node")


def node_parses(source: str) -> tuple[bool, str]:
    """Whether Node's parser accepts `source`. Returns `(ok, message)`."""
    if NODE is None:  # pragma: no cover - covered by the skip below
        raise RuntimeError("node is not installed")
    completed = subprocess.run(
        [NODE, "--check", "-"],
        input=source,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return completed.returncode == 0, (completed.stderr or completed.stdout).strip()


@unittest.skipIf(NODE is None, "node is not installed; the JavaScript cannot be parsed here")
class GeneratedJavaScriptTest(unittest.TestCase):
    """Each generator's output must be syntactically valid JavaScript."""

    def _assert_parses(self, source: str, what: str) -> None:
        ok, message = node_parses(source)
        self.assertTrue(ok, f"{what} is not valid JavaScript:\n{message}\n--- source ---\n{source}")

    def test_the_batch_script_parses(self) -> None:
        calls = [
            {
                "id": "h2-get-r0-0-abcdef12",
                "index": 0,
                "scenario": "h2-get",
                "url": "https://origin.test/anything/get?keep=1&zs_rid=run-1",
                "init": {"method": "GET", "headers": {"X-ZS-Req": "h2-get-r0-0-abcdef12"}},
            },
            {
                "id": "h2-post-removeparam-r0-1-abcdef34",
                "index": 1,
                "scenario": "h2-post-removeparam",
                "url": "https://origin.test/anything/post?keep=1&track=DROP_ME&zs_rid=run-1",
                "init": {
                    "method": "POST",
                    "body": "gamma=3&delta=4",
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                },
            },
        ]
        self._assert_parses(harness.batch_script(calls), "batch_script")

    def test_the_navigation_script_parses(self) -> None:
        call = {
            "id": "nav-h2-r0-nav-abcdef12",
            "index": 0,
            "scenario": "nav-h2",
            "url": "https://origin.test/anything/nav?keep=1&track=DROP_ME&zs_rid=run-1",
            "redirects": ["https://origin.test/a", "https://origin.test/b"],
            "status": 200,
        }
        self._assert_parses(harness.navigation_script(call), "navigation_script")

    def test_a_script_with_a_quote_in_a_url_parses(self) -> None:
        # A URL can carry a quote once it is percent-encoded into a query value; the script embeds it
        # with `json.dumps`, and this proves that embedding stays valid rather than becoming a broken
        # string literal.
        calls = [
            {
                "id": "q-0-abcdef12",
                "index": 0,
                "scenario": "quoted",
                "url": "https://origin.test/anything/get?keep=%22quoted%22&zs_rid=run-1",
                "init": {"method": "GET", "headers": {"X-ZS-Req": 'weird-"id"-\\value'}},
            }
        ]
        self._assert_parses(harness.batch_script(calls), "batch_script with a quoted id")

    def test_open_page_never_contains_a_brace_escape_in_its_source(self) -> None:
        """A source-level guard beside the behavioural one, naming the cause when it fires.

        The previous revision of this test spelled the *corrected* probe out as a literal and parsed
        that. It passed while production was broken, because a copy of the intended string is not the
        string the code uses — the review reproduced exactly that (`||{{}}` in `open_page`, Node
        `SyntaxError`, suite green). The behavioural test is
        `test_every_expression_open_page_evaluates_parses`; this one only makes the *reason* obvious
        in the failure message, by reading `open_page`'s own source rather than restating it.
        """
        source = inspect.getsource(harness.open_page)
        self.assertNotIn(
            "{{",
            source,
            "open_page's source carries `{{`, an `str.format` escape that is a JavaScript syntax "
            "error in a plain string literal",
        )
        self.assertIn("nextHopProtocol", source, "open_page no longer reads the negotiated protocol")

    def test_every_expression_open_page_evaluates_parses(self) -> None:
        """Parse what `open_page` **actually** hands to `page.evaluate`, on both of its paths.

        The stage-4 review reproduced this: `open_page` evaluated a literal containing `||{{}}`,
        Node rejected it, and the suite above still passed — because
        `test_the_whole_page_probe_every_caller_runs_parses` spelled the *correct* string out again
        instead of taking it from `open_page`. A copy of the right answer is not a test of the code.

        So this drives the real function with a page double that parses each script, for both
        branches `open_page` can take: an independent target (`page_targets` + `open_target`) and the
        single-target fallback (`open` only, which is what a browser exposing one page forces).
        """
        for label, browser in (
            ("independent target", fixtures.ParsingBrowser(targeted=True)),
            ("single-target fallback", fixtures.ParsingBrowser(targeted=False)),
        ):
            page = fixtures.ParsingBrowser.last_page
            with self.subTest(path=label):
                page = harness.open_page(browser, "http://origin.test/", set(), 5, label)
                self.assertTrue(
                    page.scripts,
                    f"{label}: open_page evaluated nothing, so nothing was proven",
                )
                for script in page.scripts:
                    ok, message = node_parses(script)
                    self.assertTrue(
                        ok,
                        f"{label}: open_page evaluated JavaScript Node rejects:\n{message}\n"
                        f"--- source ---\n{script}",
                    )

    def test_no_generated_script_contains_an_unescaped_brace_escape(self) -> None:
        """A cheap invariant beside the parser check, with a message that names the cause.

        `{{` in generated output is always an f-string escape that leaked into a non-f-string — the
        stage-3 defect exactly. `}}` is **not** a defect on its own: two adjacent empty objects
        (`[{…: {}}]`) close with it legitimately. So only `{{` is asserted here; the parser test above
        is what actually decides validity, and this one exists so the failure message says *why*.
        """
        calls = [{"id": "a", "index": 0, "scenario": "s", "url": "http://x/", "init": {}}]
        for name, source in (
            ("batch_script", harness.batch_script(calls)),
            ("navigation_script", harness.navigation_script(calls[0])),
        ):
            self.assertNotIn(
                "{{",
                source,
                f"{name} carries an f-string escape (`{{{{`), which is a JavaScript syntax error",
            )


if __name__ == "__main__":
    unittest.main()
