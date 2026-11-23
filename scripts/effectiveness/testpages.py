#!/usr/bin/env python3
"""Measure the two public filter-test pages under one measurement condition.

Usage:
    scripts/effectiveness/testpages.py --condition <name> [--out <dir>]

`--condition` is a free-form label recorded in the result (`vpn-off`, `zshield-default`,
`zshield-https`). This script does not change any state itself: the caller has already put the
device in that condition, which is what keeps the three conditions independent and lets the same
harness measure AdGuard later (task card §4).

What it does, per page:

1. attaches to the browser's WebView over CDP (`cdp.py`);
2. opens the page, waits for it to be *scored* (not merely loaded — both pages score from timers
   after `load`, and `adblock-tester` keeps `readyState` at `interactive` indefinitely because of a
   long-polling ad frame);
3. reads the result out of the DOM by the page's own contract, not by scraping prose;
4. captures a first-screen screenshot;
5. writes everything to `<out>/testpages-<condition>.json`.

The two pages are read differently because they score differently:

- **adblock-tester.com** renders one `h3.final-score[data-color]` holding `b.final-score-value` plus a
  per-service list of `✅ test passed` / `❌` lines. Both are read: the total and the breakdown, so a
  change in either is visible.
- **testcases.agrd.dev** is a set of QUnit pages, one per filter feature, and each states
  `N passing / M failing` in `#qunit-testresult`. The *element-hiding* page needs the page's own
  companion filter list installed first (`test-element-hiding-rules.txt`), which the caller injects
  through the app's `DEBUG_SET_RULES` seam; the script records whether the page saw it as
  subscribed (`#subscribe-to-test-element-hiding-rules-filter` hidden) so a run without the list
  cannot be mistaken for a run where the rules failed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cdp  # noqa: E402
import device_serial  # noqa: E402

DEFAULT_BROWSER = os.environ.get("BROWSER", "org.lineageos.jelly")

#: The QUnit pages measured, keyed by the feature family they cover. Each is a page the *shipped*
#: capability set is supposed to act on, so a failure names a concrete missing capability rather
#: than a vague score. Paths come from the site's own route table (`static/js/main.*.js`).
#:
#: Deliberately absent: `$urltransform`, `$replace`, `$content`, `$permissions`, `$stealth`,
#: `$cookie`, `$hls`, `$jsonprune`, userscripts, popup blocking. Those are features this build does
#: not claim at all, so measuring them would report a number with no decision attached. They are
#: listed in `docs/EFFECTIVENESS.md` instead, with the coverage count that motivated the choice.
QUNIT_PAGES = [
    ("element-hiding", "Filters/element-hiding-rules/test-element-hiding-rules.html"),
    ("generichide", "Filters/generichide-rules/generichide-rules.html"),
    ("css-rules", "Filters/css-rules/css-rules.html"),
    ("extended-css", "Filters/extended-css-rules/test-extended-css-rules.html"),
    ("scriptlets", "Filters/scriptlet-rules/test-scriptlet-rules.html"),
    ("important", "Filters/important-rules/test-important-rules.html"),
    ("badfilter", "Filters/badfilter-rules/test-badfilter-rules.html"),
    ("network-rules", "Filters/network-rules/test-network-rules.html"),
    ("redirect", "Filters/redirect-rules/test-redirect-rules.html"),
    ("csp", "Filters/csp-rules/test-csp-rules.html"),
    ("removeparam", "Filters/removeparam-rules/test-removeparam-rules.html"),
    ("removeheader", "Filters/removeheader-rules/test-removeheader-rules.html"),
    ("advanced-domain", "Filters/advanced-domain-modifier/test-advanced-domain-modifier.html"),
    ("subdocument", "Filters/subdocument-rules/test-subdocument-rules.html"),
]

#: The companion filter list each QUnit page needs. Every page states "Before doing the test, import
#: <name>.txt" in its own script, and without that list the page measures nothing — the element-hiding
#: page is the one this mattered for in M3b, and it applies to all of them.
QUNIT_TEST_LISTS = {
    "element-hiding": "Filters/element-hiding-rules/test-element-hiding-rules.txt",
    "generichide": "Filters/generichide-rules/generichide-rules.txt",
    "css-rules": "Filters/css-rules/css-rules.txt",
    "extended-css": "Filters/extended-css-rules/test-extended-css-rules.txt",
    "scriptlets": "Filters/scriptlet-rules/test-scriptlet-rules.txt",
    "important": "Filters/important-rules/test-important-rules.txt",
    "badfilter": "Filters/badfilter-rules/test-badfilter-rules.txt",
    "network-rules": "Filters/network-rules/test-network-rules.txt",
    "redirect": "Filters/redirect-rules/test-redirect-rules.txt",
    "csp": "Filters/csp-rules/test-csp-rules.txt",
    "removeparam": "Filters/removeparam-rules/test-removeparam-rules.txt",
    "removeheader": "Filters/removeheader-rules/test-removeheader-rules.txt",
    "advanced-domain": "Filters/advanced-domain-modifier/test-advanced-domain-modifier.txt",
    "subdocument": "Filters/subdocument-rules/test-subdocument-rules.txt",
}

#: Every QUnit page's "am I subscribed?" banner has this shape: `subscribe-to-<page>-filter`.
SUBSCRIBE_BANNER = "subscribe-to-"

#: The debug broadcast that replaces the app's user rules, and the intent the condition scripts use.
DEBUG_SET_RULES = "top.zztweb.zshield.action.DEBUG_SET_RULES"
DEBUG_RECEIVER = "top.zztweb.zshield/.filters.DebugCommandReceiver"
RULES_ON_DEVICE = "/data/local/tmp/zshield-test-lists.txt"

#: The identity used to fetch a companion list. The site answers a bare `urllib` User-Agent with 403.
BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 16; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/156.0.0.0 Mobile Safari/537.36"
)


def install_test_list(serial: str, base: str, key: str) -> str | None:
    """Replace the app's user rules with **one page's** companion list. Returns the list's text.

    Per page, not all fourteen at once, because the lists contradict each other:
    `generichide-rules.txt` contains `@@||testcases.agrd.dev$generichide`, which disables *every*
    page's generic element hiding. Installing all fourteen measures a rule set no page was written
    for — `docs/EFFECTIVENESS.md` §10.2 records that change as the difference between M5a's meaningless
    numbers and M5b's usable ones.

    The text goes over as a **file**, not as one giant `--es` argument: `adb shell` re-parses its
    argument through the device's own `sh`, which eats `|`, `*`, `(`, `)` and `'` — all of which appear
    in filter rules (`$domain=a|b`, `*$script`, `##.a:style(width: 1px)`). Reading it back with
    `"$(cat …)"` keeps every byte, because the substitution result is a single argument.
    """
    path = QUNIT_TEST_LISTS.get(key)
    if path is None:
        return None
    url = f"{base}/{path}"
    body = fetch_list(key, url)
    local = Path(".effectiveness/lists")
    local.mkdir(parents=True, exist_ok=True)
    (local / f"{key}.txt").write_text(body, encoding="utf-8")
    cdp.adb(serial, "push", str(local / f"{key}.txt"), RULES_ON_DEVICE, timeout=60)
    # The reload is observable but it takes ~9 s on the Pixel 5 — the compile alone is ~2 s and the
    # broadcast is queued behind whatever the previous page left running. `logcat -c` before the
    # broadcast is what makes any line seen afterwards belong to *this* reload; the order matters and
    # was got wrong once (clearing after the broadcast discarded the very line the wait looked for).
    output = cdp.shell(serial, "logcat -c", check=False)
    cdp.shell(
        serial,
        f"sh -c 'am broadcast -a {DEBUG_SET_RULES} -n {DEBUG_RECEIVER} "
        f'--es rules "$(cat {RULES_ON_DEVICE})"\'',
        timeout=60,
    )
    wait_for_reload(serial, key)
    return body


def wait_for_reload(serial: str, key: str, timeout: float = 120.0) -> None:
    """Block until the app has actually swapped in the rule set this page needs.

    # Why a fixed sleep is not enough

    The broadcast is asynchronous and the reload *compiles* the whole rule set before swapping it in:
    ~2.1 s of compile plus the debounce and the queue, measured at ~9 s wall-clock end to end on the
    Pixel 5. A fixed 10 s wait was the previous answer and it silently measured the wrong list often
    enough to be visible: in one 14-page pass `$removeparam` scored 5/14 while the same build scored
    14/14 when its list was installed on its own, because the page loaded against the previous page's
    rules.

    The swap is what this waits for, not the compile: `hot reload finished: ok=true` is written by
    `FilterRepository.reloadIfTunnelRunning` after the tunnel has the new rules, so a page opened
    after it is guaranteed to be judged by them.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        output = cdp.shell(
            serial,
            "logcat -d -b all 2>/dev/null | grep -E 'hot reload finished' | tail -1",
            check=False,
        )
        if "hot reload finished" in output:
            # One more moment for the pipeline to publish the new `Arc` to in-flight requests.
            time.sleep(1.5)
            return
        time.sleep(1.0)
    print(f"  warning: no reload seen for {key} within {timeout:.0f}s", file=sys.stderr)
    time.sleep(5.0)


#: How many times one companion-list fetch is attempted before the page is skipped.
LIST_FETCH_ATTEMPTS = 4


def fetch_list(key: str, url: str) -> str:
    """Fetch one companion list, retrying the host's flaky TLS.

    `urllib` against this site fails intermittently with
    `SSL: UNEXPECTED_EOF_WHILE_READING` (measured on 2026-11-10; the same URL succeeds on the next
    attempt, and `curl` is unaffected). A transport failure is not a measurement result, so it is
    retried here with a backoff rather than aborting a 15-minute device pass at page 3 — which is what
    happened before this existed.

    The cached copy under `.effectiveness/lists/` is the fallback of last resort: a list that has been
    fetched once is reused rather than losing the whole run to a transient network fault.
    """
    cached = Path(".effectiveness/lists") / f"{key}.txt"
    last: Exception | None = None
    for attempt in range(LIST_FETCH_ATTEMPTS):
        try:
            # A bare `urllib` User-Agent (`Python-urllib/3.x`) is answered with **403** by this site,
            # which is why the fetch sends the same browser identity the measurement uses.
            fetch = urllib.request.Request(url, headers={"User-Agent": BROWSER_USER_AGENT})
            with urllib.request.urlopen(fetch, timeout=45) as response:
                return response.read().decode("utf-8", "replace")
        except Exception as error:  # noqa: BLE001 - the retry covers every transport failure
            last = error
            time.sleep(2 * (attempt + 1))
    if cached.exists() and cached.stat().st_size > 0:
        print(
            f"  {key}: fetch failed ({last}); reusing the cached copy at {cached}",
            file=sys.stderr,
        )
        return cached.read_text(encoding="utf-8")
    raise cdp.CdpError(f"cannot fetch the {key} companion list from {url}: {last}")


def clear_test_list(serial: str) -> None:
    """Drop the user rules, so the next page starts from the shipped set again."""
    cdp.shell(
        serial,
        f"am broadcast -a {DEBUG_SET_RULES} -n {DEBUG_RECEIVER} --es rules ''",
        timeout=60,
    )
    time.sleep(4)


def subscription_state(page: cdp.Page) -> dict:
    """Whether the page's companion test list is in force, as the page itself reports it.

    The banner is a `<div id="subscribe-to-…-filter">` the companion list hides with a rule. When it
    is still visible the test list was never applied, and every assertion below it is meaningless —
    which is why this is recorded per page instead of assumed.
    """
    return page.evaluate(
        "(() => {"
        " const banner = document.querySelector('[id^=\"subscribe-to-\"]');"
        " if (!banner) return { present: false };"
        " return { present: true, id: banner.id,"
        "   subscribed: getComputedStyle(banner).display === 'none' };"
        "})()"
    )


def scroll_into_view(page: cdp.Page, selector: str) -> bool:
    """Scroll `selector` to the middle of the viewport; return whether it was found.

    The screenshot has to show the *result*, not the site's banner: adblock-tester renders its score
    below a full-screen header, so a first-screen capture of a correct run would look identical to a
    run where nothing was measured.
    """
    return bool(
        page.evaluate(
            "(() => { const el = document.querySelector(%s);"
            " if (!el) return false;"
            " el.scrollIntoView({block: 'center'}); return true; })()" % json.dumps(selector)
        )
    )


def read_adblock_tester(page: cdp.Page) -> dict:
    """Read the total and the per-service breakdown off adblock-tester.com."""
    script = r"""
(() => {
  const final = document.querySelector('h3.final-score');
  const value = document.querySelector('.final-score-value');
  const services = [];
  document.querySelectorAll('.service, .services-list > *').forEach(node => {
    const title = node.querySelector('.service-title, h4, b');
    const lines = [...node.querySelectorAll('*')]
      .map(el => (el.children.length === 0 ? (el.textContent || '').trim() : ''))
      .filter(text => /test (?:has most likely )?(passed|failed)|not blocked|blocked|checking|unable to check/i.test(text));
    if (title || lines.length) {
      services.push({
        name: (title ? title.textContent : '').trim().slice(0, 60),
        lines: lines.slice(0, 4),
      });
    }
  });
  return {
    title: document.title,
    url: location.href,
    score: value ? Number(value.textContent.trim()) : null,
    color: final ? final.getAttribute('data-color') : null,
    finalText: final ? final.textContent.replace(/\s+/g, ' ').trim().slice(0, 120) : null,
    services,
    checkStatuses: [...document.querySelectorAll('.service .check-list .status')]
      .map(node => node.getAttribute('data-status')),
    bodyText: document.body.innerText.replace(/\s+/g, ' ').slice(0, 4000),
  };
})()
"""
    return page.evaluate(script)


def wait_for_adblock_score(page: cdp.Page, timeout: float = 60.0) -> None:
    """Wait until the page has rendered its final score.

    Neither readyState nor a stable score proves completion: a request can remain pending while
    the interim score is unchanged. Require the site's checks to leave pending, then two identical
    complete readings so its reactive score update has settled. Unknown/failed results are final
    too; this waits for completion, never for a desired score.
    """
    deadline = time.monotonic() + timeout
    previous = None
    terminal = {"blocked", "likelyBlocked", "unblocked", "likelyUnblocked", "unknown"}
    state = None
    while time.monotonic() < deadline:
        state = page.evaluate(
            "(() => { const v = document.querySelector('.final-score-value');"
            " return {score: v ? v.textContent.trim() : null,"
            " statuses: [...document.querySelectorAll('.service .check-list .status')]"
            " .map(n => n.getAttribute('data-status'))}; })()"
        )
        value = state.get("score") if isinstance(state, dict) else None
        statuses = state.get("statuses") if isinstance(state, dict) else None
        complete = (
            isinstance(value, str) and value.isascii() and value.isdigit()
            and 0 <= int(value) <= 100
            and isinstance(statuses, list) and bool(statuses)
            and all(isinstance(status, str) and status in terminal for status in statuses)
        )
        if complete and state == previous:
            return
        previous = state if complete else None
        time.sleep(1.0)
    raise cdp.CdpError(f"adblock-tester checks did not finish with a stable score: {state}")


def read_qunit(page: cdp.Page) -> dict:
    """Read a QUnit page's result block and the per-test list."""
    script = r"""
(() => {
  const result = document.querySelector('#qunit-testresult');
  const tests = [...document.querySelectorAll('#qunit-tests > li')].map(li => {
    const name = li.querySelector('.test-name');
    const failed = li.classList.contains('fail');
    const skipped = li.classList.contains('skipped');
    return {
      name: name ? name.textContent.trim().slice(0, 120) : '',
      status: skipped ? 'skipped' : (failed ? 'failed' : 'passed'),
      assertions: [...li.querySelectorAll('.test-assertion')].map(a => ({
        message: (a.querySelector('.test-message') || {}).textContent || '',
        passed: !a.classList.contains('fail'),
      })).slice(0, 12),
    };
  });
  return {
    title: document.title,
    url: location.href,
    resultText: result ? result.textContent.replace(/\s+/g, ' ').trim() : null,
    tests,
    bodyText: document.body.innerText.replace(/\s+/g, ' ').slice(0, 2000),
  };
})()
"""
    return page.evaluate(script)


def wait_for_qunit(page: cdp.Page, timeout: float = 180.0) -> None:
    """Wait until QUnit has finished, not merely until it has said something.

    # Why the old wait was wrong

    `#qunit-testresult` is rewritten on every completed test, so it holds a *running* sentence —
    `8 / 14 tests completed.Running: Testcase 9 — negate $removeparam` — for most of the page's life.
    The previous version returned as soon as that text matched `completed`, i.e. after the eighth test,
    and the caller then read the DOM with six cases still to run. Every page that reports the
    `N / M tests completed` form was therefore measured early, and the results read as "aborted with N
    failures" rather than "read too early".

    The settle signal is the completed count: once it has not advanced for [`QUIET_SECONDS`], the page
    has finished (or is stuck, which the caller can see in the counts it records either way).
    """
    deadline = time.time() + timeout
    last_count = -1
    stable_since = time.time()
    while time.time() < deadline:
        text = page.evaluate(
            "(() => { const r = document.querySelector('#qunit-testresult');"
            " return r ? r.textContent : null; })()"
        )
        count = 0
        total = 0
        if text:
            match = re.search(r"(?:(\d+) / (\d+)|(\d+) tests)", text)
            if match:
                count = int(match.group(1) or match.group(3))
                total = int(match.group(2) or match.group(3))
        # Done means *all* tests reported, not "the count stopped moving": the page spends seconds on a
        # slow case (`$removeparam` fetches a real endpoint per case) and a plateau in the middle looks
        # exactly like the end. The total is in the same sentence, so it is checked directly.
        if total > 0 and count >= total:
            time.sleep(1.5)
            return
        if count != last_count:
            last_count = count
            stable_since = time.time()
        elif count > 0 and time.time() - stable_since > QUIET_SECONDS:
            # A genuine abort: QUnit stops without ever reaching the total.
            time.sleep(1.5)
            return
        time.sleep(0.5)
    raise cdp.CdpError("QUnit never reported a result")


#: How long the completed-test count must stay unchanged before a page counts as aborted.
#:
#: Only reached when the count never equals the total; six seconds is longer than the slowest case on
#: this device and short enough that a genuinely stuck page does not hold the whole pass.
QUIET_SECONDS = 6.0


def parse_qunit_counts(text: str | None) -> dict:
    """Extract the test and assertion counts from QUnit's summary sentence.

    The sentence is a concatenation of several spans, so it reads like
    `10 tests completed … with 10 failed, 0 skipped, and 0 todo.1 assertions of 17 passed, 16 failed.`
    — note there is no space between `todo.` and `1 assertions`, and that `passed`/`failed` appear both
    as a *test* count and as an *assertion* count. Both readings are captured.

    QUnit's assertion clause is `N assertions of M passed, K failed`: **N** passed out of **M**
    assertions, with **K** failures. For example the measured element-hiding page reports
    `15 assertions of 17 passed, 2 failed`; the total is 17, not 19.

    # The aborted form

    `network-rules` and `removeparam` stop the run partway (`Abort` in `#qunit-testresult`) when a rule
    the page needs is missing — `docs/TESTING.md` §12.7 records it. The summary then reads
    `11 / 14 tests completed.Running: Testcase 12 — …` instead of `N tests completed`, and there is no
    `with N failed` clause at all. That used to leave `testsPassed` unset, which is why §10.2 lists this
    page as 未取到. The completed count and the per-test list are both still there, so the counts are
    derived from them: `completed` tests of which the failed/skipped ones are known individually.
    """
    if not text:
        return {}
    counts: dict = {}
    if match := re.search(r"(\d+)\s*/\s*(\d+)\s+tests?\s+completed", text):
        # Aborted run: `completed` of `planned`, and no failure clause.
        counts["tests"] = int(match.group(1))
        counts["testsPlanned"] = int(match.group(2))
        counts["aborted"] = True
    elif match := re.search(r"(\d+)\s+tests?\s+completed", text):
        counts["tests"] = int(match.group(1))
    if match := re.search(r"with\s+(\d+)\s+failed", text):
        counts["testsFailed"] = int(match.group(1))
    if match := re.search(r"(\d+)\s+skipped", text):
        counts["testsSkipped"] = int(match.group(1))
    if match := re.search(r"(\d+)\s+assertions?\s+of\s+(\d+)\s+passed,\s+(\d+)\s+failed", text):
        counts["assertionsPassed"] = int(match.group(1))
        counts["assertionsFailed"] = int(match.group(3))
        counts["assertionsTotal"] = int(match.group(2))
    if counts.get("tests") is not None and counts.get("testsFailed") is not None:
        counts["testsPassed"] = counts["tests"] - counts["testsFailed"] - counts.get("testsSkipped", 0)
    return counts


def shot_or_none(page: cdp.Page, path: Path) -> str | None:
    """Capture a screenshot, or `None` when the WebView will not produce one.

    The screenshot is **evidence**, not measurement: the numbers above it came from the DOM and are
    already in hand. `Page.captureScreenshot` is the heaviest call in the loop and the one that times
    out when the browser is throttled, so letting it abort the page would trade a measurement for a
    picture. Measured on 2026-11-10: the element-hiding page read `10 tests completed` and then lost
    the whole reading to a screenshot timeout.
    """
    try:
        return page.shot(str(path))
    except (cdp.CdpError, OSError) as error:
        print(f"  screenshot failed for {path.name}: {error}", file=sys.stderr)
        return None


def fill_counts_from_tests(reading: dict) -> None:
    """Complete `reading["counts"]` from the per-test list when the summary sentence is aborted.

    An aborted QUnit run prints `11 / 14 tests completed.` and never prints `with N failed`, so
    [`parse_qunit_counts`] can only recover how many tests ran. The `<li>` list it does render carries
    each test's status, so the pass/fail split is read from there — that is the same evidence the
    summary would have given, just not aggregated.
    """
    counts = reading.get("counts") or {}
    tests = reading.get("tests") or []
    if "testsPassed" in counts or not tests:
        reading["counts"] = counts
        return
    failed = sum(1 for test in tests if test.get("status") == "failed")
    skipped = sum(1 for test in tests if test.get("status") == "skipped")
    counts.setdefault("tests", len(tests))
    counts["testsFailed"] = failed
    counts["testsSkipped"] = skipped
    counts["testsPassed"] = len(tests) - failed - skipped
    counts["countedFromTestList"] = True
    reading["counts"] = counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--condition", required=True, help="measurement condition label")
    parser.add_argument("--out", default=".effectiveness/results", help="result directory")
    parser.add_argument("--serial", default=None,
                        help="adb serial; defaults to $SERIAL, else the only attached device")
    parser.add_argument("--browser", default=DEFAULT_BROWSER)
    parser.add_argument("--port", type=int, default=9222)
    parser.add_argument("--base", default="https://testcases.agrd.dev", help="QUnit site root")
    parser.add_argument(
        "--only",
        choices=["adblock-tester", "qunit"],
        default=None,
        help="measure just one of the two families",
    )
    parser.add_argument("--shots", default=None, help="screenshot directory (defaults to <out>/shots)")
    parser.add_argument(
        "--pages",
        default=None,
        help="comma-separated QUnit page keys to measure (default: all 14). Re-measuring the two or "
        "three pages a fix touches does not require waiting out the other eleven.",
    )
    parser.add_argument(
        "--no-test-lists",
        dest="install_test_lists",
        action="store_false",
        help="do not install each QUnit page's companion filter list (measures "
        "'does this build speak the syntax at all', not the filtering result)",
    )
    parser.set_defaults(install_test_lists=True)
    parser.add_argument(
        "--suffix",
        default="",
        help="appended to the result file name, so two passes of one condition do not overwrite each other",
    )
    arguments = parser.parse_args()
    arguments.serial = device_serial.serial_from(arguments)
    if arguments.pages:
        arguments.pages = {page.strip() for page in arguments.pages.split(",") if page.strip()}
        unknown = arguments.pages - {key for key, _ in QUNIT_PAGES}
        if unknown:
            parser.error(f"unknown QUnit page(s): {', '.join(sorted(unknown))}")

    out = Path(arguments.out)
    out.mkdir(parents=True, exist_ok=True)
    shots = Path(arguments.shots) if arguments.shots else out / "shots"
    shots.mkdir(parents=True, exist_ok=True)

    result: dict = {
        "condition": arguments.condition,
        "device": arguments.serial,
        "browser": arguments.browser,
        "measuredAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "adblockTester": None,
        "qunit": {},
        "errors": [],
    }

    destination = out / f"testpages-{arguments.condition}{arguments.suffix}.json"

    def save() -> None:
        """Write the result so far.

        Called after **every** page, not only at the end: a full 14-page pass takes ~15 minutes on
        this device and the link is slow enough that an interrupted or timed-out run used to lose
        every measurement it had already made. Each page is the expensive part; the JSON write is not.
        """
        destination.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    browser = cdp.Browser.attach(arguments.serial, arguments.browser, port=arguments.port)
    print(f"attached {arguments.browser} pid={browser.pid} over tcp:{arguments.port}")

    try:
        if arguments.only in (None, "adblock-tester"):
            try:
                page = browser.open("https://adblock-tester.com/", settle=2.0)
                wait_for_adblock_score(page)
                reading = read_adblock_tester(page)
                scroll_into_view(page, "h3.final-score")
                shot = shot_or_none(
                    page, shots / f"adblock-tester-{arguments.condition}{arguments.suffix}.png"
                )
                reading["screenshot"] = shot
                result["adblockTester"] = reading
                print(f"adblock-tester: {reading.get('score')}/100")
                page.close()
            except cdp.CdpError as error:
                result["errors"].append(f"adblock-tester: {error}")
                print(f"adblock-tester FAILED: {error}", file=sys.stderr)
            save()

        if arguments.only in (None, "qunit"):
            for key, path in QUNIT_PAGES:
                if arguments.pages and key not in arguments.pages:
                    continue
                url = f"{arguments.base}/{path}"
                try:
                    # The page's own companion list replaces the user rules, one page at a time
                    # ([`install_test_list`]). `--no-test-lists` skips it, which is the "does this
                    # build speak the syntax at all" pass.
                    if arguments.install_test_lists:
                        install_test_list(arguments.serial, arguments.base, key)
                    page = browser.open(url, settle=1.5)
                    wait_for_qunit(page)
                    reading = read_qunit(page)
                    reading["counts"] = parse_qunit_counts(reading.get("resultText"))
                    fill_counts_from_tests(reading)
                    reading["testList"] = QUNIT_TEST_LISTS.get(key)
                    reading["subscription"] = subscription_state(page)
                    scroll_into_view(page, "#qunit-testresult")
                    reading["screenshot"] = shot_or_none(
                        page, shots / f"qunit-{key}-{arguments.condition}{arguments.suffix}.png"
                    )
                    result["qunit"][key] = reading
                    print(f"qunit {key}: {reading.get('resultText')}", flush=True)
                    page.close()
                except Exception as error:  # noqa: BLE001 - one page must never end the pass
                    # Deliberately broad. Every page costs ~70 s of device time, and a transport
                    # fault in `page.close()`/`shot()` (a bare `TimeoutError`, not a `CdpError`) used
                    # to abort the whole 14-page pass at page 3 — losing 11 pages to a socket hiccup.
                    # Anything that goes wrong is recorded against *this* page and the pass continues.
                    result["qunit"][key] = {"url": url, "error": f"{type(error).__name__}: {error}"}
                    result["errors"].append(f"qunit {key}: {type(error).__name__}: {error}")
                    print(f"qunit {key} FAILED: {type(error).__name__}: {error}", file=sys.stderr)
                    # A WebView that stopped answering usually means the browser fell to the
                    # background (Android throttles a backgrounded WebView's devtools socket, which
                    # `docs/TESTING.md` §12.7 records). Re-attaching brings it back to the front;
                    # without it every remaining page fails the same way.
                    try:
                        browser.close()
                        browser = cdp.Browser.attach(
                            arguments.serial, arguments.browser, port=arguments.port
                        )
                        print(f"  re-attached {arguments.browser} pid={browser.pid}", file=sys.stderr)
                    except cdp.CdpError as reattach:
                        print(f"  re-attach failed: {reattach}", file=sys.stderr)
                save()
            if arguments.install_test_lists:
                clear_test_list(arguments.serial)
    finally:
        browser.close()
        save()

    print(f"\nwrote {destination}")
    if result["errors"]:
        print(f"{len(result['errors'])} error(s):", file=sys.stderr)
        for error in result["errors"]:
            print(f"  {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
