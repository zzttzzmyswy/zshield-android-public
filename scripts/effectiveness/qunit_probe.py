#!/usr/bin/env python3
"""Drive one QUnit page and report per-assertion evidence from the live DOM.

This is a *diagnostic* companion to `testpages.py`, not a measurement: it opens a page (optionally
running a JavaScript probe before the page's own assertions run), waits for QUnit, and then prints
every assertion with its actual value, plus whatever the probe wrote into `window.__probe`.

Usage:
    scripts/effectiveness/qunit_probe.py <page-path> [--base URL] [--script FILE]

Why it exists: a QUnit failure line says `Expected: true Result: false` and nothing about *why*.
The evidence that names a root cause is the request the page actually issued and the value the
assertion actually compared, which is what this collects.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cdp  # noqa: E402
import device_serial  # noqa: E402

DEFAULT_BROWSER = "org.lineageos.jelly"

READ_ASSERTIONS = r"""
(() => {
  const results = [];
  document.querySelectorAll('#qunit-tests > li').forEach((li) => {
    const name = (li.querySelector('.test-name') || {}).textContent || '';
    const items = [];
    li.querySelectorAll('ol > li').forEach((a) => {
      items.push(a.textContent.trim().slice(0, 400));
    });
    results.push({
      name: name.trim(),
      status: li.className,
      assertions: items,
    });
  });
  return { summary: (document.querySelector('#qunit-testresult') || {}).textContent || '',
           results, probe: window.__probe || null };
})()
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="page path below the site root")
    parser.add_argument("--base", default="https://testcases.agrd.dev")
    parser.add_argument("--serial", default=None,
                        help="adb serial; defaults to $SERIAL, else the only attached device")
    parser.add_argument("--browser", default=DEFAULT_BROWSER)
    parser.add_argument("--port", type=int, default=9222)
    parser.add_argument("--script", default=None, help="JS file to evaluate before the page asserts")
    parser.add_argument("--script-after", default=None, help="JS file to evaluate after QUnit ends")
    parser.add_argument("--settle", type=float, default=1.5)
    arguments = parser.parse_args()
    arguments.serial = device_serial.serial_from(arguments)

    browser = cdp.Browser.attach(arguments.serial, arguments.browser, port=arguments.port)
    print(f"attached pid={browser.pid}", flush=True)
    try:
        url = f"{arguments.base}/{arguments.path}"
        page = browser.open(url, settle=arguments.settle)
        print(f"opened {page.final_url or url}", flush=True)
        if arguments.script:
            source = Path(arguments.script).read_text(encoding="utf-8")
            page.send("Page.addScriptToEvaluateOnNewDocument", source=source)
            print("script installed; reloading", flush=True)
            loader = page.send("Page.navigate", url=url).get("loaderId")
            page.wait_for_load(url, loader_id=loader, settle=arguments.settle)
        # Wait for QUnit to *settle*, not merely to print something. A running page reports
        # `8 / 14 tests completed.Running: Testcase 9` and the toolbar always carries the word
        # `Abort`, so a check for `completed` returns while eleven cases are still ahead — which reads
        # as "aborted with 5 failures" and is really "read too early". The stable signal is the
        # completed count not advancing for a few seconds.
        deadline = time.time() + 180
        last_count = -1
        stable_since = time.time()
        while time.time() < deadline:
            text = page.evaluate(
                "(() => { const r = document.querySelector('#qunit-testresult');"
                " return r ? r.textContent : null; })()"
            )
            count = 0
            if text:
                match = re.search(r"(?:(\d+) / (\d+)|(\d+) tests)", text)
                if match:
                    count = int(match.group(1) or match.group(3))
            if count != last_count:
                last_count = count
                stable_since = time.time()
            elif time.time() - stable_since > 6:
                break
            time.sleep(0.5)
        time.sleep(1.5)
        if arguments.script_after:
            source = Path(arguments.script_after).read_text(encoding="utf-8")
            print(
                "after-probe:",
                json.dumps(
                    page.evaluate(source, await_promise=True), ensure_ascii=False, indent=2
                ),
                flush=True,
            )
        reading = page.evaluate(READ_ASSERTIONS)
        print(json.dumps(reading, ensure_ascii=False, indent=2))
        page.close()
    finally:
        browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
