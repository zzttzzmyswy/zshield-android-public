#!/usr/bin/env python3
"""Measure 20 sites under one measurement condition, through the on-device browser.

Usage:
    scripts/effectiveness/sites.py --condition <name> [--out <dir>] [--only cn|intl|<slug>]

Per site, per condition, this records:

- **requests**: how many network requests the page issued (CDP `Network.requestWillBeSent`), and how
  many the app blocked, from the tunnel's own request log (`Native.recentRequestsJson`, surfaced on
  the debug screen). The two are reported separately because they answer different questions: CDP
  counts what the *renderer* asked for, the app's log says which of those its rules denied.
- **a screenshot of the first screen**, after the page settles.
- **a breakage verdict**, machine-checkable rather than prose: blank viewport (almost no text and no
  images), horizontal overflow (content wider than the viewport), the app's own blocked-page marker,
  and an error page (`net::ERR_…`). Anything a human would call "broken layout" that these cannot see
  is left to the reviewer looking at the screenshot, and is recorded as `needsReview`.
- the page title/URL actually reached, so a redirect to a consent wall or an error is visible.

The request counts come from CDP events, which is the only place they exist: the tunnel sees
connections, not the renderer's requests, and a page blocked by DNS never produces either.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import cdp  # noqa: E402
import device_serial  # noqa: E402

DEFAULT_BROWSER = os.environ.get("BROWSER", "org.lineageos.jelly")

#: The 20 sites the task card names, split as it splits them. `cn` sites are measured on the same
#: device with the same DNS upstream as the rest, so no special casing is needed — but they are kept
#: in their own group because a China-region site failing to load is a *network* fact, not a filter
#: fact, and conflating the two would misreport the filter.
SITES = [
    # 国内 10 个
    ("cn", "baidu", "https://www.baidu.com/"),
    ("cn", "bilibili", "https://m.bilibili.com/"),
    ("cn", "zhihu", "https://www.zhihu.com/"),
    ("cn", "weibo", "https://m.weibo.cn/"),
    ("cn", "taobao", "https://www.taobao.com/"),
    ("cn", "jd", "https://m.jd.com/"),
    ("cn", "sina-news", "https://news.sina.com.cn/"),
    ("cn", "qq-news", "https://news.qq.com/"),
    ("cn", "csdn", "https://www.csdn.net/"),
    ("cn", "douban", "https://m.douban.com/"),
    # 国外 10 个
    ("intl", "youtube", "https://m.youtube.com/"),
    ("intl", "github", "https://github.com/"),
    ("intl", "wikipedia", "https://en.m.wikipedia.org/wiki/Main_Page"),
    ("intl", "reddit", "https://www.reddit.com/"),
    ("intl", "stackoverflow", "https://stackoverflow.com/"),
    ("intl", "bbc", "https://www.bbc.com/"),
    ("intl", "cnn", "https://edition.cnn.com/"),
    ("intl", "yahoo", "https://www.yahoo.com/"),
    ("intl", "twitch", "https://m.twitch.tv/"),
    ("intl", "medium", "https://medium.com/"),
]

#: How long a page gets to settle after `load` before it is measured. Long enough for the scripts
#: that inject ads to run (they are what the filter is measured on), short enough to finish 20 sites
#: three times in one session.
SETTLE_SECONDS = 6.0

#: How long to wait for `load` before measuring anyway. A site that never finishes loading (an
#: infinite analytics beacon chain) still has a first screen worth reporting.
LOAD_TIMEOUT_SECONDS = 30.0

#: Markers the app's own blocked-page response carries (`core/src/http/response.rs`).
BLOCKED_MARKERS = ("被 ZShield 拦截", "Blocked by ZShield", "ZShield")

#: Browser error pages.
ERROR_MARKERS = (
    "net::ERR_",
    "网页无法打开",
    "This site can’t be reached",
    "This site can't be reached",
)


def read_request_log(serial: str, package: str) -> list[dict]:
    """The app's recent-request ring buffer, as the debug screen would show it.

    There is no shell-accessible JSON endpoint: the log lives in the running process and is exposed
    only through the JNI call the UI makes. The debug screen renders its size, not its contents, so
    the *count* is what can be read without a UI tap — and it is read from `uiautomator`, which is
    reliable for the native debug page (it was only WebView content that was unreadable).
    """
    cdp.shell(serial, f"am start -n {package}/.debug.DebugActivity", check=False)
    time.sleep(1.5)
    xml = cdp.shell(serial, "uiautomator dump /sdcard/zs-sites.xml >/dev/null 2>&1; "
                           "cat /sdcard/zs-sites.xml", check=False)
    counts = {}
    http = re.search(r"HTTP 请求 (\d+) ｜ 拦截 (\d+) ｜ 重定向 (\d+) ｜ 直通退化 (\d+) ｜ 引擎 (\S+) ｜ 日志 (\d+) 条", xml)
    if http:
        counts["httpRequests"] = int(http.group(1))
        counts["httpBlocked"] = int(http.group(2))
        counts["httpRedirected"] = int(http.group(3))
        counts["requestLogSize"] = int(http.group(6))
    dns = re.search(r"查询 (\d+) ｜ 拦截 (\d+) ｜ 错误 (\d+)", xml)
    if dns:
        counts["dnsQueries"] = int(dns.group(1))
        counts["dnsBlocked"] = int(dns.group(2))
        counts["dnsErrors"] = int(dns.group(3))
    tunnel = re.search(r"拦截连接 (\d+) ｜ QUIC 丢弃 (\d+)", xml)
    if tunnel:
        counts["blockedConnections"] = int(tunnel.group(1))
        counts["quicDropped"] = int(tunnel.group(2))
    https = re.search(r"解密 (\d+) ｜ 直通 (\d+) ｜ 自动放行 (\d+)", xml)
    if https:
        counts["httpsIntercepted"] = int(https.group(1))
        counts["httpsPassthrough"] = int(https.group(2))
    return counts


def measure_page(page: cdp.Page, settle: float) -> dict:
    """Collect the request count, the breakage signals and the visible text of one page."""
    # The events were buffered by `send` while it waited for our replies; drain them now.
    requests = page.events.pop("Network.requestWillBeSent", [])
    responses = page.events.pop("Network.responseReceived", [])
    failures = page.events.pop("Network.loadingFailed", [])

    urls = [event.get("request", {}).get("url", "") for event in requests]
    types: dict[str, int] = {}
    for event in requests:
        kind = event.get("type", "Other")
        types[kind] = types.get(kind, 0) + 1

    # A request the renderer made and the engine killed shows up here as `loadingFailed` with
    # `blockedReason`, and *also* as a 204/403 response when the app answered it itself. Both are
    # counted, and they are reported apart so the total is not double counted.
    blocked_by_cdp = [
        event for event in failures if event.get("blockedReason") or "ERR_BLOCKED" in str(event.get("errorText"))
    ]

    snapshot = page.evaluate(
        r"""
(() => {
  const doc = document.documentElement;
  const body = document.body || doc;
  const text = (body ? body.innerText : '').replace(/\s+/g, ' ').trim();
  const images = [...document.images].filter(img => img.naturalWidth > 1 && img.naturalHeight > 1);
  const videos = [...document.querySelectorAll('video')];
  return {
    title: document.title,
    url: location.href,
    readyState: document.readyState,
    textLength: text.length,
    textSample: text.slice(0, 400),
    images: images.length,
    videos: videos.length,
    viewportWidth: window.innerWidth,
    scrollWidth: Math.max(doc.scrollWidth, body.scrollWidth || 0),
    scrollHeight: Math.max(doc.scrollHeight, body.scrollHeight || 0),
  };
})()
"""
    )

    signals = []
    text = snapshot.get("textSample", "")
    if any(marker in text for marker in ERROR_MARKERS):
        signals.append("browser-error-page")
    if snapshot["textLength"] < 120 and snapshot["images"] == 0:
        signals.append("blank")
    # Overflow is judged at 5% so a scrollbar or one off-width ad slot does not cry wolf; a real
    # layout break from a hidden container is normally far wider than that.
    if snapshot["viewportWidth"] and snapshot["scrollWidth"] > snapshot["viewportWidth"] * 1.05:
        signals.append("horizontal-overflow")
    if any(marker in text for marker in BLOCKED_MARKERS):
        signals.append("app-blocked-page")

    return {
        "title": snapshot["title"],
        "finalUrl": snapshot["url"],
        "readyState": snapshot["readyState"],
        "requests": len(urls),
        "requestsByType": types,
        "responses": len(responses),
        "failures": len(failures),
        "blockedByBrowser": len(blocked_by_cdp),
        "blockedUrls": [
            event.get("request", {}).get("url", "")[:160] for event in blocked_by_cdp
        ][:10],
        "textLength": snapshot["textLength"],
        "images": snapshot["images"],
        "videos": snapshot["videos"],
        "viewportWidth": snapshot["viewportWidth"],
        "scrollWidth": snapshot["scrollWidth"],
        "scrollHeight": snapshot["scrollHeight"],
        "signals": signals,
        # A page that rendered, has content and did not overflow still needs eyes for "the video
        # does not play" and "the layout is subtly wrong"; the screenshot is the evidence for that.
        "needsReview": not signals,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--condition", required=True)
    parser.add_argument("--out", default=".effectiveness/results")
    parser.add_argument("--serial", default=None,
                        help="adb serial; defaults to $SERIAL, else the only attached device")
    parser.add_argument("--browser", default=DEFAULT_BROWSER)
    parser.add_argument("--package", default="top.zztweb.zshield")
    parser.add_argument("--port", type=int, default=9222)
    parser.add_argument("--settle", type=float, default=SETTLE_SECONDS)
    parser.add_argument("--load-timeout", type=float, default=LOAD_TIMEOUT_SECONDS)
    parser.add_argument(
        "--only",
        default=None,
        help="comma-separated slugs, or a group name (cn, intl), to measure a subset",
    )
    parser.add_argument("--shots", default=None)
    arguments = parser.parse_args()
    arguments.serial = device_serial.serial_from(arguments)

    selected = SITES
    if arguments.only:
        wanted = {part.strip() for part in arguments.only.split(",")}
        selected = [
            site for site in SITES if site[1] in wanted or site[0] in wanted
        ]
        if not selected:
            raise SystemExit(f"--only {arguments.only} matched none of {[s[1] for s in SITES]}")

    out = Path(arguments.out)
    out.mkdir(parents=True, exist_ok=True)
    shots = Path(arguments.shots) if arguments.shots else out / "shots"
    shots.mkdir(parents=True, exist_ok=True)

    result: dict = {
        "condition": arguments.condition,
        "device": arguments.serial,
        "browser": arguments.browser,
        "settleSeconds": arguments.settle,
        "measuredAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tunnelBefore": "up" if "IS_VPN" in cdp.shell(arguments.serial, "dumpsys connectivity") else "down",
        "sites": {},
        "errors": [],
    }
    print(f"condition {arguments.condition}: tunnel {result['tunnelBefore']}")

    browser = cdp.Browser.attach(arguments.serial, arguments.browser, port=arguments.port)
    print(f"attached {arguments.browser} pid={browser.pid}")

    # One counter reading before the first site, so the delta for each site is the site's own
    # traffic rather than everything the device did since the tunnel started.
    previous = read_request_log(arguments.serial, arguments.package)

    try:
        for group, slug, url in selected:
            started = time.time()
            entry: dict = {"group": group, "slug": slug, "url": url}
            try:
                page = browser.open(url, timeout=arguments.load_timeout, settle=arguments.settle)
                reading = measure_page(page, arguments.settle)
                # The site's own redirect is part of the measurement, not a failure of it: a
                # mobile-first site answering a phone user agent with its `m.` host is working.
                entry["redirectedTo"] = page.final_url
                shot = shots / f"site-{slug}-{arguments.condition}.png"
                page.shot(str(shot))
                reading["screenshot"] = str(shot)
                page.close()
                entry.update(reading)
            except cdp.CdpError as error:
                entry["error"] = str(error)
                result["errors"].append(f"{slug}: {error}")
            except Exception as error:  # noqa: BLE001 - one site must not abort the run
                entry["error"] = f"{type(error).__name__}: {error}"
                result["errors"].append(f"{slug}: {error}")

            current = read_request_log(arguments.serial, arguments.package)
            entry["appCounters"] = {
                key: current.get(key, 0) - previous.get(key, 0) for key in current
            }
            previous = current
            entry["elapsedSeconds"] = round(time.time() - started, 1)

            result["sites"][slug] = entry
            status = entry.get("error") or ",".join(entry.get("signals", [])) or "ok"
            print(
                f"  {group:<5} {slug:<14} req={entry.get('requests', '-'):>4} "
                f"blocked={entry.get('blockedByBrowser', '-'):>3} "
                f"dns+={entry['appCounters'].get('dnsBlocked', 0):>3} "
                f"{status}  ({entry['elapsedSeconds']}s)"
            )
    finally:
        browser.close()

    destination = out / f"sites-{arguments.condition}.json"
    destination.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {destination}")
    if result["errors"]:
        print(f"{len(result['errors'])} site(s) errored", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
