#!/usr/bin/env python3
"""Turn the measurement JSON into the tables `docs/EFFECTIVENESS.md` quotes.

Usage:
    scripts/effectiveness/report.py [--out <dir>] [--format md|json]

Reads `<out>/testpages-<condition>.json`, `<out>/sites-<condition>.json` and
`<out>/coverage-report.json`, and prints Markdown. It is deliberately separate from the measuring
scripts: the numbers are written once, by the run, and rendered as many times as the report needs —
so a table in the document can always be regenerated instead of retyped.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

CONDITIONS = [
    ("vpn-off", "VPN 关闭（基线）"),
    ("zshield-default", "ZShield 默认（HTTPS 过滤关）"),
    ("zshield-https", "ZShield + HTTPS 过滤"),
]

#: Short Chinese labels for the coverage buckets.
BUCKETS = [
    ("dns", "DNS 层"),
    ("network", "网络引擎"),
    ("elemhide", "元素隐藏"),
    ("scriptlet", "scriptlet"),
    ("procedural", "过程式/动作"),
    ("adguardModifier", "AdGuard 专有"),
    ("parseFailure", "解析失败"),
]


def load(out: Path, name: str) -> dict | None:
    path = out / name
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def coverage_section() -> list[str]:
    report = load(Path(".effectiveness"), "coverage-report.json")
    if report is None:
        return ["（未找到 .effectiveness/coverage-report.json）"]
    lines = [
        "| 类别 | 条数 | 占比 |",
        "|---|---:|---:|",
    ]
    total = sum(report["totals"].values())
    for key, label in BUCKETS:
        count = report["totals"].get(key, 0)
        lines.append(f"| {label} (`{key}`) | {count:,} | {count * 100 / total:.2f}% |")
    lines.append(f"| **合计** | **{total:,}** | 100% |")
    return lines


def adblock_tester_section(out: Path) -> list[str]:
    rows = ["| 条件 | 总分 | 未通过项 |", "|---|---:|---|"]
    for condition, label in CONDITIONS:
        # Prefer pass `B` (companion lists installed) when both exist: that is the run whose rule set
        # matches what a user of that condition would have.
        reading: dict = {}
        for name in (f"testpages-{condition}-B.json", f"testpages-{condition}-A.json",
                     f"testpages-{condition}.json"):
            data = load(out, name)
            if data and (data.get("adblockTester") or {}).get("score") is not None:
                reading = data["adblockTester"]
                break
        if not reading:
            data = load(out, f"testpages-{condition}.json")
            if data is None:
                rows.append(f"| {label} | 未测 | — |")
                continue
            rows.append(
                f"| {label} | 未取到 | "
                f"{(data.get('adblockTester') or {}).get('error', '页面未给出分数')[:60]} |"
            )
            continue
        failed = [
            service["name"]
            for service in reading.get("services", [])
            if any("failed" in line for line in service.get("lines", []))
        ]
        rows.append(f"| {label} | **{reading['score']}/100** | {', '.join(failed) or '无'} |")
    return rows


def qunit_section(out: Path) -> list[str]:
    """One table row per QUnit page, one column per (condition, pass).

    Two passes per HTTPS-capable condition: `A` with the shipped rule set only, `B` with the page's
    companion test list installed. `A` answers "does this build act on the syntax"; `B` answers "does
    the rule set plus the page's own list produce the right DOM". Collapsing them into one column would
    hide which of the two failed.
    """
    variants: list[tuple[str, str]] = []
    for condition, label in CONDITIONS:
        variants.append((f"testpages-{condition}-A.json", f"{label} A"))
        variants.append((f"testpages-{condition}-B.json", f"{label} B"))

    keys: list[str] = []
    for name, _ in variants:
        data = load(out, name)
        if not data:
            continue
        for key in (data.get("qunit") or {}):
            if key not in keys:
                keys.append(key)
    if not keys:
        return ["（未测）"]

    header = "| QUnit 页面 | " + " | ".join(label for _, label in variants) + " |"
    separator = "|---|" + "---|" * len(variants)
    lines = [header, separator]
    for key in keys:
        cells = []
        for name, _ in variants:
            reading = ((load(out, name) or {}).get("qunit") or {}).get(key) or {}
            if reading.get("error"):
                cells.append("未测")
                continue
            counts = reading.get("counts") or {}
            passed = counts.get("testsPassed")
            total = counts.get("tests")
            if passed is None or total is None:
                cells.append("未取到")
                continue
            mark = "✅" if passed == total else "❌"
            cells.append(f"{mark} {passed}/{total}")
        lines.append(f"| `{key}` | " + " | ".join(cells) + " |")
    return lines


def sites_section(out: Path) -> list[str]:
    lines: list[str] = []
    for condition, label in CONDITIONS:
        data = load(out, f"sites-{condition}.json")
        if data is None:
            lines.append(f"### {label}\n\n（未测）\n")
            continue
        lines.append(f"### {label}\n")
        lines.append("| 站点 | 请求 | 被拦(浏览器) | DNS 拦截 | 破版信号 | 备注 |")
        lines.append("|---|---:|---:|---:|---|---|")
        for slug, entry in data["sites"].items():
            if entry.get("error"):
                lines.append(f"| {slug} | — | — | — | 未测 | {entry['error'][:50]} |")
                continue
            signals = ", ".join(entry.get("signals") or []) or "无"
            counters = entry.get("appCounters") or {}
            note = ""
            if entry.get("finalUrl") and slug not in entry["finalUrl"]:
                note = entry["finalUrl"][:40]
            lines.append(
                f"| {slug} | {entry.get('requests', '—')} | {entry.get('blockedByBrowser', '—')} "
                f"| {counters.get('dnsBlocked', 0)} | {signals} | {note} |"
            )
        lines.append("")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=".effectiveness/results")
    parser.add_argument("--format", choices=["md", "json"], default="md")
    arguments = parser.parse_args()
    out = Path(arguments.out)

    if arguments.format == "json":
        payload = {
            condition: {
                "testpages": load(out, f"testpages-{condition}.json"),
                "sites": load(out, f"sites-{condition}.json"),
            }
            for condition, _ in CONDITIONS
        }
        payload["coverage"] = load(Path(".effectiveness"), "coverage-report.json")
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
        print()
        return 0

    print("## 规则覆盖\n")
    print("\n".join(coverage_section()))
    print("\n## adblock-tester.com\n")
    print("\n".join(adblock_tester_section(out)))
    print("\n## testcases.agrd.dev\n")
    print("\n".join(qunit_section(out)))
    print("\n## 20 个站点\n")
    print("\n".join(sites_section(out)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
