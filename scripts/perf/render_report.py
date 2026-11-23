#!/usr/bin/env python3
"""Generate every number in `docs/reviews/i2-edits-cost.md` from the run's JSON.

# Why this replaces hand-written tables

The stage-5 review found the report contradicting itself: §6.6's table said the `host-shortcut` shape
went 1.361 → 1.768 → 4.709 across 1/8/64 copies while the prose beside it said "2.41 → 2.41, does not
grow"; it said "no-pattern regex is the only shape that grows" while the typed-regex row visibly grew
too; §6.7 mixed a `removeparam` number with an `edits` number in one sentence; and it cited a §6.5b
that did not exist. Every one of those is a transcription error, and all of them are avoidable: the
numbers already live in `report.json`, `shapes.jsonl` and `buckets/report.json`.

So this script emits the tables and the arithmetic that the prose refers to, from those files, with the
stage and the statistic named in the header. The prose is then written to quote these blocks rather than
restate them.

# Output

Markdown fragments on stdout, each introduced by an HTML comment naming its source file and the exact
selector, so a reader can go from a row to the JSON that produced it. `--check` compares the emitted
text against the same blocks embedded in the report and exits non-zero if they differ, which is what
keeps the report from drifting again.

Usage
-----
    python3 scripts/perf/render_report.py --results .effectiveness/results/i2-edits-cost
    python3 scripts/perf/render_report.py --results … --write docs/reviews/i2-edits-cost.md
    python3 scripts/perf/render_report.py --results … --check docs/reviews/i2-edits-cost.md
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

STAGES = ["parse_url", "adblock_request", "decide", "removeheader", "removeparam", "edits"]

# The order and the exact case ids, so a renamed case fails loudly instead of silently dropping a row.
EQUAL_CASES = [
    "noquery-script", "noquery-document",
    "miss-script", "miss-xhr", "miss-document",
    "hit-typed-xhr", "hit-typed-image", "miss-typed-wrong-kind",
    "hit-document-navigation", "hit-document-post", "hit-document-zhihu",
    "miss-duplicate-params", "miss-other-host", "hit-document-fragment",
]
CAPABILITY_CASES = ["cap-untyped-on-xhr", "cap-empty-value-param"]

SHAPES = [
    "empty", "exception", "gate-only", "inert-other-parameter",
    "anchored-regex", "typed-script-regex",
    "name-indexed-engine-form", "name-indexed-hit",
    "no-pattern-name", "no-pattern-regex", "no-pattern-bare",
]
SHAPE_LOADS = [1, 8, 64]


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def rows_by_key(report: dict) -> dict[tuple[str, str], dict]:
    return {(row["id"], row["stage"]): row for row in report["timing"]}


def f(value: float, places: int = 3) -> str:
    return f"{value:.{places}f}"


def ratio(value: float) -> str:
    return f"{value:.2f}×"


def header(source: str, selector: str) -> str:
    return f"<!-- generated from {source} :: {selector} -->"


# ------------------------------------------------------------------------------------------------
# Blocks
# ------------------------------------------------------------------------------------------------

def block_equal_edits(results: Path) -> str:
    """§5.1: the `edits` stage, both builds, every equal case."""
    report = load(results / "equal-engine-name" / "report.json")
    rows = rows_by_key(report)
    lines = [
        header("equal-engine-name/report.json", "timing → stage=edits, floor=min over rounds, "
                                                "median=median over rounds"),
        "| 用例 | 候选 floor µs | v0.1.2 floor µs | 倍率(floor) | 候选 中位 µs | v0.1.2 中位 µs | 候选 更慢轮次 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for case_id in EQUAL_CASES:
        row = rows[(case_id, "edits")]
        candidate = row["floor_us"]["candidate"]
        baseline = row["floor_us"]["baseline"]
        lines.append(
            f"| `{case_id}` | {f(candidate)} | {f(baseline)} | {ratio(candidate / baseline)} "
            f"| {f(row['candidate']['median_us'])} | {f(row['baseline']['median_us'])} "
            f"| {row['pairs_primary_slower']}/{row['rounds']} |"
        )
    return "\n".join(lines)


def block_stage_split(results: Path, case_id: str) -> str:
    """§6.1: per-stage cost for one case, so the reader sees which stage moved."""
    report = load(results / "equal-engine-name" / "report.json")
    rows = rows_by_key(report)
    lines = [
        header("equal-engine-name/report.json",
               f"timing → id={case_id}, every stage, floor=min over rounds"),
        "| 阶段 | 候选 floor µs | v0.1.2 floor µs | 倍率(floor) |",
        "|---|---:|---:|---:|",
    ]
    for stage in STAGES:
        row = rows[(case_id, stage)]
        candidate = row["floor_us"]["candidate"]
        baseline = row["floor_us"]["baseline"]
        lines.append(f"| `{stage}` | {f(candidate)} | {f(baseline)} | {ratio(candidate / baseline)} |")
    return "\n".join(lines)


def block_stage_verdict(results: Path) -> str:
    """§6.2: the four stages other than `removeparam`, across every equal case.

    Stated as a range so a single borderline row cannot be paraphrased into "all unchanged".
    """
    report = load(results / "equal-engine-name" / "report.json")
    rows = rows_by_key(report)
    # `edits` is the composite of all the others, so including it would report a ratio that is not a
    # stage at all. `removeparam` is the one that moved, and is stated separately.
    other_stages = [stage for stage in STAGES if stage not in ("removeparam", "edits")]
    lowest = (float("inf"), "")
    highest = (0.0, "")
    for case_id in EQUAL_CASES:
        for stage in other_stages:
            row = rows[(case_id, stage)]
            value = row["floor_us"]["candidate"] / row["floor_us"]["baseline"]
            if value < lowest[0]:
                lowest = (value, f"{case_id}/{stage}")
            if value > highest[0]:
                highest = (value, f"{case_id}/{stage}")
    return (
        f"{header('equal-engine-name/report.json', 'timing → all stages except removeparam, all equal cases')}\n"
        f"非 `removeparam` 的 {len(other_stages)} 个阶段在全部 {len(EQUAL_CASES)} 个等价用例上的倍率区间："
        f"**{ratio(lowest[0])}**（`{lowest[1]}`）… **{ratio(highest[0])}**（`{highest[1]}`）。"
    )


def block_no_removeparam(results: Path) -> str:
    """§5.2: the fixed-overhead control, as a range."""
    report = load(results / "no-removeparam" / "report.json")
    rows = rows_by_key(report)
    values = []
    for case_id in EQUAL_CASES + CAPABILITY_CASES:
        if (case_id, "edits") not in rows:
            continue
        row = rows[(case_id, "edits")]
        values.append((row["floor_us"]["candidate"] / row["floor_us"]["baseline"], case_id))
    values.sort()
    return (
        f"{header('no-removeparam/report.json', 'timing → stage=edits, all cases')}\n"
        f"两版都不收任何 `$removeparam` 规则时，`edits` 的倍率区间：**{ratio(values[0][0])}**"
        f"（`{values[0][1]}`）… **{ratio(values[-1][0])}**（`{values[-1][1]}`）。"
    )


def block_self_eval(results: Path) -> str:
    """§5.3: rules both builds evaluate themselves, in both directions."""
    report = load(results / "self-eval-common" / "report.json")
    rows = rows_by_key(report)
    lines = [
        header("self-eval-common/report.json", "timing → stage=edits, cases with a ratio ≠ 1"),
        "| 用例 | 候选 floor µs | v0.1.2 floor µs | 倍率(floor) |",
        "|---|---:|---:|---:|",
    ]
    for case_id in EQUAL_CASES:
        row = rows[(case_id, "edits")]
        candidate = row["floor_us"]["candidate"]
        baseline = row["floor_us"]["baseline"]
        value = candidate / baseline
        if abs(value - 1.0) < 0.05:
            continue
        lines.append(f"| `{case_id}` | {f(candidate)} | {f(baseline)} | {ratio(value)} |")
    return "\n".join(lines)


def block_full(results: Path, tag: str) -> str:
    """§5.4: the realistic lists, where the two builds hold different rule counts."""
    report = load(results / tag / "report.json")
    rows = rows_by_key(report)
    lines = [
        header(f"{tag}/report.json", "timing → stage=edits, floor=min over rounds"),
        "| 用例 | 候选 floor µs | v0.1.2 floor µs | 倍率(floor) |",
        "|---|---:|---:|---:|",
    ]
    for case_id in EQUAL_CASES:
        row = rows[(case_id, "edits")]
        candidate = row["floor_us"]["candidate"]
        baseline = row["floor_us"]["baseline"]
        lines.append(f"| `{case_id}` | {f(candidate)} | {f(baseline)} | {ratio(candidate / baseline)} |")
    return "\n".join(lines)


def block_rule_counts(results: Path) -> str:
    """§3.5: how many rules each build collects from each input — the coverage difference itself."""
    lines = [
        header("<input>/headers.json", "record=header → removeparam_rules / removeparam_rejected"),
        "| 输入 | 候选规则 | 候选拒收 | v0.1.2 规则 | v0.1.2 拒收 |",
        "|---|---:|---:|---:|---:|",
    ]
    for tag in ("equal-engine-name", "no-removeparam", "self-eval-common", "eval-reached",
                "full-5", "full-9"):
        path = results / tag / "headers.json"
        if not path.is_file():
            lines.append(f"| `{tag}` | 未采集 | — | 未采集 | — |")
            continue
        headers = load(path)
        cells = []
        for name in ("candidate", "baseline"):
            rows = headers.get(name) or []
            if not rows:
                cells += ["未采集", "—"]
                continue
            header_row = rows[0]
            cells += [str(header_row.get("removeparam_rules", "—")),
                      str(header_row.get("removeparam_rejected", "—"))]
        lines.append(f"| `{tag}` | {cells[0]} | {cells[1]} | {cells[2]} | {cells[3]} |")
    return "\n".join(lines)


def block_shapes(results: Path) -> str:
    """§6.6: one rule shape at a time, with the columns the prose has to quote."""
    path = results / "shapes.jsonl"
    records = [json.loads(line) for line in path.read_text().splitlines() if line.startswith("{")]
    table: dict[tuple[str, str, int], dict] = {}
    for record in records:
        table[(record["build"], record["id"], record["copies"])] = record

    lines = [
        header("shapes.jsonl", "record=shape → removeparam stage, min over rounds, µs/call"),
        "| 形状 | 1 条 | 8 条 | 64 条 | 1→64 增长 | 候选在 1 条时 | 旧版是否收下 |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    for shape in SHAPES:
        cells = []
        for copies in SHAPE_LOADS:
            record = table.get(("candidate", shape, copies))
            cells.append(f(record["min_us"]) if record else "—")
        first = table.get(("candidate", shape, 1))
        last = table.get(("candidate", shape, 64))
        growth = (f"{last['min_us'] / first['min_us']:.2f}×"
                  if first and last and first["min_us"] > 0 else "—")
        collected = table.get(("baseline", shape, 1))
        collected_text = (f"是（{collected['min_us']:.3f} µs）" if collected and collected["rules_in_set"]
                          else "否")
        lines.append(f"| `{shape}` | {cells[0]} | {cells[1]} | {cells[2]} | {growth} "
                     f"| {f(first['min_us']) if first else '—'} | {collected_text} |")
    return "\n".join(lines)


def block_shape_growth(results: Path) -> str:
    """The sentence about which shapes grow, computed rather than asserted."""
    path = results / "shapes.jsonl"
    records = [json.loads(line) for line in path.read_text().splitlines() if line.startswith("{")]
    table = {(record["build"], record["id"], record["copies"]): record for record in records}
    grown = []
    flat = []
    for shape in SHAPES:
        first = table.get(("candidate", shape, 1))
        last = table.get(("candidate", shape, 64))
        if not first or not last or first["min_us"] == 0:
            continue
        factor = last["min_us"] / first["min_us"]
        (grown if factor >= 1.5 else flat).append((shape, factor))
    grown.sort(key=lambda item: -item[1])
    flat.sort(key=lambda item: item[1])
    return (
        f"{header('shapes.jsonl', 'record=shape → candidate, 1 vs 64 copies, min over rounds')}\n"
        f"从 1 条到 64 条**明显增长**（≥1.5×）的形状："
        + "、".join(f"`{name}` {factor:.2f}×" for name, factor in grown)
        + "。**基本不增长**的形状："
        + "、".join(f"`{name}` {factor:.2f}×" for name, factor in flat)
        + "。"
    )


def block_buckets(results: Path) -> str:
    """§6.5: the bucket split, with the path each row actually took."""
    report = load(results / "buckets" / "report.json")
    lines = [
        header("buckets/report.json", "rows → removeparam stage, min over rounds"),
        "| 桶 | 行数 | 候选规则 | 候选 µs | v0.1.2 规则 | v0.1.2 µs | 倍率 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in report["rows"]:
        candidate = row["candidate"]
        baseline = row["baseline"]
        lines.append(
            f"| `{row['bucket']}` | {row['lines']} | {candidate['rules']} "
            f"| {f(candidate['removeparam_us'])} | {baseline['rules']} "
            f"| {f(baseline['removeparam_us'])} | {ratio(row['ratio'])} |"
        )
    shared = report.get("shared_by_value")
    if shared:
        lines.append(
            f"| `by-value`（两版共有） | {shared['lines']} | {shared['candidate']['rules']} "
            f"| {f(shared['candidate']['removeparam_us'])} | {shared['baseline']['rules']} "
            f"| {f(shared['baseline']['removeparam_us'])} "
            f"| {ratio(shared['candidate']['removeparam_us'] / shared['baseline']['removeparam_us'])} |"
        )
    return "\n".join(lines)


def block_paths(results: Path) -> str:
    """§6.5: which rows entered evaluation, from the harness rather than from an assumption."""
    path = results / "paths.jsonl"
    if not path.is_file():
        return (f"{header('paths.jsonl', 'record=path')}\n"
                f"（未采集：`paths.jsonl` 不存在）")
    records = [json.loads(line) for line in path.read_text().splitlines() if line.startswith("{")]
    lines = [
        header("paths.jsonl", "record=path → gate_should_block / enters_in_force per build and input"),
        "| 输入 | 用例 | 候选 gate 开 | 候选进入 in_force | v0.1.2 gate 开 | v0.1.2 进入 in_force |",
        "|---|---|---|---|---|---|",
    ]
    by_key = {(record["build"], record["rules_file"], record["case"]): record for record in records}
    inputs = sorted({(record["rules_file"], record["case"]) for record in records})
    for rules_file, case in inputs:
        candidate = by_key.get(("candidate", rules_file, case))
        baseline = by_key.get(("baseline", rules_file, case))
        mark = lambda value: ("是" if value else "**否**") if value is not None else "—"
        lines.append(
            f"| `{Path(rules_file).name}` | `{case}` "
            f"| {mark(candidate and candidate['gate_should_block'])} "
            f"| {mark(candidate and candidate['enters_in_force'])} "
            f"| {mark(baseline and baseline['gate_should_block'])} "
            f"| {mark(baseline and baseline['enters_in_force'])} |"
        )
    return "\n".join(lines)


def block_cache(results: Path) -> str:
    """First-use and warmed cost, identified by request case."""
    lines = [
        header("<input>/report.json", "cache[] → record=cache, median over rounds"),
        "| 输入 | 用例 | 构建 | 冷（首调用）µs | 热后首调用 µs | 稳态 µs | 冷/稳态 |",
        "|---|---|---|---:|---:|---:|---:|",
    ]
    for tag in ("eval-reached", "equal-engine-name"):
        report_path = results / tag / "report.json"
        if not report_path.is_file():
            continue
        report = load(report_path)
        for name, records in (report.get("cache") or {}).items():
            for record in records:
                lines.append(
                    f"| `{tag}` | `{record['id']}` | {name} | {f(record['cold_median_us'], 2)} "
                    f"| {f(record['warm_first_call_median_us'], 2)} "
                    f"| {f(record['warm_median_us'])} "
                    f"| {record['cold_over_warm']:.1f}× |"
                )
    return "\n".join(lines)


def block_alloc(results: Path) -> str:
    """§6.3: allocations per call, per stage."""
    report = load(results / "equal-engine-name" / "report.json")
    candidate = {(row["id"], row["stage"]): row for row in report["allocations"]["candidate"]}
    baseline = {(row["id"], row["stage"]): row for row in report["allocations"]["baseline"]}
    lines = [
        header("equal-engine-name/report.json", "allocations → --mode=alloc, per call"),
        "| 用例 | 阶段 | 候选 次/请求 | v0.1.2 次/请求 | 候选 B/请求 | v0.1.2 B/请求 |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for case_id in ("miss-document", "hit-document-post", "hit-typed-xhr"):
        for stage in ("decide", "removeparam", "edits"):
            key = (case_id, stage)
            if key not in candidate or key not in baseline:
                continue
            lines.append(
                f"| `{case_id}` | `{stage}` | {candidate[key]['allocations_per_call']:.0f} "
                f"| {baseline[key]['allocations_per_call']:.0f} "
                f"| {candidate[key]['bytes_per_call']:.0f} | {baseline[key]['bytes_per_call']:.0f} |"
            )
    return "\n".join(lines)


def block_reload(results: Path) -> str:
    """§8: each reload control's verdict, including the N/A."""
    report = load(results / "equal-engine-name" / "report.json")
    verdicts = report.get("reload") or []
    if isinstance(verdicts, dict):
        # Older shape: keyed by build. Normalised here so one block serves both.
        verdicts = [verdict for records in verdicts.values() for verdict in records]
    lines = [
        header("equal-engine-name/report.json", "reload[] → verdict per build and check"),
        "| 构建 | 检查 | 结论 | 说明 |",
        "|---|---|---|---|",
    ]
    for verdict in report["reload"]:
        mark = {"pass": "PASS", "fail": "FAIL", "n/a": "N/A", "reported": "REPORTED"}[verdict["verdict"]]
        reason = (verdict.get("reason") or "").replace("|", "\\|")
        lines.append(f"| {verdict['build']} | `{verdict['check']}` | {mark} | {reason} |")
    return "\n".join(lines)


def block_eval_reached(results: Path) -> str:
    """§6.5a: the corrected equal-work comparison, with the path verified for both builds."""
    report = load(results / "eval-reached" / "report.json")
    rows = rows_by_key(report)
    lines = [
        header("eval-reached/report.json", "timing → stage=edits, floor=min over rounds"),
        "| 用例 | 候选 floor µs | v0.1.2 floor µs | 倍率(floor) |",
        "|---|---:|---:|---:|",
    ]
    for case_id in EQUAL_CASES:
        row = rows[(case_id, "edits")]
        candidate = row["floor_us"]["candidate"]
        baseline = row["floor_us"]["baseline"]
        lines.append(f"| `{case_id}` | {f(candidate)} | {f(baseline)} | {ratio(candidate / baseline)} |")
    return "\n".join(lines)


BLOCKS = {
    "equal-edits": block_equal_edits,
    "stage-split-miss-document": lambda results: block_stage_split(results, "miss-document"),
    "stage-split-hit-document-navigation":
        lambda results: block_stage_split(results, "hit-document-navigation"),
    "stage-verdict": block_stage_verdict,
    "no-removeparam": block_no_removeparam,
    "self-eval": block_self_eval,
    "full-5": lambda results: block_full(results, "full-5"),
    "full-9": lambda results: block_full(results, "full-9"),
    "shapes": block_shapes,
    "shape-growth": block_shape_growth,
    "buckets": block_buckets,
    "paths": block_paths,
    "cache": block_cache,
    "alloc": block_alloc,
    "reload": block_reload,
    "eval-reached": block_eval_reached,
    "rule-counts": block_rule_counts,
}


def render(results: Path) -> str:
    parts = []
    for name, builder in BLOCKS.items():
        parts.append(f"<!-- BLOCK {name} -->\n{builder(results)}\n<!-- /BLOCK {name} -->")
    return "\n\n".join(parts) + "\n"


def splice(report_path: Path, generated: str) -> str:
    """Replace every `<!-- BLOCK name -->…<!-- /BLOCK name -->` region with the generated text."""
    text = report_path.read_text()
    for name, builder in BLOCKS.items():
        start_marker = f"<!-- BLOCK {name} -->"
        end_marker = f"<!-- /BLOCK {name} -->"
        start = text.find(start_marker)
        end = text.find(end_marker)
        if start < 0 or end < 0:
            continue
        new_block = generated[generated.find(start_marker):generated.find(end_marker) + len(end_marker)]
        text = text[:start] + new_block + text[end + len(end_marker):]
    return text


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", required=True, type=Path)
    parser.add_argument("--write", type=Path, help="splice the blocks into this markdown file")
    parser.add_argument("--check", type=Path, help="exit non-zero if this file's blocks are stale")
    arguments = parser.parse_args()

    generated = render(arguments.results)
    if arguments.write:
        arguments.write.write_text(splice(arguments.write, generated))
        print(f"wrote {arguments.write}", file=sys.stderr)
        return 0
    if arguments.check:
        expected = splice(arguments.check, generated)
        if expected != arguments.check.read_text():
            print(f"STALE: {arguments.check} does not match the run's JSON. "
                  f"Re-run with --write.", file=sys.stderr)
            return 1
        print(f"{arguments.check}: all blocks match the run's JSON", file=sys.stderr)
        return 0
    sys.stdout.write(generated)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
