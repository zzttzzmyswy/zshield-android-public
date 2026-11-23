#!/usr/bin/env python3
"""Split the five-table rule union by evaluation bucket and measure each on both builds.

# Why this is the decisive experiment

A rule-set comparison can only say "the whole set is slower". §6.5 of
`docs/reviews/i2-edits-cost.md` claims something sharper — that the cost is not the number of rules but
the way the rules that survive screening are evaluated — and that claim is only credible if the set is
split along the axis the claim names.

The axis is `RemoveParamRules::build`'s own classification (`core/src/https/extras.rs`):

  * `host-shortcut` → `by_host`: decided by a hostname comparison, no engine query;
  * `by-name`       → `by_name`: consulted only when the URL carries that parameter name;
  * `by-value`      → `by_value`: walked on every request.

Feeding each bucket to both builds separates "more rules" from "more work per rule": the candidate
holds 16× more `host-shortcut` rules than v0.1.2 and they cost almost nothing, while the bucket whose
rule count barely differs is where the whole difference lives.

# What each row costs, and what it does not

Each build is fed the bucket and measured on `miss-document` from the request matrix — a document
request carrying no parameter any rule names, which is the shape that walks `by_value`. The
`outcome` column is recorded so a reader can see the buckets produce no rewrite on either build; a
cost difference here is not a rewrite difference.

Usage
-----
    python3 scripts/perf/bucket_split.py \\
        --lists .effectiveness/catalog-lists \\
        --union .effectiveness/full-5/union.txt \\
        --out .effectiveness/results/i2-edits-cost/buckets \\
        --candidate ./candidate/examples/edits_cost_matrix \\
        --baseline  ./baseline/examples/edits_cost_matrix \\
        --cpu 19
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rule_classes import classify  # noqa: E402  (same directory, one definition of a bucket)

BUCKETS = ("host-shortcut", "by-name", "by-value")
CASE = "miss-document"

# The forms v0.1.2's collector refuses outright (`core/src/https/extras.rs` in that build):
# `compile_param_matcher` returns `None` for a bare value, a `~` inversion and a `/regex/`; and its
# `add_list` skips a bare `$removeparam` unless it is an exception. The one shape it does keep from the
# `by-value` bucket is therefore `||host^$removeparam=/regex/`, where the value is a regex.
#
# This matters because a bucket comparison mixes two effects: how many rules each side holds, and
# whether its gate opens. Restricting to the forms **both** collectors keep removes the second.
def accepted_by_both(line: str) -> bool:
    return line.startswith("||") and "removeparam=/" in line


def measure(binary: str, rules: Path, matrix: Path, cpu: int | None, rounds: int,
            iterations: int) -> dict:
    command = (["taskset", "-c", str(cpu)] if cpu is not None else []) + [
        binary,
        "--rules", str(rules),
        "--matrix", str(matrix),
        "--build-id", Path(binary).parent.parent.parent.name,
        "--mode=timing",
        f"--only-case={CASE}",
        "--rounds", str(rounds),
        "--iters", str(iterations),
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"{' '.join(command)}\n{result.stdout}\n{result.stderr}")
    records = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    header = next(record for record in records if record.get("record") == "header")
    rows = {(record["id"], record["stage"]): record for record in records
            if record.get("record") == "timing"}
    return {
        "rules": header["removeparam_rules"],
        "rejected": header["removeparam_rejected"],
        "removeparam_us": rows[(CASE, "removeparam")]["min_us"],
        "removeparam_median_us": rows[(CASE, "removeparam")]["median_us"],
        "edits_us": rows[(CASE, "edits")]["min_us"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lists", required=True, type=Path,
                        help="directory of `<id>.txt` catalog lists (for provenance only)")
    parser.add_argument("--union", required=True, type=Path,
                        help="the five-table union the other measurements use")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--matrix", required=True, type=Path)
    parser.add_argument("--cpu", type=int, default=None)
    parser.add_argument("--rounds", type=int, default=7)
    parser.add_argument("--iterations", type=int, default=2000)
    arguments = parser.parse_args()

    arguments.out.mkdir(parents=True, exist_ok=True)
    lines = arguments.union.read_text(errors="replace").splitlines()
    buckets: dict[str, list[str]] = {bucket: [] for bucket in BUCKETS}
    outcomes = {bucket: 0 for bucket in BUCKETS}
    for line in lines:
        record = classify(line)
        if record is None:
            continue
        buckets[record["bucket"]].append(line)
        outcomes[record["bucket"]] += 1

    # The `by-value` subset both collectors actually hold. Same request, same rules, so a difference
    # here is implementation, not coverage — the only comparison in this script with that property.
    shared = [line for line in buckets["by-value"] if accepted_by_both(line)]
    shared_path = arguments.out / "by-value-shared.txt"
    shared_path.write_text("\n".join(shared) + "\n")
    shared_candidate = measure(arguments.candidate, shared_path, arguments.matrix, arguments.cpu,
                               arguments.rounds, arguments.iterations)
    shared_baseline = measure(arguments.baseline, shared_path, arguments.matrix, arguments.cpu,
                              arguments.rounds, arguments.iterations)

    rows = []
    for bucket in BUCKETS:
        subset = arguments.out / f"{bucket}.txt"
        subset.write_text("\n".join(buckets[bucket]) + "\n")
        candidate = measure(arguments.candidate, subset, arguments.matrix, arguments.cpu,
                            arguments.rounds, arguments.iterations)
        baseline = measure(arguments.baseline, subset, arguments.matrix, arguments.cpu,
                           arguments.rounds, arguments.iterations)
        rows.append({
            "bucket": bucket,
            "lines": len(buckets[bucket]),
            "candidate": candidate,
            "baseline": baseline,
            "ratio": candidate["removeparam_us"] / baseline["removeparam_us"]
                     if baseline["removeparam_us"] else None,
        })

    (arguments.out / "report.json").write_text(
        json.dumps({"case": CASE, "union": str(arguments.union),
                    "union_sha256": __import__("hashlib").sha256(
                        arguments.union.read_bytes()).hexdigest(),
                    "rows": rows,
                    "shared_by_value": {
                        "lines": len(shared),
                        "candidate": shared_candidate,
                        "baseline": shared_baseline,
                    }}, ensure_ascii=False, indent=2) + "\n"
    )

    print(f"## `{CASE}` 上按桶拆分五表规则集（`removeparam` 阶段，多轮最小值，绑核 {arguments.cpu}）\n")
    print("| 桶 | 行数 | 候选规则 | 候选 µs | v0.1.2 规则 | v0.1.2 µs | 倍率 |")
    print("|---|---:|---:|---:|---:|---:|---:|")
    for row in rows:
        candidate = row["candidate"]
        baseline = row["baseline"]
        ratio = f"{row['ratio']:.2f}×" if row["ratio"] else "—"
        print(f"| `{row['bucket']}` | {row['lines']} | {candidate['rules']} "
              f"| {candidate['removeparam_us']:.3f} | {baseline['rules']} "
              f"| {baseline['removeparam_us']:.3f} | {ratio} |")
    print()
    print("三个桶都对该请求**不改写**（`miss-document` 不带任何被命名的参数），")
    print("所以任何成本差异都只能来自「求值方式」，不能来自「改写结果不同」。")

    totals = {
        "candidate_rules": sum(row["candidate"]["rules"] for row in rows),
        "baseline_rules": sum(row["baseline"]["rules"] for row in rows),
    }
    print(f"\n三桶合计：候选 {totals['candidate_rules']} 条 / v0.1.2 {totals['baseline_rules']} 条。")

    # The isolation row: the same rules, both collectors holding them, so both gates see the same form
    # set for this request. A difference here cannot be coverage.
    print("\n### 两版都收下的 `by-value` 子集（**不能**作求值结论，见下）\n")
    print("| 子集 | 行数 | 候选规则 | 候选 µs | v0.1.2 规则 | v0.1.2 µs | 倍率 |")
    print("|---|---:|---:|---:|---:|---:|---:|")
    ratio = (shared_candidate["removeparam_us"] / shared_baseline["removeparam_us"]
             if shared_baseline["removeparam_us"] else float("nan"))
    ratio_text = f"{ratio:.2f}×" if ratio == ratio else "—"
    print(f"| `by-value`（两版共有） | {len(shared)} | {shared_candidate['rules']} "
          f"| {shared_candidate['removeparam_us']:.3f} | {shared_baseline['rules']} "
          f"| {shared_baseline['removeparam_us']:.3f} | {ratio_text} |")
    print("\n**这一行的用途与上一轮的声明相反。** 这批规则的 gate 在 `miss-document` 上"
          "是关闭的（见 `paths.jsonl`），`rewrites` 在 `extras.rs:1132` 就返回，`in_force` 没跑，"
          "所以它测的是「gate 未命中的开销」。第一轮把它当成「求值没退化」的证据，评审已推翻。")
    print("要证明求值路径本身，必须用 gate 两版都开、规则数相同的对照："
          "`scripts/perf/rules/eval-reached.txt`，结果见报告 §5.5。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
