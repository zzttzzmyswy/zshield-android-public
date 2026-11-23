#!/usr/bin/env python3
"""Render the per-shape table from `removeparam_rule_shapes` output.

Reads the `jsonl` the runner appends (both builds, three loads) and prints one table per load, with the
two columns that make the numbers interpretable:

  * `vs empty` — the shape's cost minus the same build's `empty` row, i.e. what *having a rule of this
    shape* costs rather than what calling the entry point costs;
  * `ratio` — candidate over baseline on that already-subtracted figure, so a build whose fixed floor
    differs is not credited with (or blamed for) the difference.
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

# The order the evaluator takes them in, so a reader can follow the table top to bottom: no rule, a rule
# that is screened out, then each way a rule can be reached.
ORDER = [
    "empty",
    "exception",
    "gate-only",
    "inert-other-parameter",
    "anchored-regex",
    "typed-script-regex",
    "name-indexed-engine-form",
    "name-indexed-hit",
    "no-pattern-name",
    "no-pattern-regex",
    "no-pattern-bare",
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    arguments = parser.parse_args()

    by_load: dict[int, dict[tuple[str, str], dict]] = collections.defaultdict(dict)
    for line in arguments.input.read_text().splitlines():
        if not line.startswith("{"):
            continue
        record = json.loads(line)
        if record.get("record") != "shape":
            continue
        by_load[record["copies"]][(record["build"], record["id"])] = record

    builds = {build for table in by_load.values() for build, _ in table}
    # Named, not ordered: sorting alphabetically put `baseline` first and silently swapped every column
    # in the table, which is exactly the kind of error a table of differences cannot afford.
    if builds != {"candidate", "baseline"}:
        raise SystemExit(f"expected builds `candidate` and `baseline` in {arguments.input}, "
                         f"found {sorted(builds)}")
    candidate, baseline = "candidate", "baseline"

    for load in sorted(by_load):
        table = by_load[load]
        floors = {
            name: table[(name, "empty")]["min_us"] if (name, "empty") in table else 0.0
            for name in builds
        }
        print(f"### 规则形状单价（集合内 {load} 条同形规则）\n")
        print(f"| 形状 | 命中 | {candidate} µs | {baseline} µs | {candidate} 净成本 µs "
              f"| {baseline} 净成本 µs | 倍率 | 备注 |")
        print("|---|---|---:|---:|---:|---:|---:|---|")
        for shape in ORDER:
            if (candidate, shape) not in table:
                continue
            left = table[(candidate, shape)]
            right = table[(baseline, shape)]
            net_candidate = left["min_us"] - floors[candidate]
            net_baseline = right["min_us"] - floors[baseline]
            ratio = (net_candidate / net_baseline) if net_baseline > 0.01 else float("nan")
            outcome = "改写" if left.get("outcome") else "不改写"
            ratio_text = f"{ratio:.2f}×" if ratio == ratio else "—"
            # A row the old build does not even collect (`rules_in_set` 0) is not a cost difference:
            # its 0.007 µs is "the rule does not exist there", and rendering that as a small ratio
            # would read as "the candidate is slower". Mark it instead.
            left_rules = left.get("rules_in_set", 0)
            right_rules = right.get("rules_in_set", 0)
            note = ""
            if right_rules == 0 and left_rules > 0:
                note = "旧版不收这条规则"
                ratio_text = "—"
            elif left_rules == 0 and right_rules > 0:
                note = "候选不收这条规则"
                ratio_text = "—"
            print(f"| `{shape}` | {outcome} | {left['min_us']:.3f} | {right['min_us']:.3f} "
                  f"| {net_candidate:.3f} | {net_baseline:.3f} | {ratio_text} | {note} |")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
