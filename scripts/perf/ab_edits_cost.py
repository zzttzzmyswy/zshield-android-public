#!/usr/bin/env python3
"""Interleaved A/B driver for `core/examples/edits_cost_matrix` (MYS-2826).

Two builds of the same harness are placed side by side by the caller; this script

  1. feeds both the **same** rule file and the **same** request matrix (verifying their SHA-256),
  2. captures each build's complete decision per case and asserts the two agree on every case the
     matrix marks `group: equal` — a timing comparison is only attributable when the work's *outcome*
     is identical, so this runs before any number is reported,
  3. lists the cases where the two builds genuinely differ (the candidate implements rule forms and
     semantics the older build does not) **separately**, never mixed into the timing table,
  4. runs interleaved multi-batch timing: for each round it runs build A, then build B, on the same
     case, so a slow phase of the machine hits both builds rather than only one,
  5. reports absolute µs, median/mean/min/max/stddev, the ratio, and a bootstrap-free sign test over
     the per-round pairs, so "A is slower" is a claim about the pairing rather than about one sample.

Nothing here needs the device, the network, or root: it runs on the host CPU.

Usage
-----
    python3 scripts/perf/ab_edits_cost.py \
        --build candidate=/path/to/candidate/harness \
        --build baseline=/path/to/baseline/harness \
        --rules scripts/perf/rules/equal-engine-name.txt \
        --matrix scripts/perf/matrix.json \
        --out .effectiveness/results/i2-edits-cost
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import subprocess
import sys
from pathlib import Path


# ------------------------------------------------------------------------------------------------
# Plumbing
# ------------------------------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_jsonl(command: list[str]) -> list[dict]:
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    records = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        records.append(json.loads(line))
    return records


def load_average() -> str:
    return " ".join(Path("/proc/loadavg").read_text().split()[:3])


# ------------------------------------------------------------------------------------------------
# Step 1: same input, same outcome
# ------------------------------------------------------------------------------------------------

# Every field a rewrites record must carry. A record missing any of them is **not** "equal to another
# record also missing it" — an earlier version compared with `.get()`, so two records holding nothing
# but an `id` produced "0 mismatches" and the driver went on to time two builds that had not been shown
# to agree at all. `REQUIRED_FIELDS` is therefore a schema, checked before any comparison.
#
# `INTERNAL_FIELDS` are recorded but **not** part of the equivalence assertion, and the distinction is
# load-bearing rather than a convenience:
#
#   * `removeparam_self` is what the core's *own* evaluator answers. v0.1.2 leaves every `$removeparam`
#     rule to the engine, so it answers `None` while still producing the correct final URL — the same
#     decision reached by a different component. Comparing it would call two builds different when they
#     rewrite the same URL, which is exactly the case `equal-engine-name` is built to measure.
#   * `removeparam_after_serialized_reload` is a reload control, reported in its own section.
#
# What decides a request is `edits_url` + the header lists + `csp` + `block`; those are compared.
REQUIRED_FIELDS = (
    "block",
    "engine_rewritten_url",
    "edits_url",
    "edits_csp",
    "edits_drop_request_headers",
    "edits_drop_response_headers",
    "removeheader_direct",
    "csp_from_decision",
    "removeparam_self",
    "removeparam_after_serialized_reload",
    "edits_present",
)

DECISION_FIELDS = (
    "block",
    "engine_rewritten_url",
    "edits_url",
    "edits_csp",
    "edits_drop_request_headers",
    "edits_drop_response_headers",
    "removeheader_direct",
    "csp_from_decision",
    "edits_present",
)

INTERNAL_FIELDS = ("removeparam_self", "removeparam_after_serialized_reload")

# Bookkeeping keys the harness also emits; allowed but not compared.
NON_DECISION_FIELDS = frozenset({
    "record", "build", "id", "label", "kind", "method", "url_in", "referer", "rules",
})


class OutcomeError(Exception):
    """The rewrites output cannot support a comparison. Raised, never downgraded to a warning."""


def validate_rewrites(name: str, records: list[dict], matrix: dict) -> dict[str, dict]:
    """Check one build's rewrites output is complete, unique and schema-conforming.

    Returns `id -> record`. Raises `OutcomeError` on anything that would make the comparison
    vacuous:

      * a record with no `id`;
      * a duplicate `id` (two records for one case means the later silently won before);
      * an `id` the matrix does not name, or a matrix case with no record (coverage);
      * a record missing any `DECISION_FIELDS` entry, or carrying an unknown key — an unknown key is
        how a renamed field would silently stop being compared;
      * a record whose `record` field says it is not an outcome.

    The harness's header line (`record: header`) is filtered out by the caller; anything else that is
    not an outcome is an error.
    """
    matrix_ids = [case["id"] for case in matrix["cases"]]
    if len(set(matrix_ids)) != len(matrix_ids):
        duplicates = sorted({case for case in matrix_ids if matrix_ids.count(case) > 1})
        raise OutcomeError(f"matrix has duplicate case ids: {duplicates}")

    by_id: dict[str, dict] = {}
    for record in records:
        if record.get("record", "outcome") != "outcome":
            raise OutcomeError(
                f"build {name}: record with record={record.get('record')!r} in the rewrites output; "
                f"only outcome records may appear there"
            )
        case_id = record.get("id")
        if not case_id:
            raise OutcomeError(f"build {name}: an outcome record has no id: {record!r}")
        if case_id in by_id:
            raise OutcomeError(f"build {name}: duplicate outcome record for case {case_id!r}")
        by_id[case_id] = record

    missing = [case for case in matrix_ids if case not in by_id]
    if missing:
        raise OutcomeError(f"build {name}: no outcome record for matrix cases {missing}")
    extra = sorted(set(by_id) - set(matrix_ids))
    if extra:
        raise OutcomeError(f"build {name}: outcome records for cases not in the matrix: {extra}")

    problems = []
    for case_id, record in by_id.items():
        absent = [field for field in REQUIRED_FIELDS if field not in record]
        unknown = sorted(set(record) - set(REQUIRED_FIELDS) - NON_DECISION_FIELDS)
        # Reported together: a renamed field is both "missing" under its old name and "unexpected"
        # under the new one, and naming only the first half hides the rename.
        if absent:
            problems.append(f"build {name}, case {case_id}: missing decision fields {absent}; "
                            f"a record without them cannot be compared — absence is not agreement")
        if unknown:
            problems.append(f"build {name}, case {case_id}: unexpected fields {unknown}; "
                            f"a renamed decision field would otherwise silently stop being compared")
    if problems:
        raise OutcomeError("; ".join(problems))
    return by_id


def compare_outcomes(name_a: str, name_b: str, rewrites_a: list[dict], rewrites_b: list[dict],
                     matrix: dict) -> dict:
    """Compare two builds' decisions on every matrix case.

    Raises `OutcomeError` when either side's output is not a complete, schema-conforming answer for
    the matrix — that is a broken measurement, not a difference of opinion. For a well-formed pair it
    returns both the mismatches on `group: equal` cases (a regression) and the differences on
    `group: capability` cases (by design, reported separately).
    """
    by_id_a = validate_rewrites(name_a, rewrites_a, matrix)
    by_id_b = validate_rewrites(name_b, rewrites_b, matrix)
    groups = {case["id"]: case.get("group", "equal") for case in matrix["cases"]}

    equal_mismatches = []
    capability_differences = []
    internal_differences = []
    equal_cases = 0
    for case_id, group in groups.items():
        record_a = by_id_a[case_id]
        record_b = by_id_b[case_id]
        differing = [
            field for field in DECISION_FIELDS
            if record_a[field] != record_b[field]
        ]
        internal = [
            field for field in INTERNAL_FIELDS
            if record_a[field] != record_b[field]
        ]
        if internal:
            internal_differences.append({
                "id": case_id,
                "group": group,
                "note": "recorded, not compared: different components, same shipping decision",
                "fields": {field: {name_a: record_a[field], name_b: record_b[field]}
                           for field in internal},
            })
        if group == "equal":
            equal_cases += 1
        if differing:
            entry = {
                "id": case_id,
                "group": group,
                "label": record_a.get("label"),
                "fields": {field: {name_a: record_a[field], name_b: record_b[field]}
                           for field in differing},
            }
            if group == "equal":
                equal_mismatches.append(entry)
            else:
                capability_differences.append(entry)

    return {
        "name_a": name_a,
        "name_b": name_b,
        "cases": len(groups),
        "equal_cases": equal_cases,
        "equal_mismatches": equal_mismatches,
        "capability_differences": capability_differences,
        "internal_differences": internal_differences,
        "checked_fields": list(DECISION_FIELDS),
        "not_compared_fields": list(INTERNAL_FIELDS),
    }


# ------------------------------------------------------------------------------------------------
# Step 1b: reload controls are decided, not merely printed
# ------------------------------------------------------------------------------------------------

# Declared, per-build reload defects. Each entry says *which build*, *what it does wrong* and therefore
# why the check cannot be read as a pass for it. Nothing here can excuse the candidate: the lookup is by
# build name, and `run.sh` only ever declares the historical baseline.
#
# v0.1.2 on the full catalog: its `extras.txt` does not round-trip, so `collect(serialize_lines())`
# stops rewriting `hit-document-post` and `hit-document-zhihu` — two cases it rewrites before the reload.
# Measured, not assumed: the check reports the exact case ids it lost.
RELOAD_KNOWN_DEFECTS: dict[str, str] = {}

# A check that cannot apply to a build is reported as N/A with its reason, never as a pass. The one
# such case today: v0.1.2 collects no `$removeparam` rule from the rule sets used here, so its
# `serialize_lines()` is empty and "reload decides the same" has no subject. Marking that PASS would
# hide a real failure behind a vacuous success; marking it FAIL would blame a build for a property it
# has no rules to violate. N/A is the honest third answer, and it is never silently produced — the
# reason has to be written out.
def evaluate_reload_controls(names: list[str], reloads: dict[str, list[dict]],
                             known_defect: dict[str, str] | None = None) -> list[dict]:
    """Turn each build's reload records into a pass / fail / N/A / known-defect verdict.

    `known_defect` maps a build name to a written reason. It exists for one specific, declared
    situation: a build whose own serialized artifact does not reproduce its own decisions. v0.1.2 has
    that property on the full catalog — `extras.txt` does not round-trip, so after a reload it stops
    rewriting two cases it rewrote before. That is a **defect of that build**, not of the candidate,
    and it is itself a finding; aborting the whole run would throw away the data it is part of.

    A `known-defect` verdict:

      * requires a non-empty reason, which is printed and stored — it can never be silent;
      * is only honoured for the build it names, so the candidate can never inherit it;
      * is not a pass: the affected checks are listed separately and the runner reports them.
    """
    verdicts: list[dict] = []
    for name in names:
        records = [record for record in reloads[name] if record.get("record") == "reload"]
        by_check: dict[str, dict] = {}
        for record in records:
            check = record.get("check")
            if not check:
                verdicts.append({"build": name, "check": "<missing>", "verdict": "fail",
                                 "reason": f"reload record without a check name: {record!r}"})
                continue
            by_check[check] = record

        round_trip = by_check.get("serialized_round_trip")
        if round_trip is None:
            verdicts.append({"build": name, "check": "serialized_round_trip", "verdict": "fail",
                             "reason": "no record produced"})
        elif round_trip.get("serialized_lines", 0) == 0:
            verdicts.append({
                "build": name, "check": "serialized_round_trip", "verdict": "n/a",
                "reason": "the build collects no rule from this input, so there is nothing to "
                          "serialize; the check has no subject (not a failure, not a pass)",
            })
        else:
            identical = round_trip.get("identical")
            if identical is True:
                verdict = {"build": name, "check": "serialized_round_trip",
                           "verdict": "pass", "reason": None,
                           "serialized_lines": round_trip.get("serialized_lines")}
            elif known_defect and name in known_defect:
                # Declared, named, and reported — never silent, and never applied to another build.
                affected = sorted({mismatch.get("id") for mismatch
                                   in (round_trip.get("mismatches") or [])})
                verdict = {
                    "build": name, "check": "serialized_round_trip", "verdict": "known-defect",
                    "reason": known_defect[name],
                    "affected_cases": affected,
                    "mismatches": round_trip.get("mismatches"),
                    "serialized_lines": round_trip.get("serialized_lines"),
                }
            else:
                verdict = {"build": name, "check": "serialized_round_trip", "verdict": "fail",
                           "reason": f"mismatches: {round_trip.get('mismatches')}",
                           "serialized_lines": round_trip.get("serialized_lines")}
            verdicts.append(verdict)

        for check in ("hot_swap_same_content", "hot_swap_new_content"):
            record = by_check.get(check)
            if record is None:
                collected = (round_trip or {}).get("serialized_lines", 0)
                verdicts.append({
                    "build": name, "check": check,
                    "verdict": "n/a" if collected == 0 else "fail",
                    "reason": ("the build collects no rule from this input, so a hot swap has "
                               "nothing to change" if collected == 0 else "no record produced"),
                })
                continue
            if check == "hot_swap_same_content":
                identical = record.get("identical")
                if identical is True:
                    verdict = {"build": name, "check": check, "verdict": "pass", "reason": None}
                elif known_defect and name in known_defect:
                    verdict = {"build": name, "check": check, "verdict": "known-defect",
                               "reason": known_defect[name],
                               "mismatches": record.get("mismatches")}
                else:
                    verdict = {"build": name, "check": check, "verdict": "fail",
                               "reason": f"mismatches: {record.get('mismatches')}"}
                verdicts.append(verdict)
            else:
                # Reported, never failed: whether a build follows a live rule set is a property, and
                # v0.1.2's snapshot behaviour is a known defect the candidate fixes. It must not be
                # able to mask a failure of the two checks above, and it must not be counted as one.
                verdicts.append({
                    "build": name, "check": check, "verdict": "reported",
                    "reason": f"follows_live_rule_set={record.get('follows_live_rule_set')}",
                })
    return verdicts


# ------------------------------------------------------------------------------------------------
# Step 2: interleaved timing
# ------------------------------------------------------------------------------------------------

def timing_records(binary: str, rules: Path, matrix: Path, build_id: str, rounds: int,
                   iterations: int, cpu: int | None) -> dict[tuple[str, str], dict]:
    command = []
    if cpu is not None:
        # Pin to one core. Measured on this host (i9-10900X, load ~5–8 from an emulator and a Chrome
        # renderer): the per-process spread of the same binary's median falls from ±0.97 µs to ±0.01 µs
        # when both builds share one dedicated core, because a migration to a busy core is what
        # otherwise dominates a 2 µs measurement. `taskset` rather than a scheduler hint so the pin
        # applies to the exact process being measured.
        command += ["taskset", "-c", str(cpu)]
    records = run_jsonl(command + [
        binary,
        "--rules", str(rules),
        "--matrix", str(matrix),
        "--build-id", build_id,
        "--mode=timing",
        "--rounds", str(rounds),
        "--iters", str(iterations),
    ])
    return {
        (record["id"], record["stage"]): record
        for record in records
        if record.get("record") == "timing"
    }


def alloc_records(binary: str, rules: Path, matrix: Path, build_id: str) -> dict[tuple[str, str], dict]:
    records = run_jsonl([
        binary,
        "--rules", str(rules),
        "--matrix", str(matrix),
        "--build-id", build_id,
        "--mode=alloc",
    ])
    return {
        (record["id"], record["stage"]): record
        for record in records
        if record.get("record") == "alloc"
    }


def interleaved(binaries: dict[str, str], rules: Path, matrix_path: Path, matrix: dict,
                rounds: int, iterations: int, stages: list[str], cpu: int | None) -> list[dict]:
    """Run the builds round-robin, one process per (round, build), and pair the results.

    A separate process per round is what makes this an A/B rather than a sequential pair of A-then-B
    runs: the machine's state at round *k* is shared by both builds, and the median over rounds is a
    median over *paired* samples.
    """
    names = list(binaries)
    per_round: dict[str, list[dict[tuple[str, str], dict]]] = {name: [] for name in names}
    for round_index in range(rounds):
        # Alternate the order every round, so a systematic first-mover effect (page cache, frequency
        # scaling after an idle gap) does not always favour the same build.
        order = names if round_index % 2 == 0 else list(reversed(names))
        for name in order:
            per_round[name].append(
                timing_records(binaries[name], rules, matrix_path, name, 5, iterations, cpu)
            )

    rows = []
    for case in matrix["cases"]:
        case_id = case["id"]
        for stage in stages:
            samples = {
                name: [record[(case_id, stage)]["median_us"]
                       for record in per_round[name]
                       if (case_id, stage) in record]
                for name in names
            }
            if any(not values for values in samples.values()):
                continue
            primary, secondary = names[0], names[1]
            paired = list(zip(samples[primary], samples[secondary]))
            ratios = [a / b for a, b in paired if b]
            floor_primary = min(samples[primary])
            floor_secondary = min(samples[secondary])
            row = {
                "id": case_id,
                "group": case.get("group", "equal"),
                "label": case.get("label", ""),
                "kind": case.get("kind", ""),
                "stage": stage,
                "rounds": len(paired),
                "iterations": iterations,
                primary: summarize(samples[primary]),
                secondary: summarize(samples[secondary]),
                "floor_us": {primary: floor_primary, secondary: floor_secondary},
                "ratio_median": (statistics.median(samples[primary])
                                 / statistics.median(samples[secondary])
                                 if statistics.median(samples[secondary]) else None),
                "ratio_floor": floor_primary / floor_secondary if floor_secondary else None,
                "ratio_paired_median": statistics.median(ratios) if ratios else None,
                "pairs_primary_slower": sum(1 for ratio in ratios if ratio > 1.0),
                "cpu": cpu,
                "loadavg": load_average(),
            }
            rows.append(row)
    return rows


def summarize(values: list[float]) -> dict:
    ordered = sorted(values)
    return {
        "median_us": statistics.median(ordered),
        "mean_us": statistics.fmean(ordered),
        "min_us": ordered[0],
        "max_us": ordered[-1],
        "stddev_us": statistics.pstdev(ordered) if len(ordered) > 1 else 0.0,
        "samples_us": ordered,
    }


# ------------------------------------------------------------------------------------------------
# Rendering
# ------------------------------------------------------------------------------------------------

def table(rows: list[dict], name_a: str, name_b: str, stage: str) -> str:
    lines = [
        f"| 用例 | 组 | {name_a} µs(中位) | {name_b} µs(中位) | 倍率(中位) "
        f"| {name_a} 下界 µs | {name_b} 下界 µs | 倍率(下界) | {name_a} 更慢的轮次 |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        if row["stage"] != stage:
            continue
        floor = row["floor_us"]
        lines.append(
            f"| `{row['id']}` | {row['group'][:4]} "
            f"| {row[name_a]['median_us']:.3f} | {row[name_b]['median_us']:.3f} "
            f"| {row['ratio_median']:.2f}× "
            f"| {floor[name_a]:.3f} | {floor[name_b]:.3f} | {row['ratio_floor']:.2f}× "
            f"| {row['pairs_primary_slower']}/{row['rounds']} |"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", action="append", required=True,
                        metavar="NAME=PATH", help="build name and harness binary; pass twice")
    parser.add_argument("--rules", required=True, type=Path)
    parser.add_argument("--matrix", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--rounds", type=int, default=9)
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument(
        "--known-reload-defect", action="append", default=[], metavar="BUILD=REASON",
        help="declare that BUILD's own serialized artifact does not round-trip, with the reason. "
             "Applied to that build only, reported as KNOWN-DEFECT with the reason and the affected "
             "case ids — never as a pass. Use only for defects the run measures, not to excuse the "
             "candidate.",
    )
    parser.add_argument("--cpu", type=int, default=None,
                        help="pin both builds to this CPU (strongly recommended; see timing_records)")
    arguments = parser.parse_args()

    binaries = {}
    for specification in arguments.build:
        name, _, path = specification.partition("=")
        if not path:
            raise SystemExit(f"--build needs NAME=PATH, got {specification!r}")
        binaries[name] = path
    if len(binaries) != 2:
        raise SystemExit("exactly two --build arguments are required")
    names = list(binaries)

    arguments.out.mkdir(parents=True, exist_ok=True)
    matrix = json.loads(arguments.matrix.read_text())
    stages = ["parse_url", "adblock_request", "decide", "removeheader", "removeparam", "edits"]

    inputs = {
        "rules": str(arguments.rules),
        "rules_sha256": sha256_file(arguments.rules),
        "rules_bytes": arguments.rules.stat().st_size,
        "matrix": str(arguments.matrix),
        "matrix_sha256": sha256_file(arguments.matrix),
        "binaries": {name: {"path": binaries[name], "sha256": sha256_file(Path(binaries[name]))}
                     for name in names},
        "cpu_pin": arguments.cpu,
        "loadavg_at_start": load_average(),
    }

    # ---------------------------------------------------------------------------------------
    # 1. Outcomes. This is a gate, not a report: if it does not pass, nothing else runs.
    #
    # The earlier version wrote the comparison out and then went on to run reload, alloc and timing,
    # returning non-zero only at the very end — so a driver wrapped in `|| true`, or a reader looking
    # at the tables, saw a full set of ratios produced by two builds that had never been shown to
    # agree. Everything below this block is unreachable unless the comparison passed.
    # ---------------------------------------------------------------------------------------
    rewrites = {
        name: run_jsonl([
            binaries[name], "--rules", str(arguments.rules), "--matrix", str(arguments.matrix),
            "--build-id", name, "--mode=rewrites",
        ])
        for name in names
    }
    for name in names:
        (arguments.out / f"rewrites-{name}.jsonl").write_text(
            "\n".join(json.dumps(record, ensure_ascii=False)
                      for record in rewrites[name] if record.get("id")) + "\n"
        )

    # The header carries the rule counts each build collected; keep it where the report can read it
    # instead of re-deriving counts from prose.
    headers = {name: [record for record in rewrites[name] if record.get("record") == "header"]
               for name in names}
    (arguments.out / "headers.json").write_text(
        json.dumps(headers, ensure_ascii=False, indent=2) + "\n"
    )

    # Header records are harness bookkeeping, not outcomes; drop exactly those and nothing else.
    outcomes = {
        name: [record for record in rewrites[name]
               if record.get("record", "outcome") == "outcome"]
        for name in names
    }
    try:
        comparison = compare_outcomes(names[0], names[1],
                                      outcomes[names[0]], outcomes[names[1]], matrix)
    except OutcomeError as error:
        # A malformed or incomplete rewrites output is a failed measurement. Report it, write nothing
        # that could be mistaken for a result, and exit non-zero without invoking any other mode.
        print(f"OUTCOME-CHECK-FAILED: {error}", file=sys.stderr)
        (arguments.out / "outcome-check-failed.json").write_text(
            json.dumps({"passed": False, "reason": str(error), "inputs": inputs},
                       ensure_ascii=False, indent=2) + "\n"
        )
        return 2

    print(json.dumps({"record": "inputs", **inputs}, ensure_ascii=False))
    print()
    print(f"## 改写一致性：{comparison['equal_cases']} 个等价用例，"
          f"{len(comparison['equal_mismatches'])} 处不一致")
    for mismatch in comparison["equal_mismatches"]:
        print(f"  MISMATCH {mismatch['id']}: {json.dumps(mismatch['fields'], ensure_ascii=False)}")
    print(f"## 能力差异用例：{len(comparison['capability_differences'])} 个（不计入倍率结论）")
    for difference in comparison["capability_differences"]:
        print(f"  DIFF {difference['id']}: {json.dumps(difference['fields'], ensure_ascii=False)}")
    print(f"## 内部字段差异：{len(comparison['internal_differences'])} 个"
          f"（{', '.join(comparison['not_compared_fields'])}；记录但不比较）")
    for difference in comparison["internal_differences"]:
        print(f"  INTERNAL {difference['id']}: "
              f"{json.dumps(difference['fields'], ensure_ascii=False)}")

    if comparison["equal_mismatches"]:
        # Stop here. No reload, no alloc, no timing — a ratio computed from two builds that decide the
        # same request differently is not a cost measurement, and printing one invites it being read
        # as one.
        print()
        print(f"## 等价用例不一致 → 终止，未执行任何计时（{len(comparison['equal_mismatches'])} 处）",
              file=sys.stderr)
        (arguments.out / "report.json").write_text(
            json.dumps({"inputs": inputs, "outcome_comparison": comparison,
                        "timing": None, "reload": None, "allocations": None,
                        "aborted": "equal-case mismatch: no timing was run"},
                       ensure_ascii=False, indent=2) + "\n"
        )
        return 1

    # ---------------------------------------------------------------------------------------
    # 2. Reload controls. A failure here is also fatal: it would mean a rule set decides differently
    # after a round trip through its own serialized form, which invalidates every number below.
    #
    # One baseline record is legitimately not applicable rather than failed (it collects no
    # `$removeparam` rule, so its serialized text is empty); that is marked N/A with the reason, and
    # the check is skipped — not counted as a pass.
    # ---------------------------------------------------------------------------------------
    reloads = {
        name: run_jsonl([
            binaries[name], "--rules", str(arguments.rules), "--matrix", str(arguments.matrix),
            "--build-id", name, "--mode=reload",
        ])
        for name in names
    }
    for name in names:
        (arguments.out / f"reload-{name}.jsonl").write_text(
            "\n".join(json.dumps(record, ensure_ascii=False) for record in reloads[name]) + "\n"
        )

    declared: dict[str, str] = {}
    for specification in arguments.known_reload_defect:
        build_name, _, reason = specification.partition("=")
        if not reason.strip():
            parser.error(f"--known-reload-defect needs BUILD=REASON, got {specification!r}")
        if build_name not in names:
            parser.error(f"--known-reload-defect names {build_name!r}, which is not a --build")
        declared[build_name] = reason.strip()
    reload_verdicts = evaluate_reload_controls(names, reloads, declared)
    print()
    for verdict in reload_verdicts:
        mark = {"pass": "PASS", "fail": "FAIL", "n/a": "N/A", "reported": "REPORTED",
                "known-defect": "KNOWN-DEFECT"}[
            verdict["verdict"]]
        print(f"## reload[{verdict['build']}] {verdict['check']}: {mark}"
              + (f" — {verdict['reason']}" if verdict.get("reason") else ""))
    failed_reloads = [verdict for verdict in reload_verdicts if verdict["verdict"] == "fail"]
    if failed_reloads:
        print()
        print(f"## reload 控制失败 → 终止，未执行任何计时（{len(failed_reloads)} 项）",
              file=sys.stderr)
        (arguments.out / "report.json").write_text(
            json.dumps({"inputs": inputs, "outcome_comparison": comparison,
                        "reload": reload_verdicts, "timing": None, "allocations": None,
                        "aborted": "reload control failed: no timing was run"},
                       ensure_ascii=False, indent=2) + "\n"
        )
        return 3

    # 2b. First-use and warmed costs. These ratios do not identify construction frequency.
    cache = {
        name: run_jsonl([
            *(["taskset", "-c", str(arguments.cpu)] if arguments.cpu is not None else []),
            binaries[name], "--rules", str(arguments.rules), "--matrix", str(arguments.matrix),
            "--build-id", name, "--mode=cache",
            "--rounds", str(arguments.rounds), "--iters", str(arguments.iterations),
        ])
        for name in names
    }
    cache_rows = {name: [record for record in cache[name] if record.get("record") == "cache"]
                  for name in names}
    print()
    for name in names:
        for record in cache_rows[name]:
            print(f"## cache[{name}] {record['id']}: cold {record['cold_median_us']:.2f} µs / "
                  f"warm-first {record['warm_first_call_median_us']:.2f} µs / "
                  f"warm {record['warm_median_us']:.3f} µs "
                  f"(×{record['cold_over_warm']:.1f} cold/warm)")

    # 3. Allocation counts.
    allocations = {name: alloc_records(binaries[name], arguments.rules, arguments.matrix, name)
                   for name in names}

    # 4. Interleaved timing.
    rows = interleaved(binaries, arguments.rules, arguments.matrix, matrix, arguments.rounds,
                       arguments.iterations, stages, arguments.cpu)

    report = {
        "inputs": inputs,
        "outcome_comparison": comparison,
        "reload": reload_verdicts,
        "cache": cache_rows,
        "allocations": {
            name: [
                {"id": key[0], "stage": key[1],
                 "allocations_per_call": allocations[name][key]["allocations_per_call"],
                 "bytes_per_call": allocations[name][key]["bytes_per_call"]}
                for key in sorted(allocations[name])
            ]
            for name in names
        },
        "timing": rows,
        "loadavg_at_end": load_average(),
    }
    (arguments.out / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")

    # 5. Human-readable summary on stdout, so the run's log is the same evidence as the JSON.
    print()
    for stage in stages:
        print(f"### 阶段 `{stage}`")
        print(table(rows, names[0], names[1], stage))
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
