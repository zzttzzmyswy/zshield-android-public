#!/usr/bin/env python3
"""Regression tests for `scripts/perf/ab_edits_cost.py` (MYS-2826, review round 2).

The stage-5 review rejected the driver for two behaviours that a reader could not see from its output:

  1. **It kept going after a mismatch.** The comparison was computed and printed, then reload, alloc
     and timing ran anyway, with the non-zero exit arriving only at the end. A run wrapped in `|| true`,
     or a reader looking at the tables, got a full set of ratios from two builds that had never been
     shown to agree.
  2. **A record with no decision fields compared equal to another such record.** `compare_outcomes`
     read fields with `.get()`, so two records holding nothing but `id` produced "0 mismatches".

Both are tested here through the **real CLI**, with stand-in binaries that are executed the way the
driver executes the harness — not by importing one function and trusting it, which is what let the
original 5/5 pass while the real entry point was broken.

Run with:
    python3 -m unittest discover -s scripts/perf/tests -p 'test_*.py' -v
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

DRIVER = Path(__file__).resolve().parent.parent / "ab_edits_cost.py"

# A stand-in harness: it logs every mode it is asked for, and answers `--mode=rewrites` with whatever
# the test told it to. Written as a real executable file so the driver runs it through `subprocess`
# exactly as it runs the compiled bench — the point of the review's repro.
STAND_IN = """\
#!{python}
import json, sys
from pathlib import Path
mode = next(a for a in sys.argv if a.startswith("--mode="))
with open({trace!r}, "a") as fh:
    fh.write({name!r} + " " + mode + "\\n")
if mode == "--mode=rewrites":
    for line in {payload!r}.splitlines():
        if line.strip():
            sys.stdout.write(line + "\\n")
elif mode == "--mode=reload":
    for line in {reload_payload!r}.splitlines():
        if line.strip():
            sys.stdout.write(line + "\\n")
elif mode == "--mode=cache":
    sys.stdout.write(json.dumps({{"record": "cache", "build": {name!r}, "id": "c1",
        "cold_median_us": 1.0, "warm_first_call_median_us": 1.0, "warm_median_us": 1.0,
        "cold_over_warm": 1.0}}) + "\\n")
"""


def decision_record(case_id: str, *, block: bool = False, url: str | None = None) -> dict:
    """A complete outcome record: every field the driver requires, with honest defaults."""
    return {
        "record": "outcome",
        "id": case_id,
        "label": case_id,
        "kind": "document",
        "method": "GET",
        "url_in": "https://www.example.com/page",
        "referer": None,
        "block": block,
        "engine_rewritten_url": url,
        "edits_url": url,
        "edits_csp": None,
        "edits_drop_request_headers": [],
        "edits_drop_response_headers": [],
        "removeheader_direct": [],
        "csp_from_decision": None,
        "removeparam_self": url,
        "removeparam_after_serialized_reload": url,
        "edits_present": url is not None,
    }


def reload_records(*, serialized_lines: int = 7, identical: bool = True,
                   follows_live: bool = True) -> list[dict]:
    return [
        {"record": "reload", "check": "serialized_round_trip", "build": "x",
         "identical": identical, "mismatches": [] if identical else [{"id": "c1"}],
         "serialized_lines": serialized_lines, "serialized_bytes": 100, "serialized_sha256": "00"},
        {"record": "reload", "check": "hot_swap_same_content", "build": "x",
         "identical": identical, "mismatches": [] if identical else [{"id": "c1"}]},
        {"record": "reload", "check": "hot_swap_new_content", "build": "x",
         "cases_that_changed": [], "follows_live_rule_set": follows_live},
    ]


class DriverCase(unittest.TestCase):
    """Runs the driver as a subprocess against stand-in binaries in a temp directory."""

    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.dir = Path(self._directory.name)
        self.trace = self.dir / "calls.log"
        self.trace.write_text("")
        (self.dir / "rules.txt").write_text("||ads.example^\n")
        self.matrix = {"version": 1, "cases": [{"id": "c1", "group": "equal",
                                                "method": "GET",
                                                "url": "https://www.example.com/page",
                                                "kind": "document"}]}
        (self.dir / "matrix.json").write_text(json.dumps(self.matrix))
        self.out = self.dir / "out"

    def tearDown(self) -> None:
        self._directory.cleanup()

    def stand_in(self, name: str, payload: list[dict], reload_payload: list[dict] | None = None) -> Path:
        path = self.dir / name
        path.write_text(STAND_IN.format(
            python=sys.executable,
            trace=str(self.trace),
            name=name,
            payload="\n".join(json.dumps(record) for record in payload),
            reload_payload="\n".join(json.dumps(record) for record in (reload_payload or [])),
        ))
        path.chmod(0o755)
        return path

    def run_driver(self, a: Path, b: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(DRIVER),
             "--build", f"a={a}", "--build", f"b={b}",
             "--rules", str(self.dir / "rules.txt"),
             "--matrix", str(self.dir / "matrix.json"),
             "--rounds", "1", "--iterations", "1",
             "--out", str(self.out)],
            text=True, capture_output=True,
        )

    def modes_called(self) -> list[str]:
        text = self.trace.read_text()
        return [line.strip() for line in text.splitlines() if line.strip()]


class MismatchStopsEverything(DriverCase):
    """Review finding 1: a mismatch must abort before any timing."""

    def test_a_block_difference_exits_non_zero_and_runs_no_timing(self) -> None:
        a = self.stand_in("a", [decision_record("c1", block=True)])
        b = self.stand_in("b", [decision_record("c1", block=False)])
        result = self.run_driver(a, b)

        self.assertNotEqual(result.returncode, 0,
                            f"a decision mismatch must fail the run; stdout={result.stdout}")
        called = self.modes_called()
        self.assertEqual(sorted(called), ["a --mode=rewrites", "b --mode=rewrites"],
                         f"no mode beyond rewrites may run after a mismatch; got {called}")
        for forbidden in ("--mode=timing", "--mode=reload", "--mode=alloc"):
            self.assertNotIn(forbidden, " ".join(called),
                             f"{forbidden} must not be invoked after a mismatch")

    def test_a_url_difference_also_aborts(self) -> None:
        a = self.stand_in("a", [decision_record("c1", url="https://www.example.com/page?keep=1")])
        b = self.stand_in("b", [decision_record("c1", url="https://www.example.com/page?keep=2")])
        result = self.run_driver(a, b)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("--mode=timing", " ".join(self.modes_called()))

    def test_the_report_carries_no_timing_after_abort(self) -> None:
        a = self.stand_in("a", [decision_record("c1", block=True)])
        b = self.stand_in("b", [decision_record("c1", block=False)])
        self.run_driver(a, b)
        report = json.loads((self.out / "report.json").read_text())
        self.assertIsNone(report["timing"],
                          "a report written after an aborted comparison must not carry timings")
        self.assertIn("aborted", report)

    def test_no_ratio_table_is_printed_after_abort(self) -> None:
        a = self.stand_in("a", [decision_record("c1", block=True)])
        b = self.stand_in("b", [decision_record("c1", block=False)])
        result = self.run_driver(a, b)
        # The table header, not the word "倍率" — the abort message itself says "不计入倍率结论".
        self.assertNotIn("µs(中位)", result.stdout,
                         "no ratio table may be printed once the equivalence gate has failed")
        self.assertNotIn("### 阶段", result.stdout)


class IncompleteRecordsAreRejected(DriverCase):
    """Review finding 1: absence of a field is not agreement about it."""

    def test_records_with_only_an_id_are_rejected(self) -> None:
        a = self.stand_in("a", [{"id": "c1"}])
        b = self.stand_in("b", [{"id": "c1"}])
        result = self.run_driver(a, b)

        self.assertNotEqual(result.returncode, 0,
                            "records holding only an id must not compare equal")
        self.assertIn("missing decision fields", result.stderr + result.stdout)
        self.assertNotIn("--mode=timing", " ".join(self.modes_called()))

    def test_a_single_missing_field_is_rejected(self) -> None:
        record_a = decision_record("c1")
        record_b = decision_record("c1")
        del record_a["edits_csp"]
        del record_b["edits_csp"]
        a = self.stand_in("a", [record_a])
        b = self.stand_in("b", [record_b])
        result = self.run_driver(a, b)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("edits_csp", result.stderr + result.stdout)

    def test_a_renamed_field_is_rejected(self) -> None:
        record_a = decision_record("c1")
        record_b = decision_record("c1")
        record_a["edits_url_renamed"] = record_a.pop("edits_url")
        record_b["edits_url_renamed"] = record_b.pop("edits_url")
        result = self.run_driver(self.stand_in("a", [record_a]), self.stand_in("b", [record_b]))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unexpected fields", result.stderr + result.stdout)

    def test_a_missing_case_is_rejected(self) -> None:
        self.matrix["cases"].append({"id": "c2", "group": "equal", "method": "GET",
                                     "url": "https://www.example.com/other", "kind": "document"})
        (self.dir / "matrix.json").write_text(json.dumps(self.matrix))
        a = self.stand_in("a", [decision_record("c1")])
        b = self.stand_in("b", [decision_record("c1")])
        result = self.run_driver(a, b)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no outcome record for matrix cases", result.stderr + result.stdout)

    def test_a_duplicate_id_is_rejected(self) -> None:
        a = self.stand_in("a", [decision_record("c1"), decision_record("c1", block=True)])
        b = self.stand_in("b", [decision_record("c1")])
        result = self.run_driver(a, b)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate outcome record", result.stderr + result.stdout)

    def test_an_extra_case_is_rejected(self) -> None:
        a = self.stand_in("a", [decision_record("c1"), decision_record("c9")])
        b = self.stand_in("b", [decision_record("c1")])
        result = self.run_driver(a, b)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cases not in the matrix", result.stderr + result.stdout)


class InternalFieldsAreRecordedNotCompared(DriverCase):
    """A field may be *required* without being *compared* — and the difference must be visible.

    `removeparam_self` is what the core's own evaluator answers. v0.1.2 hands every `$removeparam` rule
    to the engine, so it answers `None` while producing the same final URL. Comparing it would fail the
    equivalence gate on two builds that rewrite identically — which is the case `equal-engine-name`
    exists to measure — so it must be recorded and reported, not gated on.
    """

    def test_a_differing_internal_field_does_not_abort(self) -> None:
        record_a = decision_record("c1", url="https://www.example.com/page?k=1")
        record_b = decision_record("c1", url="https://www.example.com/page?k=1")
        record_b["removeparam_self"] = None
        a = self.stand_in("a", [record_a], reload_records())
        b = self.stand_in("b", [record_b], reload_records())
        result = self.run_driver(a, b)

        self.assertIn("--mode=timing", " ".join(self.modes_called()),
                      "a difference in a not-compared field must not stop the run")
        self.assertIn("INTERNAL", result.stdout,
                      "the difference must still be reported, just not gated on")

    def test_a_missing_internal_field_is_still_rejected(self) -> None:
        # Required-but-not-compared: absent is still a schema violation, because absence cannot be
        # distinguished from "the harness stopped emitting it".
        record_a = decision_record("c1")
        record_b = decision_record("c1")
        del record_a["removeparam_self"]
        del record_b["removeparam_self"]
        result = self.run_driver(self.stand_in("a", [record_a]), self.stand_in("b", [record_b]))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("removeparam_self", result.stderr + result.stdout)


class DeclaredDefectIsStillNotAPass(DriverCase):
    """A declared defect must be louder than a pass and impossible to inherit silently."""

    def _pair(self, reload_a, reload_b):
        return self.run_driver(self.stand_in("a", [decision_record("c1")], reload_a),
                               self.stand_in("b", [decision_record("c1")], reload_b))

    def test_a_declared_defect_is_reported_with_its_reason_and_does_not_abort(self) -> None:
        result = self.run_driver(
            self.stand_in("a", [decision_record("c1")], reload_records()),
            self.stand_in("b", [decision_record("c1")], reload_records(identical=False)),
        ) if False else subprocess.run(
            [sys.executable, str(DRIVER),
             "--build", f"a={self.stand_in('a', [decision_record('c1')], reload_records())}",
             "--build", f"b={self.stand_in('b', [decision_record('c1')], reload_records(identical=False))}",
             "--rules", str(self.dir / "rules.txt"),
             "--matrix", str(self.dir / "matrix.json"),
             "--rounds", "1", "--iterations", "1",
             "--known-reload-defect", "b=declared for the test",
             "--out", str(self.out)],
            text=True, capture_output=True,
        )
        self.assertIn("KNOWN-DEFECT", result.stdout,
                      "a declared defect must be reported, not counted as a pass")
        self.assertIn("declared for the test", result.stdout,
                      "the reason must be printed, so a defect can never be silent")
        self.assertIn("--mode=timing", " ".join(self.modes_called()),
                      "a declared defect must not abort the run")

    def test_an_undeclared_failure_is_still_fatal(self) -> None:
        result = self._pair(reload_records(), reload_records(identical=False))
        self.assertNotEqual(result.returncode, 0)

    def test_a_declaration_without_a_reason_is_refused(self) -> None:
        result = subprocess.run(
            [sys.executable, str(DRIVER),
             "--build", f"a={self.stand_in('a', [decision_record('c1')], reload_records())}",
             "--build", f"b={self.stand_in('b', [decision_record('c1')], reload_records())}",
             "--rules", str(self.dir / "rules.txt"),
             "--matrix", str(self.dir / "matrix.json"),
             "--known-reload-defect", "b=",
             "--out", str(self.out)],
            text=True, capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("BUILD=REASON", result.stderr)


class SuccessfulRunStillWorks(DriverCase):
    """The guard must not block the legitimate path (the review asked for a green continuation)."""

    def test_identical_outcomes_proceed_to_timing(self) -> None:
        a = self.stand_in("a", [decision_record("c1", url="https://www.example.com/page?k=1")],
                          reload_records())
        b = self.stand_in("b", [decision_record("c1", url="https://www.example.com/page?k=1")],
                          reload_records())
        result = self.run_driver(a, b)

        called = " ".join(self.modes_called())
        # The stand-ins answer no timing records, so the driver may still fail on shape — what matters
        # here is that it got *past* the equivalence gate, i.e. it invoked the later modes at all.
        self.assertIn("--mode=timing", called,
                      f"a passing equivalence check must proceed to timing; stderr={result.stderr}")
        self.assertNotIn("OUTCOME-CHECK-FAILED", result.stderr)
        self.assertNotIn("MISMATCH", result.stdout)

    def test_a_capability_difference_does_not_abort(self) -> None:
        self.matrix["cases"].append({"id": "c2", "group": "capability", "method": "GET",
                                     "url": "https://www.example.com/cap", "kind": "document"})
        (self.dir / "matrix.json").write_text(json.dumps(self.matrix))
        a = self.stand_in("a", [decision_record("c1"), decision_record("c2", url="https://x/1")],
                          reload_records())
        b = self.stand_in("b", [decision_record("c1"), decision_record("c2")], reload_records())
        result = self.run_driver(a, b)
        self.assertIn("--mode=timing", " ".join(self.modes_called()),
                      "a by-design capability difference must not stop the run")
        self.assertNotIn("OUTCOME-CHECK-FAILED", result.stderr)


class ReloadControlsAreDecided(DriverCase):
    """Review finding 1: a failing reload control must not be masked by the overall pass."""

    def _pair(self, reload_a: list[dict], reload_b: list[dict]):
        a = self.stand_in("a", [decision_record("c1")], reload_a)
        b = self.stand_in("b", [decision_record("c1")], reload_b)
        return self.run_driver(a, b)

    def test_a_failing_round_trip_aborts(self) -> None:
        result = self._pair(reload_records(identical=False), reload_records())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reload", result.stderr + result.stdout)
        self.assertNotIn("--mode=timing", " ".join(self.modes_called()))

    def test_an_inapplicable_check_is_reported_as_na_not_passed(self) -> None:
        # serialized_lines == 0 is the v0.1.2 case: it collects no rule, so there is nothing to
        # serialize. That must read N/A, and the run must continue.
        result = self._pair(reload_records(serialized_lines=0), reload_records())
        self.assertIn("N/A", result.stdout,
                      f"an inapplicable reload check must be marked N/A; stdout={result.stdout}")
        self.assertIn("--mode=timing", " ".join(self.modes_called()))

    def test_a_missing_reload_record_fails(self) -> None:
        result = self._pair([], reload_records())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no record produced", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
