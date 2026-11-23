"""`memory_profile.py` must not be able to report a comparison its evidence does not support.

The stage-6 delivery (`docs/EFFECTIVENESS.md` §16.2) compared **one batch per cell** and wrote two
opposite conclusions from it (candidate lower on five lists, higher on nine), while the batches'
own spread was 5.1–7.0 MiB against a 1.15 MiB difference. Nothing in the tooling made that visible.
This module drives the real `memory_profile.py` as a program and checks the three things that make
the difference:

* a **missing** sample or batch is a voided cell with a reason, never a median over the survivors;
* two batches of one cell that ran under different rule content or on different APKs void the cell —
  the campaign is not allowed to average them;
* the **median** is exact (half a kB is preserved) and MiB is derived from the raw kB once;
* a difference inside the between-batch range is printed as *not established*, in both directions.

The fixtures are plain directories of the exact files `pss_idle.sh` writes, because that is what
`recompute` reads — the point of the offline path is that a reviewer can re-derive a finished
campaign from the evidence on disk, with no device and no re-run.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import datetime
import hashlib
import json
import os
import re
import statistics
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent
REPO = SCRIPTS.parent

#: Import the module under test without requiring it to be on `sys.path`. It has to be **registered**
#: in `sys.modules` before its body runs, because `@dataclass` resolves annotations through
#: `sys.modules[cls.__module__]` and fails on an unregistered module.
SPEC = importlib.util.spec_from_file_location("memory_profile", SCRIPTS / "memory_profile.py")
memory_profile = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules["memory_profile"] = memory_profile
SPEC.loader.exec_module(memory_profile)

APK_A = "a" * 64
APK_B = "b" * 64
TOKEN_A = "sha256:" + "1" * 64 + ":1000"
TOKEN_B = "sha256:" + "2" * 64 + ":1000"
#: The serial these offline tests hand the runner. It is a stand-in, not a device: nothing here talks
#: to adb, and the tools refuse to invent a serial of their own (see `device_serial.py`).
STUB_SERIAL = "stub"
#: What a legacy build can declare: the numbers its own load line prints. Not a content hash.
LEGACY_TOKEN = "engine_bytes=32198109 block_rules=180571 network_rules=406819"


def identity(dns: str, engine: str, extras: str) -> str:
    return f"dns={dns} engine={engine} extras={extras}"


def attempt_start(root: Path, rule_set: str, build: str, index: int) -> str:
    """The start the campaign's own attempt record gives this batch.

    A batch writes its `at=` stamp itself, and the campaign records the same instant per attempt;
    two sources for one fact drift unless a fixture derives one from the other. When there is no
    attempt record (a test that removes them on purpose) the stamp falls back to a fixed value, so
    the *only* defect such a test introduces is the missing record.
    """
    record = root / "campaign.json"
    if record.is_file():
        try:
            document = json.loads(record.read_text(encoding="utf-8"))
        except ValueError:
            document = {}
        for attempt in document.get("attempts") or []:
            if attempt.get("cell") == [build, rule_set] and attempt.get("index") == index:
                if attempt.get("started_at"):
                    return str(attempt["started_at"])
    return "2026-11-13T00:00:00Z"


def write_batch(
    root: Path,
    rule_set: str,
    build: str,
    index: int,
    *,
    samples: list[int],
    apk: str = APK_A,
    content: str | None = None,
    with_median: bool = True,
    failure: str | None = None,
    extra_median: bool = False,
    generation: int = 1,
    handle: int = 1,
    apk_after: str | None = None,
    write_apk_before: bool = True,
    write_apk_after: bool = True,
    write_raw: bool = True,
    raw_total_shift: int = 0,
    started_at: str | None = None,
    interval: int = 60,
    gaps: list[int] | None = None,
) -> Path:
    """Write one batch directory exactly as a finished `pss_idle.sh` batch leaves it.

    Complete by default — result rows, both APK hashes and one raw `dumpsys meminfo` answer per
    sample — because the validator now refuses a batch that cannot show which build it ran on, that
    its samples came from one process+generation+handle, and that its rows match the device's own
    answers. Each keyword turns exactly one of those into a controlled defect.
    """
    if started_at is None:
        started_at = attempt_start(root, rule_set, build, index)
    directory = root / f"{rule_set}--{build}--b{index}"
    directory.mkdir(parents=True, exist_ok=True)
    raw = directory / f"pss-{rule_set}-{build}-b{index}.raw"
    if write_raw:
        raw.mkdir(exist_ok=True)
    lines = [
        f"# idle PSS — label={rule_set}-{build}-b{index} at={started_at}",
        f"# serial=stub package=top.zztweb.zshield samples={len(samples)} interval={interval}s "
        f"owner=MYS-2840",
        f"# effective rule content: {content or identity(TOKEN_A, TOKEN_A, TOKEN_A)}",
        "# index\telapsed_s\ttotal_pss_kb\tjava_kb\tnative_kb\tpid\tgeneration\thandle",
    ]
    elapsed = 0
    for offset, value in enumerate(samples, start=1):
        if offset > 1:
            elapsed += gaps[offset - 2] if gaps else interval
        lines.append(f"{offset}\t{elapsed}\t{value}\t5336\t60640\t4242\t"
                     f"{generation}\t{handle}")
        if write_raw:
            (raw / f"meminfo-{offset}.txt").write_text(
                f"Applications Memory Usage (in Kilobytes):\n\n"
                f"** MEMINFO in pid 4242 [top.zztweb.zshield] **\n"
                f"      Native Heap:    60640\n"
                f"        Java Heap:     5336\n"
                f"        TOTAL PSS:    {value + raw_total_shift}"
                f"            TOTAL RSS:   120000\n",
                encoding="utf-8")
    if with_median and samples:
        median = statistics.median(samples)
        exact = f"{int(median)}" if float(median).is_integer() else f"{median:.1f}"
        lines.append(f"## median {exact} kB = {median / 1024:.9f} MiB "
                     f"(min {min(samples)} kB, max {max(samples)} kB)")
        if extra_median:
            lines.append(f"## median {exact} kB = {median / 1024:.9f} MiB "
                         f"(min {min(samples)} kB, max {max(samples)} kB)")
    if failure:
        lines.append(f"FAIL: {failure}")
    (directory / "result.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    if write_apk_before:
        (directory / "apk-sha256-before.txt").write_text(
            f"{apk}  top.zztweb.zshield\n", encoding="utf-8")
    if write_apk_after:
        (directory / "apk-sha256-after.txt").write_text(
            f"{apk_after or apk}  top.zztweb.zshield\n", encoding="utf-8")
    return directory


def write_campaign(
    root: Path,
    *,
    legacy: set[str] | None = None,
    builds: dict[str, str] | None = None,
    rule_sets: dict[str, list[str]] | None = None,
    batches: int = 3,
    samples: int = 6,
    interval: int = 60,
    diagnostic: bool = True,
    record_outcomes: bool = True,
    outcomes: list[str] | None = None,
    record_order: bool = True,
    record_attempts: bool = True,
    attempts_finished: bool = True,
    attempt_gap_minutes: int = 10,
    inputs: bool = True,
    base_time: str = "2026-11-13T00:00:00Z",
    batch_starts: dict[tuple[str, str, int], str] | None = None,
) -> Path:
    """Write the campaign a finished run leaves, complete enough to be *formal* when asked.

    Defaults make a small diagnostic matrix (so a test can vary one thing); a test that wants the
    formal verdict passes `diagnostic=False` and gets a campaign whose three layers all hold. The
    attempt records are what make the executed order checkable: each carries its own id, cell,
    start/finish and output directory, spaced so the batches do not overlap.
    """
    builds = builds or {"candidate": APK_A, "baseline": APK_B}
    rule_sets = rule_sets or {"fixed-five": list(memory_profile.FIXED_FIVE)}
    legacy = legacy or set()
    plan: dict = {
        "builds": {
            name: {"apk_sha256": sha, "apk_path": f"/tmp/{name}.apk",
                   "legacy": name in legacy,
                   "identities": {
                       rule_set: (LEGACY_TOKEN if name in legacy
                                  else identity(TOKEN_A, TOKEN_A, TOKEN_A))
                       for rule_set in rule_sets}}
            for name, sha in builds.items()
        },
        "rule_sets": rule_sets,
        "batches": batches,
        "samples": samples,
        "interval": interval,
        "diagnostic": diagnostic,
    }
    if inputs:
        plan["inputs"] = {
            f"{name}/{rule_set}": input_record(rule_sets[rule_set], legacy=name in legacy,
                                              apk=builds[name])
            for name in builds for rule_set in rule_sets
        }
    record: dict = {"plan": plan, "batches": []}
    ordered = memory_profile.Plan(
        builds={name: memory_profile.Build(name=name, apk_sha256=sha)
                for name, sha in builds.items()},
        rule_sets={name: tuple(lists) for name, lists in rule_sets.items()},
        batches=batches, samples=samples, interval=interval).order()
    if record_order:
        record["order"] = [list(item) for item in ordered]
    if record_outcomes:
        for position, (build_name, rule_set, index) in enumerate(ordered):
            outcome = outcomes[position] if outcomes else "ok"
            record["batches"].append({
                "cell": [build_name, rule_set], "index": index, "outcome": outcome,
                "reason": "sampler exited nonzero" if outcome != "ok" else None,
            })
    if record_attempts:
        base = memory_profile.parse_stamp(base_time)
        record["attempts"] = []
        for position, (build_name, rule_set, index) in enumerate(ordered):
            outcome = outcomes[position] if outcomes else "ok"
            if batch_starts and (build_name, rule_set, index) in batch_starts:
                started = memory_profile.parse_stamp(
                    batch_starts[(build_name, rule_set, index)])
            else:
                started = base + datetime.timedelta(minutes=attempt_gap_minutes * position)
            # A batch is 6 × 60 s plus startup; 8 minutes is a plausible finished span.
            finished = started + datetime.timedelta(minutes=8)
            entry = {
                "attempt_id": f"a{position + 1:03d}-{build_name}-{rule_set}-b{index}",
                "cell": [build_name, rule_set], "index": index,
                "outcome": outcome,
                "directory": f"{rule_set}--{build_name}--b{index}",
            }
            if attempts_finished:
                entry["started_at"] = started.strftime("%Y-%m-%dT%H:%M:%SZ")
                entry["finished_at"] = finished.strftime("%Y-%m-%dT%H:%M:%SZ")
            if outcome != "ok":
                entry["reason"] = "sampler exited nonzero"
            record["attempts"].append(entry)
    (root / "campaign.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return root


def input_record(lists: list[str], *, legacy: bool = False, apk: str = APK_A) -> dict:
    """The input proof a cell needs: which lists the phone had on, their content, and the artifacts.

    A legacy build cannot supply an artifact content hash (it prints byte counts), so its record
    omits that field — which is precisely what `check_inputs` reports as a structural gap rather
    than inventing one.
    """
    record: dict = {
        "lists": [{"id": list_id, "enabled": True, "sha256": hashlib.sha256(
            list_id.encode()).hexdigest()} for list_id in lists],
        "user_rules_sha256": hashlib.sha256(b"user rules").hexdigest(),
        "allowlist_sha256": hashlib.sha256(b"").hexdigest(),
        "apk_sha256": apk,
    }
    if not legacy:
        record["loaded_artifacts_sha256"] = {
            "dns": TOKEN_A, "engine": TOKEN_A, "extras": TOKEN_A}
    return record


def _recompute_stderr(directory: Path) -> str:
    """What `recompute` printed on stderr — the reason, when it refused."""
    err = io.StringIO()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
        memory_profile.main(["recompute", str(directory), "--json"])
    return err.getvalue()


def recompute(directory: Path) -> tuple[int, str]:
    """Run `recompute` in-process and return its exit status and stdout."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        status = memory_profile.main(["recompute", str(directory), "--json"])
    return status, out.getvalue()


def recompute_markdown(directory: Path) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        status = memory_profile.main(["recompute", str(directory)])
    return status, out.getvalue()


def write_formal_campaign(root: Path) -> Path:
    """Write one campaign whose three layers all hold — the reference *valid* fixture.

    The strict time and input schema made the older positive fixtures fail for reasons that had
    nothing to do with the rule under test (they were probes, so they legitimately lacked attempts
    and input records). A reviewer needs the opposite: a campaign constructed to be genuinely
    acceptable, so that "this is rejected" means something. That is this function. It is importable
    on purpose — `tests/review/` probes build on it instead of re-deriving the shape.

    What it contains, and why each part is needed:

    * two builds × two rule sets × three batches (the card's formal matrix);
    * an `inputs` record per cell: the lists with their body hashes and enabled state, the user
      rules and allowlist hashes, the APK hash, and the artifacts the tunnel loaded;
    * an `attempts` list with one unique id per batch, its own start/finish, and the output
      directory — spaced 10 minutes apart so no two batches overlap on one phone;
    * every batch's `# at=` stamp equal to its attempt's start, its declared `interval=60s`, and
      elapsed values 60 s apart;
    * a batch body that agrees with the plan's declared identity for its cell.

    The numbers are synthetic (fixed-five candidate 89 001 kB is deliberately over 84.6 MiB, so the
    fixture also exercises a real FAIL) — a fixture is about the *shape* of evidence, and its
    provenance says so.
    """
    starts: dict[tuple[str, str, int], str] = {}
    for rule_set, hour in (("fixed-five", 0), ("default-nine", 2)):
        for index in range(1, 4):
            starts[("candidate", rule_set, index)] = (
                f"2026-11-13T{hour:02d}:{(index - 1) * 20:02d}:00Z")
            starts[("v012", rule_set, index)] = (
                f"2026-11-13T{hour:02d}:{(index - 1) * 20 + 10:02d}:00Z")
    write_campaign(
        root, diagnostic=False, legacy=set(),
        builds={"candidate": APK_A, "v012": APK_B},
        rule_sets={"fixed-five": list(memory_profile.FIXED_FIVE),
                   "default-nine": list(memory_profile.RULE_SETS["default-nine"])},
        batch_starts=starts)
    for (build_name, rule_set, index), started in starts.items():
        base = {"fixed-five": {"candidate": 89000, "v012": 88500},
                "default-nine": {"candidate": 99000, "v012": 98500}}[rule_set][build_name]
        write_batch(root, rule_set, build_name, index, samples=[base + index] * 6,
                    apk=APK_A if build_name == "candidate" else APK_B, started_at=started)
    return root


class CampaignFixture(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="zs-mem-profile-")
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()


class TheHappyPathIsEvidence(CampaignFixture):
    """A complete campaign re-derives to the same numbers the batches recorded."""

    def test_three_full_batches_per_cell_produce_a_compared_table(self) -> None:
        write_campaign(self.root)
        for index, samples in enumerate(([90000] * 6, [90200] * 6, [90400] * 6), start=1):
            write_batch(self.root, "fixed-five", "candidate", index, samples=samples)
        for index, samples in enumerate(([91000] * 6, [91200] * 6, [91400] * 6), start=1):
            write_batch(self.root, "fixed-five", "baseline", index, samples=samples, apk=APK_B)

        status, output = recompute(self.root)
        document = json.loads(output)
        self.assertEqual(document["problems"], [])
        # `ok` is the acceptance question, not "the samples parsed": every batch here is complete,
        # and the campaign is still not acceptance evidence because it declares itself diagnostic.
        self.assertTrue(document["samples_ok"])
        self.assertFalse(document["ok"])
        # A diagnostic campaign: the numbers are real and reported, and no formal verdict is stated.
        self.assertTrue(document["layer"]["samples_valid"])
        self.assertEqual(document["layer"]["diagnostic"], True)

        cells = {(row["build"], row["rule_set"]): row for row in document["cells"]}
        candidate = cells[("candidate", "fixed-five")]
        # The cell's figure is the median of its batch medians, not the median of all 18 samples.
        self.assertEqual(candidate["batches_kb"], [90000.0, 90200.0, 90400.0])
        self.assertEqual(candidate["centre_kb"], 90200.0)
        self.assertEqual(candidate["between_batch_range_mib"], (90400 - 90000) / 1024.0)
        self.assertEqual(candidate["samples_per_batch"], [6, 6, 6])

    def test_the_threshold_is_reported_per_cell_and_not_relaxed(self) -> None:
        # 87.9 MiB, the stage-6 candidate figure: over the 84.6 MiB gate.
        write_campaign(self.root)
        for index in range(1, 4):
            write_batch(self.root, "fixed-five", "candidate", index,
                        samples=[90000 + index] * 6)
            write_batch(self.root, "fixed-five", "baseline", index,
                        samples=[91000 + index] * 6, apk=APK_B)
        status, output = recompute(self.root)
        document = json.loads(output)
        verdicts = {(row["build"], row["rule_set"]): row["verdict"]
                    for row in document["threshold"]}
        self.assertEqual(document["thresholds_mib"], {"fixed-five": 84.6})
        # The fixture is a diagnostic campaign, so its number is reported without a formal verdict —
        # but the threshold it is measured against is still the card's 84.6, not something softer.
        self.assertEqual(verdicts[("candidate", "fixed-five")], "DIAGNOSTIC")
        # A diagnostic campaign is not acceptance evidence, so it exits non-zero while still
        # reporting its numbers: the exit status means "this is valid evidence", not "the tool ran".
        self.assertNotEqual(status, 0)


class MissingEvidenceIsNeverAveraged(CampaignFixture):
    """A batch that produced no median voids its cell, and the reason is printed."""

    def test_a_batch_without_a_median_line_voids_the_cell(self) -> None:
        write_campaign(self.root)
        for index in range(1, 4):
            write_batch(self.root, "fixed-five", "candidate", index, samples=[90000] * 6,
                        with_median=index != 2)
            write_batch(self.root, "fixed-five", "baseline", index, samples=[91000] * 6, apk=APK_B)
        status, output = recompute(self.root)
        self.assertEqual(status, 1)
        document = json.loads(output)
        self.assertFalse(document["ok"])
        joined = "\n".join(document["problems"])
        self.assertIn("samples but no median line", joined)
        # The valid batches are still reported; the cell is not given a centre.
        cell = next(row for row in document["cells"]
                    if row["build"] == "candidate" and row["rule_set"] == "fixed-five")
        self.assertEqual(cell["ok_batches"], 2)
        self.assertEqual(cell["batches"], 3)

    def test_a_missing_batch_directory_voids_the_cell(self) -> None:
        write_campaign(self.root)
        for index in (1, 3):
            write_batch(self.root, "fixed-five", "candidate", index, samples=[90000] * 6)
            write_batch(self.root, "fixed-five", "baseline", index, samples=[91000] * 6, apk=APK_B)
        status, output = recompute(self.root)
        self.assertEqual(status, 1)
        problems = json.loads(output)["problems"]
        self.assertTrue(any("batch 2 has no directory" in problem for problem in problems), problems)

    def test_a_refused_batch_voids_the_cell_with_its_reason(self) -> None:
        write_campaign(self.root)
        write_batch(self.root, "fixed-five", "candidate", 1, samples=[], with_median=False,
                    failure="the tunnel did not come up; no idle PSS to measure")
        for index in (2, 3):
            write_batch(self.root, "fixed-five", "candidate", index, samples=[90000] * 6)
        for index in range(1, 4):
            write_batch(self.root, "fixed-five", "baseline", index, samples=[91000] * 6, apk=APK_B)
        status, output = recompute(self.root)
        self.assertEqual(status, 1)
        problems = "\n".join(json.loads(output)["problems"])
        self.assertIn("pss_idle.sh refused this batch", problems)
        self.assertIn("tunnel did not come up", problems)

    def test_a_median_that_is_not_the_median_of_its_samples_is_refused(self) -> None:
        # A hand-edited or mis-assembled result file: the printed median does not describe these
        # samples. Nothing downstream may quote it.
        write_campaign(self.root)
        directory = write_batch(self.root, "fixed-five", "candidate", 1, samples=[90000] * 6)
        text = (directory / "result.txt").read_text(encoding="utf-8")
        text = text.replace("## median 90000 kB = 87.890625000 MiB",
                            "## median 80000 kB = 78.125000000 MiB")
        (directory / "result.txt").write_text(text, encoding="utf-8")
        for index in (2, 3):
            write_batch(self.root, "fixed-five", "candidate", index, samples=[90000] * 6)
        for index in range(1, 4):
            write_batch(self.root, "fixed-five", "baseline", index, samples=[91000] * 6, apk=APK_B)
        status, output = recompute(self.root)
        self.assertEqual(status, 1)
        self.assertIn("is not the median of these", "\n".join(json.loads(output)["problems"]))


class IdentityMismatchVoidsTheCell(CampaignFixture):
    """Batches of one cell must have run under one rule content on one APK."""

    def test_two_rule_contents_in_one_cell_void_it(self) -> None:
        write_campaign(self.root)
        write_batch(self.root, "fixed-five", "candidate", 1, samples=[90000] * 6)
        write_batch(self.root, "fixed-five", "candidate", 2, samples=[90000] * 6,
                    content=identity(TOKEN_B, TOKEN_B, TOKEN_B))
        write_batch(self.root, "fixed-five", "candidate", 3, samples=[90000] * 6)
        for index in range(1, 4):
            write_batch(self.root, "fixed-five", "baseline", index, samples=[91000] * 6, apk=APK_B)
        status, output = recompute(self.root)
        self.assertEqual(status, 1)
        problems = "\n".join(json.loads(output)["problems"])
        self.assertIn("2 different rule contents", problems)

    def test_a_rule_content_other_than_the_declared_one_voids_the_cell(self) -> None:
        write_campaign(self.root)
        for index in range(1, 4):
            write_batch(self.root, "fixed-five", "candidate", index, samples=[90000] * 6,
                        content=identity(TOKEN_B, TOKEN_B, TOKEN_B))
            write_batch(self.root, "fixed-five", "baseline", index, samples=[91000] * 6, apk=APK_B)
        status, output = recompute(self.root)
        self.assertEqual(status, 1)
        problems = "\n".join(json.loads(output)["problems"])
        self.assertIn("but the cell declares", problems)

    def test_batches_on_two_apks_void_the_cell(self) -> None:
        write_campaign(self.root)
        write_batch(self.root, "fixed-five", "candidate", 1, samples=[90000] * 6)
        write_batch(self.root, "fixed-five", "candidate", 2, samples=[90000] * 6, apk=APK_B)
        write_batch(self.root, "fixed-five", "candidate", 3, samples=[90000] * 6)
        for index in range(1, 4):
            write_batch(self.root, "fixed-five", "baseline", index, samples=[91000] * 6, apk=APK_B)
        status, output = recompute(self.root)
        self.assertEqual(status, 1)
        self.assertIn("different APKs", "\n".join(json.loads(output)["problems"]))

    def test_a_batch_on_an_undeclared_apk_voids_the_cell(self) -> None:
        write_campaign(self.root)
        undeclared = "c" * 64
        for index in range(1, 4):
            write_batch(self.root, "fixed-five", "candidate", index, samples=[90000] * 6,
                        apk=undeclared)
            write_batch(self.root, "fixed-five", "baseline", index, samples=[91000] * 6, apk=APK_B)
        status, output = recompute(self.root)
        self.assertEqual(status, 1)
        self.assertIn("but the cell declares", "\n".join(json.loads(output)["problems"]))


class TheStatisticsAreExact(CampaignFixture):
    """Half-step medians survive, and MiB is derived from the raw kB once."""

    def test_an_even_sample_count_keeps_the_half_kilobyte(self) -> None:
        write_campaign(self.root, samples=6)
        # Six samples with a half-step median: the exact case the stage-5 review caught rounding.
        samples = [98800, 98810, 98811, 98812, 98900, 98990]
        self.assertEqual(statistics.median(samples), 98811.5)
        for index in range(1, 4):
            write_batch(self.root, "fixed-five", "candidate", index, samples=samples)
            write_batch(self.root, "fixed-five", "baseline", index, samples=samples, apk=APK_B)
        status, output = recompute(self.root)
        self.assertTrue(json.loads(output)["layer"]["samples_valid"], output)
        document = json.loads(output)
        cell = next(row for row in document["cells"] if row["build"] == "candidate")
        self.assertEqual(cell["centre_kb"], 98811.5)
        self.assertEqual(cell["centre_mib"], 98811.5 / 1024.0)
        self.assertAlmostEqual(cell["centre_mib"], 96.49560546875, places=12)

    def test_a_mib_that_disagrees_with_its_kb_is_refused(self) -> None:
        write_campaign(self.root)
        directory = write_batch(self.root, "fixed-five", "candidate", 1, samples=[90000] * 6)
        text = (directory / "result.txt").read_text(encoding="utf-8")
        text = text.replace("= 87.890625000 MiB", "= 88.890625000 MiB")
        (directory / "result.txt").write_text(text, encoding="utf-8")
        for index in (2, 3):
            write_batch(self.root, "fixed-five", "candidate", index, samples=[90000] * 6)
        for index in range(1, 4):
            write_batch(self.root, "fixed-five", "baseline", index, samples=[91000] * 6, apk=APK_B)
        status, output = recompute(self.root)
        self.assertEqual(status, 1)
        self.assertIn("is not 90000 kB / 1024",
                      "\n".join(json.loads(output)["problems"]))

    def test_two_medians_in_one_result_file_are_refused(self) -> None:
        write_campaign(self.root)
        write_batch(self.root, "fixed-five", "candidate", 1, samples=[90000] * 6,
                    extra_median=True)
        for index in (2, 3):
            write_batch(self.root, "fixed-five", "candidate", index, samples=[90000] * 6)
        for index in range(1, 4):
            write_batch(self.root, "fixed-five", "baseline", index, samples=[91000] * 6, apk=APK_B)
        status, output = recompute(self.root)
        self.assertEqual(status, 1)
        self.assertIn("two medians", "\n".join(json.loads(output)["problems"]))


class ComparisonsDescribeAndDoNotDecide(CampaignFixture):
    """The comparison reports numbers; it does not turn them into a direction verdict.

    The previous revision had `established = |difference| > max(spread)` and its mirror tests. The
    second review deleted that inference, and so are the tests that encoded it: the spread of three
    batches is not an error bar, and "the difference is bigger than the drift I happened to observe"
    is not a claim about the product. What the report must do is state both centres, the difference
    and both ranges, and let the reader decide.

    A formal comparison *is* still withheld when a layer fails — that is a different thing, and it is
    covered by `TheFormalVerdictNeedsAllThreeLayers`.
    """

    def _comparison(self, candidate: list[int], baseline: list[int], **kwargs) -> dict:
        kwargs.setdefault("diagnostic", False)
        kwargs.setdefault("builds", {"candidate": APK_A, "v012": APK_B})
        kwargs.setdefault("legacy", set())
        kwargs.setdefault("rule_sets", {
            "fixed-five": list(memory_profile.FIXED_FIVE),
            "default-nine": list(memory_profile.RULE_SETS["default-nine"]),
        })
        starts: dict[tuple[str, str, int], str] = {}
        for rule_set, hour in (("fixed-five", 0), ("default-nine", 2)):
            for index in range(1, 4):
                starts[("candidate", rule_set, index)] = (
                    f"2026-11-13T{hour:02d}:{(index - 1) * 20:02d}:00Z")
                starts[("v012", rule_set, index)] = (
                    f"2026-11-13T{hour:02d}:{(index - 1) * 20 + 10:02d}:00Z")
        kwargs.setdefault("batch_starts", starts)
        write_campaign(self.root, **kwargs)
        for index, median in enumerate(candidate, start=1):
            write_batch(self.root, "fixed-five", "candidate", index, samples=[median] * 6,
                        started_at=starts[("candidate", "fixed-five", index)])
            write_batch(self.root, "default-nine", "candidate", index,
                        samples=[99000 + index] * 6,
                        started_at=starts[("candidate", "default-nine", index)])
        for index, median in enumerate(baseline, start=1):
            write_batch(self.root, "fixed-five", "v012", index, samples=[median] * 6,
                        apk=APK_B, started_at=starts[("v012", "fixed-five", index)])
            write_batch(self.root, "default-nine", "v012", index, samples=[98500 + index] * 6,
                        apk=APK_B, started_at=starts[("v012", "default-nine", index)])
        status, output = recompute(self.root)
        self.assertEqual(status, 0, output)
        comparisons = json.loads(output)["comparisons"]
        five = [entry for entry in comparisons if entry["rule_set"] == "fixed-five"]
        self.assertEqual(len(five), 1, "the fixed five-list set is compared once")
        return five[0]

    def test_a_large_difference_is_still_reported_without_a_direction(self) -> None:
        # A 6 MiB gap with tight batches: the numbers are stated, and no verdict is attached to them.
        verdict = self._comparison([100000, 100100, 100200], [94000, 94100, 94200])
        self.assertAlmostEqual(verdict["difference_mib"], (100100 - 94100) / 1024.0, places=9)
        self.assertAlmostEqual(verdict["left_mib"], 100100 / 1024.0, places=9)
        self.assertAlmostEqual(verdict["right_mib"], 94100 / 1024.0, places=9)
        self.assertAlmostEqual(verdict["left_range_mib"], 200 / 1024.0, places=9)
        for forbidden in ("established", "verdict"):
            self.assertNotIn(forbidden, verdict,
                             "a difference-versus-spread verdict is not this tool's conclusion")

    def test_a_small_difference_is_reported_the_same_way(self) -> None:
        verdict = self._comparison([88000, 90000, 95000], [90000, 91000, 92000])
        self.assertLess(verdict["difference_mib"], 0)
        self.assertNotIn("established", verdict)

    def test_each_cells_batch_count_is_reported(self) -> None:
        verdict = self._comparison([100000, 100100, 100200], [99000, 99100, 99200])
        self.assertEqual(verdict["left_batches"], 3)
        self.assertEqual(verdict["right_batches"], 3)


class ThePlanIsValidatedBeforeAnyDeviceCommand(CampaignFixture):
    """A hand-written plan is checked by name, so a typo costs nothing on the phone."""

    def _check(self, document: dict) -> int:
        path = self.root / "plan.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return memory_profile.main(["plan-check", "--plan", str(path)])

    def test_a_complete_plan_is_accepted_and_its_order_alternates(self) -> None:
        document = _plan_document()
        document["rule_sets"]["default-nine"] = [
            "adguard-base", "adguard-tracking", "adguard-mobile", "adguard-url-tracking",
            "adguard-chinese", "adguard-dns", "easylist-china", "ublock-unbreak",
            "ublock-quick-fixes"]
        for build in document["builds"].values():
            build["identities"]["default-nine"] = identity(TOKEN_A, TOKEN_A, TOKEN_A)
        self.assertEqual(self._check(document), 0)
        plan = memory_profile.load_plan(self.root / "plan.json")
        order = plan.order()
        self.assertEqual(len(order), 2 * 2 * 3)

        # Property 1: the two builds alternate batch for batch, so no build owns a contiguous window
        # of the phone's warming up (which is how a 1.15 MiB difference could be read from data whose
        # own batches spread 5–7 MiB in stage 6).
        for index in range(0, len(order) - 1, 2):
            first, second = order[index], order[index + 1]
            self.assertEqual((first[1], first[2]), (second[1], second[2]))
            self.assertNotEqual(first[0], second[0])

        # Property 2: the rule set changes once per block, because toggling lists makes the app
        # recompile and a compile transient must not sit inside one build's window and not the
        # other's.
        switches = sum(1 for first, second in zip(order, order[1:]) if first[1] != second[1])
        self.assertEqual(switches, 1)

    def test_fewer_than_three_batches_is_refused(self) -> None:
        formal = _plan_document(batches=2)
        formal["diagnostic"] = False
        self.assertEqual(self._check(formal), 2)

    def test_two_builds_with_one_apk_is_refused(self) -> None:
        document = _plan_document()
        document["builds"]["baseline"]["apk_sha256"] = APK_A
        self.assertEqual(self._check(document), 2)

    def test_a_build_without_an_identity_for_a_rule_set_is_refused(self) -> None:
        document = _plan_document()
        document["builds"]["candidate"]["identities"] = {}
        self.assertEqual(self._check(document), 2)

    def test_an_identity_of_all_absent_components_is_refused(self) -> None:
        document = _plan_document()
        document["builds"]["candidate"]["identities"]["fixed-five"] = "dns=- engine=- extras=-"
        self.assertEqual(self._check(document), 2)

    def test_a_malformed_identity_token_is_refused(self) -> None:
        document = _plan_document()
        document["builds"]["candidate"]["identities"]["fixed-five"] = \
            "dns=sha256:nothex:1000 engine=- extras=-"
        self.assertEqual(self._check(document), 2)

    def test_a_missing_rule_set_is_refused(self) -> None:
        document = _plan_document()
        document["rule_sets"]["fixed-five"] = []
        self.assertEqual(self._check(document), 2)

    def test_a_not_a_campaign_directory_exits_two(self) -> None:
        status, _ = recompute(self.root)
        self.assertEqual(status, 2)


class TheRuleSetNamesAreTheCards(CampaignFixture):
    """The five and nine list sets are spelled the card's way, so a plan cannot quietly measure other."""

    def test_the_fixed_five_are_the_cards_five(self) -> None:
        self.assertEqual(
            memory_profile.RULE_SETS["fixed-five"],
            ("adguard-base", "adguard-tracking", "adguard-mobile", "adguard-url-tracking",
             "adguard-chinese"),
        )

    def test_the_default_nine_are_the_five_plus_the_cards_four(self) -> None:
        self.assertEqual(
            memory_profile.RULE_SETS["default-nine"][:5],
            memory_profile.RULE_SETS["fixed-five"],
        )
        self.assertEqual(
            set(memory_profile.RULE_SETS["default-nine"][5:]),
            {"adguard-dns", "easylist-china", "ublock-unbreak", "ublock-quick-fixes"},
        )

    def test_the_threshold_is_the_design_documents(self) -> None:
        self.assertEqual(memory_profile.THRESHOLD_MIB, 84.6)


class TheMarkdownReportSaysWhatTheJsonSays(CampaignFixture):
    """The printed table is what goes into the issue comment, so it must not contradict the data."""

    def test_the_table_carries_the_centre_range_and_the_verdict(self) -> None:
        write_campaign(self.root)
        for index, samples in enumerate(([90000] * 6, [90200] * 6, [90400] * 6), start=1):
            write_batch(self.root, "fixed-five", "candidate", index, samples=samples)
            write_batch(self.root, "fixed-five", "baseline", index,
                        samples=[x + 1000 for x in samples], apk=APK_B)
        status, output = recompute_markdown(self.root)
        self.assertNotEqual(status, 0, "a diagnostic campaign is not acceptance evidence")
        self.assertIn("证据分层", output)
        self.assertIn("样本数值有效：是", output)
        self.assertIn("fixed-five", output)
        self.assertIn("88.085937500", output)  # 90200 kB, the candidate's centre
        self.assertIn("批间极差", output)
        self.assertIn("诊断数值", output)


class TheLegacyBuildIsMeasuredWithTheEvidenceItHas(CampaignFixture):
    """v0.1.2 predates `rules identity:`; its cells must say so rather than pass as equal."""

    def test_a_legacy_plan_declares_numbers_not_a_hash(self) -> None:
        document = _plan_document()
        document["builds"]["baseline"]["legacy"] = True
        document["builds"]["baseline"]["identities"] = {
            "fixed-five": "engine_bytes=32198109 block_rules=180571 network_rules=406819"}
        path = self.root / "plan.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(memory_profile.main(["plan-check", "--plan", str(path)]), 0)
        plan = memory_profile.load_plan(path)
        self.assertTrue(plan.builds["baseline"].legacy)
        self.assertFalse(plan.builds["candidate"].legacy)

    def test_a_legacy_identity_with_a_hash_is_refused(self) -> None:
        # A `sha256:` token on a legacy build would claim the content identity that build cannot
        # produce. That is the misreporting the whole split exists to prevent.
        document = _plan_document()
        document["builds"]["baseline"]["legacy"] = True
        path = self.root / "plan.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(memory_profile.main(["plan-check", "--plan", str(path)]), 2)

    def test_a_legacy_identity_missing_a_key_is_refused(self) -> None:
        document = _plan_document()
        document["builds"]["baseline"]["legacy"] = True
        document["builds"]["baseline"]["identities"] = {"fixed-five": "engine_bytes=32198109"}
        path = self.root / "plan.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(memory_profile.main(["plan-check", "--plan", str(path)]), 2)

    def test_a_legacy_identity_with_a_non_numeric_value_is_refused(self) -> None:
        document = _plan_document()
        document["builds"]["baseline"]["legacy"] = True
        document["builds"]["baseline"]["identities"] = {
            "fixed-five": "engine_bytes=many block_rules=1 network_rules=2"}
        path = self.root / "plan.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(memory_profile.main(["plan-check", "--plan", str(path)]), 2)

    def test_a_build_without_apk_path_is_refused(self) -> None:
        document = _plan_document()
        del document["builds"]["candidate"]["apk_path"]
        path = self.root / "plan.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(memory_profile.main(["plan-check", "--plan", str(path)]), 2)

    def test_a_legacy_batch_reports_its_numbers_as_its_content_line(self) -> None:
        # The campaign file a legacy batch writes must round-trip through `parse_batch` without
        # pretending the numbers are a content hash: `recompute` accepts the string it finds and the
        # cell keeps it in the report.
        write_campaign(self.root, legacy={"candidate"})
        legacy = LEGACY_TOKEN
        for index in range(1, 4):
            write_batch(self.root, "fixed-five", "candidate", index, samples=[90000] * 6,
                        content=legacy)
            write_batch(self.root, "fixed-five", "baseline", index, samples=[91000] * 6, apk=APK_B)
        status, output = recompute(self.root)
        self.assertTrue(json.loads(output)["layer"]["samples_valid"], output)
        document = json.loads(output)
        cell = next(row for row in document["cells"] if row["build"] == "candidate")
        self.assertEqual(cell["identity"], legacy)


class ADevicePinnedIdentityIsAPinNotADerivation(CampaignFixture):
    """The phone's list bodies cannot be read from a release build, so a host compile may not match.

    The measurement that exposed this: the phone's own `compiled 6 lists:` line reported
    `180571 block` for the five-list set while the host compile of the same five catalog bodies
    reported `180794`. The phone also holds four user rules, which the host request had as `""`.
    An identity computed on the host is therefore not automatically the identity the phone reaches,
    and a plan that hard-codes one would refuse every batch of a correctly selected rule set.
    """

    def test_a_device_pinned_build_needs_no_declared_identity_for_the_cell(self) -> None:
        document = _plan_document()
        for build in document["builds"].values():
            build["identity_source"] = "device"
            build["identities"] = {}
        path = self.root / "plan.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(memory_profile.main(["plan-check", "--plan", str(path)]), 0)

    def test_a_device_pinned_cell_must_still_agree_with_itself(self) -> None:
        # Pinning removes the *declaration* check, not the consistency check: two batches of one cell
        # that ran under two different contents are still a voided cell.
        write_campaign(self.root)
        write_batch(self.root, "fixed-five", "candidate", 1, samples=[90000] * 6)
        write_batch(self.root, "fixed-five", "candidate", 2, samples=[90000] * 6,
                    content=identity(TOKEN_B, TOKEN_B, TOKEN_B))
        write_batch(self.root, "fixed-five", "candidate", 3, samples=[90000] * 6)
        for index in range(1, 4):
            write_batch(self.root, "fixed-five", "baseline", index, samples=[91000] * 6, apk=APK_B)
        status, output = recompute(self.root)
        self.assertEqual(status, 1)
        self.assertIn("2 different rule contents", "\n".join(json.loads(output)["problems"]))

    def test_a_legacy_build_can_be_pinned_from_the_phone_too(self) -> None:
        # v0.1.2 is exactly the build that needs this: its list bodies cannot be read off the phone
        # either, so a host compile of the catalog bodies is not necessarily its inputs. The pin is
        # the numbers its own load line prints, and every later batch of the cell is held to them.
        document = _plan_document()
        document["builds"]["baseline"]["identity_source"] = "device"
        document["builds"]["baseline"]["legacy"] = True
        document["builds"]["baseline"]["identities"] = {}
        path = self.root / "plan.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(memory_profile.main(["plan-check", "--plan", str(path)]), 0)

    def test_a_legacy_pin_is_still_validated_when_present(self) -> None:
        document = _plan_document()
        document["builds"]["baseline"]["identity_source"] = "device"
        document["builds"]["baseline"]["legacy"] = True
        document["builds"]["baseline"]["identities"] = {"fixed-five": "engine_bytes=many"}
        path = self.root / "plan.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(memory_profile.main(["plan-check", "--plan", str(path)]), 2)

    def test_an_unknown_identity_source_is_refused(self) -> None:
        document = _plan_document()
        document["builds"]["candidate"]["identity_source"] = "guessed"
        path = self.root / "plan.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(memory_profile.main(["plan-check", "--plan", str(path)]), 2)

    def test_the_report_says_where_each_cell_identity_came_from(self) -> None:
        write_campaign(self.root)
        for index in range(1, 4):
            write_batch(self.root, "fixed-five", "candidate", index, samples=[90000] * 6)
            write_batch(self.root, "fixed-five", "baseline", index, samples=[91000] * 6, apk=APK_B)
        status, output = recompute(self.root)
        self.assertTrue(json.loads(output)["layer"]["samples_valid"], output)
        for row in json.loads(output)["cells"]:
            self.assertEqual(row["identity_source"], "declared")


class _AlwaysGrantedLock:
    """A device lock that always says yes, for tests that drive a stand-in batch tool."""

    def __init__(self, owner: str, serial: str) -> None:
        self.owner = owner
        self.serial = serial
        self.taken = 0
        self.released = 0

    def take(self) -> None:
        self.taken += 1

    def release(self) -> None:
        self.released += 1


class _RefusedLock:
    """A device lock another owner holds."""

    def __init__(self, owner: str, serial: str) -> None:
        self.owner = owner

    def take(self) -> None:
        raise memory_profile.CampaignError(
            "the device lock is not available: HELD owner=MYS-9999. Nothing was installed, toggled "
            "or cleared: this run refuses to touch a phone it does not own")

    def release(self) -> None:
        pass


class ThePreparationPhaseNeedsTheLock(CampaignFixture):
    """No lock, no device write — the card's ordering, checked by counting the writes.

    The first delivery installed the APK, toggled lists and cold-started for the identity check
    *before* any lock existed (`run_campaign`'s install step and `verify_selection_identity`), so a
    run could change a phone another task owned. The lock is now taken before the first write and
    released before each sampler starts, because the sampler takes it itself.
    """

    def _plan(self, out: Path) -> Path:
        document = _plan_document(batches=3, samples=6)
        document["select"] = "none"
        document["builds"].pop("baseline", None)
        plan_file = self.root / "plan.json"
        plan_file.write_text(json.dumps(document), encoding="utf-8")
        return plan_file

    def test_a_refused_lock_touches_nothing(self) -> None:
        # The three things the preparation phase would otherwise do, each counted.
        writes: list[str] = []
        saved = {
            "DeviceLock": memory_profile.DeviceLock,
            "device_apk_sha": memory_profile.device_apk_sha,
            "select_rule_set": memory_profile.select_rule_set,
            "verify_selection_identity": memory_profile.verify_selection_identity,
            "PSS_IDLE": memory_profile.PSS_IDLE,
        }
        memory_profile.DeviceLock = _RefusedLock
        memory_profile.device_apk_sha = lambda serial, package: (
            writes.append("read-apk"), APK_A)[1]
        memory_profile.select_rule_set = lambda *a, **k: writes.append("select-lists")
        memory_profile.verify_selection_identity = lambda *a, **k: (
            writes.append("identity-precheck"), f"dns={TOKEN_A} engine={TOKEN_A} extras={TOKEN_A}")[1]
        try:
            out = self.root / "campaign"
            # The public `run` refuses before anything else, so this drives the runner body
            # directly: what is under test here is that the lock is taken *before* the first device
            # write, a property the gated entry point no longer exercises at all.
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                status = memory_profile.device_campaign_draft(
                    memory_profile.load_plan(self._plan(out)), out, "MYS-2840",
                    STUB_SERIAL, memory_profile.DEFAULT_PACKAGE)
            self.assertEqual(status, 1, "a run that cannot take the lock does not report success")
            self.assertEqual(writes, [],
                             f"nothing may touch the phone without the lock, but these ran: {writes}")
            # Every batch is recorded as void with the lock as the reason.
            record = json.loads((out / "campaign.json").read_text(encoding="utf-8"))
            self.assertTrue(record["batches"])
            for entry in record["batches"]:
                self.assertEqual(entry["outcome"], "void")
                self.assertIn("lock", (entry.get("reason") or "").lower())
        finally:
            memory_profile.DeviceLock = saved["DeviceLock"]
            memory_profile.device_apk_sha = saved["device_apk_sha"]
            memory_profile.select_rule_set = saved["select_rule_set"]
            memory_profile.verify_selection_identity = saved["verify_selection_identity"]
            memory_profile.PSS_IDLE = saved["PSS_IDLE"]

    def test_the_lock_is_taken_before_every_write_and_released_before_the_sampler(self) -> None:
        order: list[str] = []
        saved = {
            "DeviceLock": memory_profile.DeviceLock,
            "device_apk_sha": memory_profile.device_apk_sha,
            "verify_selection_identity": memory_profile.verify_selection_identity,
            "PSS_IDLE": memory_profile.PSS_IDLE,
        }

        class _RecordingLock:
            def __init__(self, owner: str, serial: str) -> None:
                self.owner = owner

            def take(self) -> None:
                order.append("lock-take")

            def release(self) -> None:
                order.append("lock-release")

        stub = self.root / "bin" / "pss_idle.sh"
        stub.parent.mkdir(parents=True, exist_ok=True)
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "set -u\n"
            "label=\"$1\"; shift\n"
            "out=\"\"\n"
            "while [ $# -gt 0 ]; do case \"$1\" in --out) out=\"$2\"; shift 2;; *) shift;; esac; done\n"
            "{ printf '## samples (raw dumpsys kB)\\n'\n"
            "  printf '1\\t0\\t90000\\t5000\\t60000\\t4242\\t1\\t1\\n'\n"
            "  printf '2\\t60\\t90002\\t5000\\t60000\\t4242\\t1\\t1\\n'\n"
            "  printf '3\\t120\\t90004\\t5000\\t60000\\t4242\\t1\\t1\\n'\n"
            "  printf '4\\t180\\t90006\\t5000\\t60000\\t4242\\t1\\t1\\n'\n"
            "  printf '5\\t240\\t90008\\t5000\\t60000\\t4242\\t1\\t1\\n'\n"
            "  printf '6\\t300\\t90010\\t5000\\t60000\\t4242\\t1\\t1\\n'\n"
            "  printf '# effective rule content: %s\\n' \"$STUB_TOKENS\"; } > \"$out/pss-$label.txt\"\n"
            "mkdir -p \"$out/pss-$label.raw\"\n"
            "i=1; for v in 90000 90002 90004 90006 90008 90010; do\n"
            "  printf '** MEMINFO in pid 4242 [top.zztweb.zshield] **\\n        TOTAL PSS:    %s\\n' \"$v\""
            " > \"$out/pss-$label.raw/meminfo-$i.txt\"; i=$((i+1)); done\n"
            "printf '%s  top.zztweb.zshield\\n' \"$STUB_APK\" > \"$out/apk-sha256-before.txt\"\n"
            "printf '%s  top.zztweb.zshield\\n' \"$STUB_APK\" > \"$out/apk-sha256-after.txt\"\n"
            "echo '## median 90005 kB = 87.895507813 MiB (min 90000 kB, max 90010 kB)'\n"
            "printf 'sampler-ran\\n' >> \"$STUB_TRACE\"\n",
            encoding="utf-8")
        stub.chmod(0o755)
        adb = stub.parent / "adb"
        adb.write_text(
            "#!/usr/bin/env bash\n"
            "case \"$*\" in\n"
            "  *\"pm path\"*) echo \"package:/data/app/base.apk\" ;;\n"
            "  *sha256sum*) echo \"$STUB_APK  /data/app/base.apk\" ;;\n"
            "esac\n", encoding="utf-8")
        adb.chmod(0o755)
        tokens = f"dns={TOKEN_A} engine={TOKEN_A} extras={TOKEN_A}"
        trace = self.root / "trace.txt"
        memory_profile.DeviceLock = _RecordingLock
        memory_profile.device_apk_sha = lambda serial, package: (
            order.append("read-apk"), APK_A)[1]
        memory_profile.verify_selection_identity = lambda *a, **k: (
            order.append("identity-precheck"), tokens)[1]
        memory_profile.PSS_IDLE = stub
        saved_path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{stub.parent}{os.pathsep}{saved_path}"
        os.environ["STUB_TOKENS"] = tokens
        os.environ["STUB_APK"] = APK_A
        os.environ["STUB_TRACE"] = str(trace)
        try:
            out = self.root / "campaign"
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                memory_profile.device_campaign_draft(
                    memory_profile.load_plan(self._plan(out)), out, "MYS-2840",
                    STUB_SERIAL, memory_profile.DEFAULT_PACKAGE)
            self.assertTrue(order, "the preparation phase ran")
            first_write = next(index for index, item in enumerate(order)
                               if item in ("read-apk", "identity-precheck"))
            self.assertLess(order.index("lock-take"), first_write,
                            f"the lock is taken before the first device write; order was {order}")
            self.assertLess(order.index("lock-release"), len(order) - 1,
                            f"the lock is handed back before the sampler runs; order was {order}")
        finally:
            memory_profile.DeviceLock = saved["DeviceLock"]
            memory_profile.device_apk_sha = saved["device_apk_sha"]
            memory_profile.verify_selection_identity = saved["verify_selection_identity"]
            memory_profile.PSS_IDLE = saved["PSS_IDLE"]
            os.environ["PATH"] = saved_path
            for name in ("STUB_TOKENS", "STUB_APK", "STUB_TRACE"):
                os.environ.pop(name, None)


def _plan_document(**overrides) -> dict:
    document = {
        "builds": {
            "candidate": {"apk_sha256": APK_A, "apk_path": "/tmp/candidate.apk", "identities": {
                "fixed-five": identity(TOKEN_A, TOKEN_A, TOKEN_A)}},
            "baseline": {"apk_sha256": APK_B, "apk_path": "/tmp/baseline.apk", "identities": {
                "fixed-five": identity(TOKEN_A, TOKEN_A, TOKEN_A)}},
        },
        "rule_sets": {"fixed-five": ["adguard-base", "adguard-tracking", "adguard-mobile",
                                     "adguard-url-tracking", "adguard-chinese"]},
        "batches": 3,
        "samples": 6,
        "interval": 60,
        # A probe, not the card's 12-batch matrix: each test below varies one thing. Declaring it
        # diagnostic is what keeps a probe from ever being summarised as acceptance evidence.
        "diagnostic": True,
    }
    document.update(overrides)
    return document


class TheReviewerCounterExamplesAreRejected(CampaignFixture):
    """The six invalid-evidence shapes an independent review reproduced as accepted.

    On the previous head every one of these recomputed to `exit 0 / ok=true / threshold=['PASS']`,
    while the valid summary passed too — six false accepts in one script. Each is a shape a real
    campaign can produce, not a contrived edit: a batch that lost two samples, a rule swap or a
    process restart inside one batch, a batch whose APK hashes were never written, a phone that took
    a different build between the two reads, and a campaign file that itself recorded voids.

    They live here so the fix cannot regress: the reviewer's script is external and one run only.
    """

    def _assert_refused(self, case: str) -> dict:
        status, output = recompute(self.root)
        self.assertEqual(status, 1, f"{case}: invalid evidence must not recompute to success")
        document = json.loads(output)
        self.assertFalse(document["ok"], f"{case}: ok must be false")
        self.assertTrue(document["problems"], f"{case}: the reason must be stated")
        # The defective cell carries no threshold verdict and takes part in no comparison. (The
        # other cell of the same rule set is untouched evidence and may still report its own centre;
        # what it may not do is produce a version difference, which needs both.)
        self.assertEqual([row for row in document["threshold"] if row["build"] == "candidate"], [],
                         f"{case}: a voided cell must carry no threshold verdict")
        self.assertEqual([row for row in document["comparisons"] if row["rule_set"] == "fixed-five"],
                         [], f"{case}: a voided cell must not produce a version difference")
        return document

    def test_a_batch_with_five_of_six_samples_is_refused(self) -> None:
        write_campaign(self.root)
        for index in range(1, 4):
            write_batch(self.root, "fixed-five", "candidate", index,
                        samples=[80000] * (5 if index == 2 else 6))
            write_batch(self.root, "fixed-five", "baseline", index, samples=[81000] * 6, apk=APK_B)
        document = self._assert_refused("five-of-six")
        self.assertIn("5 sample row(s)", "\n".join(document["problems"]))

    def test_a_generation_change_inside_one_batch_is_refused(self) -> None:
        # A swap *within* one batch: samples 1-2 under generation 1 and 3-6 under generation 2
        # describe two different rule sets, so their median describes neither. (A batch that ran
        # entirely under one generation is fine, whatever its number — that is what the cell check
        # compares.)
        write_campaign(self.root)
        for index in range(1, 4):
            write_batch(self.root, "fixed-five", "candidate", index, samples=[80000] * 6)
            write_batch(self.root, "fixed-five", "baseline", index, samples=[81000] * 6, apk=APK_B)
        target = self.root / "fixed-five--candidate--b2" / "result.txt"
        lines = target.read_text(encoding="utf-8").splitlines()
        rewritten = []
        for line in lines:
            if line.startswith(("3\t", "4\t", "5\t", "6\t")):
                parts = line.split("\t")
                parts[6] = "2"          # generation
                line = "\t".join(parts)
            rewritten.append(line)
        target.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
        document = self._assert_refused("generation-change")
        self.assertIn("different (pid, generation, handle) states",
                      "\n".join(document["problems"]))

    def test_a_handle_change_inside_one_batch_is_refused(self) -> None:
        write_campaign(self.root)
        for index in range(1, 4):
            write_batch(self.root, "fixed-five", "candidate", index, samples=[80000] * 6,
                        handle=1)
            write_batch(self.root, "fixed-five", "baseline", index, samples=[81000] * 6, apk=APK_B)
        # Rewrite batch 2 so its samples straddle two handles.
        target = self.root / "fixed-five--candidate--b2" / "result.txt"
        lines = target.read_text(encoding="utf-8").splitlines()
        rewritten = []
        for line in lines:
            if line.startswith("3\t"):
                line = line.rsplit("\t", 1)[0] + "\t9"
            rewritten.append(line)
        target.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
        self._assert_refused("handle-change")

    def test_a_batch_without_apk_hashes_is_refused(self) -> None:
        write_campaign(self.root)
        for index in range(1, 4):
            write_batch(self.root, "fixed-five", "candidate", index, samples=[80000] * 6,
                        write_apk_before=False, write_apk_after=False)
            write_batch(self.root, "fixed-five", "baseline", index, samples=[81000] * 6, apk=APK_B)
        document = self._assert_refused("apk-missing")
        self.assertIn("APK SHA-256 is missing", "\n".join(document["problems"]))

    def test_a_batch_whose_apk_changed_is_refused(self) -> None:
        write_campaign(self.root)
        for index in range(1, 4):
            write_batch(self.root, "fixed-five", "candidate", index, samples=[80000] * 6,
                        apk_after=APK_B if index == 2 else None)
            write_batch(self.root, "fixed-five", "baseline", index, samples=[81000] * 6, apk=APK_B)
        document = self._assert_refused("apk-changed")
        self.assertIn("APK changed during the batch", "\n".join(document["problems"]))

    def test_a_campaign_that_recorded_voids_is_refused(self) -> None:
        write_campaign(self.root, outcomes=["void", "void", "void", "void", "void", "void"])
        for index in range(1, 4):
            write_batch(self.root, "fixed-five", "candidate", index, samples=[80000] * 6)
            write_batch(self.root, "fixed-five", "baseline", index, samples=[81000] * 6, apk=APK_B)
        document = self._assert_refused("recorded-void")
        self.assertIn("campaign file itself records", "\n".join(document["problems"]))

    def test_a_result_row_that_disagrees_with_the_raw_meminfo_is_refused(self) -> None:
        # The raw `dumpsys meminfo` answer is the device's own words. A result row that contradicts
        # it is a number nobody can attribute, even though every other check passes.
        write_campaign(self.root)
        for index in range(1, 4):
            write_batch(self.root, "fixed-five", "candidate", index, samples=[80000] * 6,
                        raw_total_shift=1 if index == 1 else 0)
            write_batch(self.root, "fixed-five", "baseline", index, samples=[81000] * 6, apk=APK_B)
        document = self._assert_refused("raw-mismatch")
        self.assertIn("raw `dumpsys meminfo` answer", "\n".join(document["problems"]))


class TheLegacySamplerCountsInstallsWithoutASlidingWindow(CampaignFixture):
    """A windowed logcat read must not turn "a line scrolled out" into "a rule install landed".

    v0.1.2 recompiles on every launch, so its `compiled N lists:` line sits near the edge of the
    `-t 4000` window. Counting that line made the count *drop* as it aged out, and a batch whose
    rules never changed was voided as "a rule install landed during sample N". The fix compares the
    **set of timestamps** instead of a count: a stamp leaving the window is harmless, a new stamp
    is the event that matters.
    """

    def test_a_stamp_scrolling_out_is_not_an_install(self) -> None:
        # The two sets the sampler compares: an install that was there at the start and is gone now
        # must produce no difference, while a genuinely new stamp must.
        at_start = {"11-14 00:20:01.100", "11-14 00:20:05.200"}
        later_window = {"11-14 00:20:05.200"}
        self.assertEqual(set(later_window) - at_start, set(),
                         "a stamp leaving the window is not a new install")
        later_with_new = {"11-14 00:20:05.200", "11-14 00:22:30.900"}
        self.assertEqual(set(later_with_new) - at_start, {"11-14 00:22:30.900"},
                         "a genuinely new install is detected")

    def test_the_sampler_compares_stamps_not_counts(self) -> None:
        source = (SCRIPTS / "memory_profile.py").read_text(encoding="utf-8")
        self.assertIn("def rule_install_stamps", source)
        self.assertNotIn("def rule_install_count", source,
                         "a count over a sliding window cannot distinguish the two events")
        self.assertIn("new_installs = set(rule_install_stamps()) - installs_at_start", source)


class TheFormalMatrixCannotBeShortened(CampaignFixture):
    """The card fixes two builds x two rule sets x >=3 batches of 6 samples at 60 s.

    The first delivery ran one build on one rule set and called it the campaign. Shortening it is
    legitimate while building the tool, so a plan says so with `diagnostic: true` — and then its
    numbers are never acceptance evidence.
    """

    def _check(self, document: dict) -> int:
        path = self.root / "plan.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return memory_profile.main(["plan-check", "--plan", str(path)])

    def _formal(self) -> dict:
        document = _plan_document()
        document["diagnostic"] = False
        document["builds"]["baseline"]["identities"] = {
            "fixed-five": identity(TOKEN_B, TOKEN_B, TOKEN_B)}
        document["rule_sets"]["default-nine"] = list(memory_profile.RULE_SETS["default-nine"])
        for build in document["builds"].values():
            build["identities"]["default-nine"] = identity(TOKEN_A, TOKEN_A, TOKEN_A)
        return document

    def test_the_full_matrix_is_accepted(self) -> None:
        self.assertEqual(self._check(self._formal()), 0)

    def test_one_build_is_refused(self) -> None:
        document = self._formal()
        document["builds"].pop("baseline")
        self.assertEqual(self._check(document), 2)

    def test_one_rule_set_is_refused(self) -> None:
        document = self._formal()
        document["rule_sets"].pop("default-nine")
        for build in document["builds"].values():
            build["identities"].pop("default-nine", None)
        self.assertEqual(self._check(document), 2)

    def test_a_rule_set_with_the_wrong_lists_is_refused(self) -> None:
        document = self._formal()
        document["rule_sets"]["fixed-five"] = ["adguard-base"]
        self.assertEqual(self._check(document), 2)

    def test_five_samples_or_a_short_interval_is_refused(self) -> None:
        for override in ({"samples": 5}, {"interval": 30}):
            document = self._formal()
            document.update(override)
            self.assertEqual(self._check(document), 2, override)

    def test_the_same_short_matrix_is_accepted_when_declared_diagnostic(self) -> None:
        # The reduction that makes the probe legitimate: it must say so, and then it is a probe.
        document = self._formal()
        document["diagnostic"] = True
        document["builds"].pop("baseline")
        document["rule_sets"] = {"fixed-five": list(memory_profile.FIXED_FIVE)}
        document["builds"]["candidate"]["identities"] = {
            "fixed-five": identity(TOKEN_A, TOKEN_A, TOKEN_A)}
        self.assertEqual(self._check(document), 0)


class TheRunnerComposesAsProgram(CampaignFixture):
    """`run` as a program: the failures a unit test of the statistics cannot see.

    Both cases here are defects that only appeared once the runner actually drove a batch tool, and
    both left every test above green:

    * a `with ... as out` shadowed the campaign's own output directory, so batch 2 died with
      `unsupported operand type(s) for /: '_io.TextIOWrapper' and 'str'`;
    * the batch tool prints its `## median` on **stdout**, not into the file it writes, so a runner
      that kept only the file produced "samples but no median" for every batch — and `recompute`
      correctly voided all of them.

    The stand-in below reproduces that split exactly: rows into the file, median onto stdout.
    """

    #: A valid 20-byte ZShield envelope is not needed — the stub writes a plain text result file.
    #: A stand-in for `pss_idle.sh` that writes the *whole* shape the validator now requires: rows,
    #: one raw `dumpsys meminfo` answer per sample, both APK hashes, and the median on stdout.
    STUB = """#!/usr/bin/env bash
set -u
label="$1"; shift
out=""
while [ $# -gt 0 ]; do
  case "$1" in --out) out="$2"; shift 2;; *) shift;; esac
done
{
  printf '## samples (raw dumpsys kB)\n'
  printf '1\t0\t90000\t5000\t60000\t4242\t1\t1\n'
  printf '2\t60\t90002\t5000\t60000\t4242\t1\t1\n'
  printf '3\t120\t90004\t5000\t60000\t4242\t1\t1\n'
  printf '4\t180\t90006\t5000\t60000\t4242\t1\t1\n'
  printf '5\t240\t90008\t5000\t60000\t4242\t1\t1\n'
  printf '6\t300\t90010\t5000\t60000\t4242\t1\t1\n'
  printf '# effective rule content: %s\n' "$STUB_TOKENS"
} > "$out/pss-$label.txt"
mkdir -p "$out/pss-$label.raw"
i=1
for value in 90000 90002 90004 90006 90008 90010; do
  printf '** MEMINFO in pid 4242 [top.zztweb.zshield] **\n        TOTAL PSS:    %s\n' "$value" \
    > "$out/pss-$label.raw/meminfo-$i.txt"
  i=$((i+1))
done
printf '%s  top.zztweb.zshield\n' "$STUB_APK" > "$out/apk-sha256-before.txt"
printf '%s  top.zztweb.zshield\n' "$STUB_APK" > "$out/apk-sha256-after.txt"
echo '## median 90005 kB = 87.895507813 MiB (min 90000 kB, max 90010 kB)'
"""

    ADB = """#!/usr/bin/env bash
case "$*" in
  *"pm path"*) echo "package:/data/app/base.apk" ;;
  *sha256sum*) echo "$STUB_APK  /data/app/base.apk" ;;
  *install*) echo Success ;;
esac
"""

    def test_two_batches_run_and_the_stdout_median_is_kept(self) -> None:
        stub_dir = self.root / "bin"
        stub_dir.mkdir()
        stub = stub_dir / "pss_idle.sh"
        stub.write_text(self.STUB, encoding="utf-8")
        stub.chmod(0o755)
        adb = stub_dir / "adb"
        adb.write_text(self.ADB, encoding="utf-8")
        adb.chmod(0o755)

        tokens = f"dns={TOKEN_A} engine={TOKEN_A} extras={TOKEN_A}"
        saved = {"PSS_IDLE": memory_profile.PSS_IDLE, "PATH": os.environ.get("PATH", ""),
                 "verify": memory_profile.verify_selection_identity}
        memory_profile.PSS_IDLE = stub
        # The identity precheck talks to a real phone; a stand-in batch tool has no tunnel to start,
        # so it is replaced rather than left to spin for 90 s against a device that is not there. What
        # is under test here is the runner's composition — running every batch, keeping the stdout
        # median — not the precheck, which has its own coverage below.
        memory_profile.verify_selection_identity = lambda serial, package, expected, batch_dir: (
            expected or tokens)
        # The preparation phase now takes the canonical device lock before it writes anything. A
        # stand-in batch tool has no phone, so the lock is stood in for as always grantable — the
        # lock's own behaviour (refuse when another owner holds it) is covered separately by
        # `ThePreparationPhaseNeedsTheLock`.
        memory_profile.DeviceLock = _AlwaysGrantedLock
        os.environ["PATH"] = f"{stub_dir}{os.pathsep}{saved['PATH']}"
        os.environ["STUB_TOKENS"] = tokens
        os.environ["STUB_APK"] = APK_A
        try:
            # `select: none`: this stand-in is a batch tool, not a phone, so there is no filters
            # screen to drive. The per-batch identity check still runs, which is the point being
            # tested here.
            document = _plan_document(batches=3, samples=6)
            document["select"] = "none"
            document["builds"].pop("baseline", None)
            plan_file = self.root / "plan.json"
            plan_file.write_text(json.dumps(document), encoding="utf-8")
            out_dir = self.root / "campaign"
            # The CLI `run` refuses until the transaction protocol is accepted, so the runner body
            # is driven directly. Composition — running every batch, keeping the stdout median — is
            # what this test covers, and it must keep working for when the gate opens.
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                status = memory_profile.device_campaign_draft(
                    memory_profile.load_plan(plan_file), out_dir, "MYS-2840",
                    STUB_SERIAL, memory_profile.DEFAULT_PACKAGE)
            self.assertEqual(status, 0, "both batches must run and succeed")

            second = out_dir / "fixed-five--candidate--b3" / "result.txt"
            self.assertTrue(second.is_file(),
                            "the third batch ran; a shadowed output directory crashed it before")
            self.assertIn("## median 90005 kB", second.read_text(encoding="utf-8"),
                          "the median printed on stdout is kept in the result file")

            status, output = recompute(out_dir)
            document = json.loads(output)
            cell = next(row for row in document["cells"] if row["build"] == "candidate")
            self.assertEqual(cell["ok_batches"], 3)
            self.assertEqual(cell["centre_kb"], 90005.0)
            # The samples are valid evidence; the campaign is not formal evidence, and this is the
            # draft's own remaining gap rather than a test artifact: it writes no input records and
            # no per-attempt timing yet. The gate stays shut until it does.
            self.assertTrue(document["layer"]["samples_valid"], output)
            self.assertFalse(document["layer"]["inputs_proven"])
            self.assertFalse(document["layer"]["order_proven"])
            self.assertNotEqual(status, 0, "an unproven campaign is not acceptance evidence")
            self.assertEqual(document["comparisons"], [])
        finally:
            memory_profile.PSS_IDLE = saved["PSS_IDLE"]
            memory_profile.verify_selection_identity = saved["verify"]
            os.environ["PATH"] = saved["PATH"]
            for name in ("STUB_TOKENS", "STUB_APK"):
                os.environ.pop(name, None)


class TheSwitchRowParserReadsTheAppsOwnDump(unittest.TestCase):
    """`find_row` must find a list's switch, and must not confuse "off" with "scrolled away"."""

    #: A slice of the filters screen as `uiautomator dump` writes it: a list name, its detail line,
    #: and the switch the app draws on the trailing edge (`FiltersScreen.kt` `FilterRow`).
    DUMP = (
        '<node index="0" text="" class="android.widget.ScrollView" bounds="[0,0][1080,1634]">'
        '<node text="AdGuard 基础过滤" class="android.widget.TextView" bounds="[88,1474][463,1540]" />'
        '<node text="55,689 条规则 · 1 天前更新" class="android.widget.TextView" '
        'bounds="[88,1540][544,1595]" />'
        '<node text="" class="android.view.View" checkable="true" checked="true" '
        'bounds="[849,1436][992,1590]" />'
        '<node text="EasyList" class="android.widget.TextView" bounds="[88,384][264,450]" />'
        '<node text="未启用" class="android.widget.TextView" bounds="[88,450][205,505]" />'
        '<node text="" class="android.view.View" checkable="true" checked="false" '
        'bounds="[849,378][992,510]" />'
        '</node>'
    )

    def test_an_enabled_row_is_found_as_checked(self) -> None:
        state = memory_profile.find_row(self.DUMP, "AdGuard 基础过滤")
        self.assertIsNotNone(state)
        checked, bounds = state
        self.assertTrue(checked)
        self.assertEqual(bounds, (849, 1436, 992, 1590))

    def test_a_disabled_row_is_found_as_unchecked(self) -> None:
        state = memory_profile.find_row(self.DUMP, "EasyList")
        self.assertIsNotNone(state)
        self.assertFalse(state[0])

    def test_a_row_that_is_not_in_the_dump_is_absent_not_off(self) -> None:
        # The distinction the caller's toggling loop depends on: "not visible" would otherwise read
        # as "switch it on", and the loop would tap a row that is not there.
        self.assertIsNone(memory_profile.find_row(self.DUMP, "uBlock 过滤器"))

    def test_the_switch_is_matched_to_its_own_row(self) -> None:
        # Two rows, two switches: taking the first checkable node in the dump would move EasyList's
        # switch when the caller asked about the base list.
        base = memory_profile.find_row(self.DUMP, "AdGuard 基础过滤")
        easy = memory_profile.find_row(self.DUMP, "EasyList")
        self.assertNotEqual(base[1], easy[1])

    def test_a_name_with_regex_metacharacters_is_matched_literally(self) -> None:
        # Catalog names contain `$`, `(`, `)` and `.`; a regex built from one would either miss or
        # match the wrong row.
        xml = ('<node text="uBlock (测试) $1.0" class="android.widget.TextView" '
               'bounds="[88,100][400,160]" />'
               '<node text="" class="android.view.View" checkable="true" checked="true" '
               'bounds="[849,100][992,160]" />')
        state = memory_profile.find_row(xml, "uBlock (测试) $1.0")
        self.assertIsNotNone(state)
        self.assertTrue(state[0])


if __name__ == "__main__":
    unittest.main()


class TheFormalVerdictNeedsAllThreeLayers(CampaignFixture):
    """A formal PASS and a version difference require samples, inputs AND order to be proven.

    Every case here is one the second review reproduced against the delivered bundle, plus the ones
    the card asks for explicitly: a campaign that re-ran its batches after the fact, one that forged
    the plan's order, one whose samples were a second apart, one whose inputs were never recorded,
    and a legacy build asked to take part in a formal equivalence comparison it cannot support.
    """

    def _formal(self, **kwargs) -> Path:
        """A campaign whose three layers all hold: the positive control."""
        kwargs.setdefault("diagnostic", False)
        kwargs.setdefault("builds", {"candidate": APK_A, "v012": APK_B})
        kwargs.setdefault("legacy", set())
        # The card's formal matrix needs both rule sets; a one-rule-set campaign is a probe by
        # definition, and `plan-check` would refuse it as formal.
        kwargs.setdefault("rule_sets", {
            "fixed-five": list(memory_profile.FIXED_FIVE),
            "default-nine": list(memory_profile.RULE_SETS["default-nine"]),
        })
        # The attempt stamps and the batches' own stamps must describe the same runs, or the
        # cross-check correctly reports that the record does not describe the batch.
        starts: dict[tuple[str, str, int], str] = {}
        for rule_set, hour in (("fixed-five", 0), ("default-nine", 2)):
            for index in range(1, 4):
                starts[("candidate", rule_set, index)] = f"2026-11-13T{hour:02d}:{(index - 1) * 20:02d}:00Z"
                starts[("v012", rule_set, index)] = (
                    f"2026-11-13T{hour:02d}:{(index - 1) * 20 + 10:02d}:00Z")
        kwargs.setdefault("batch_starts", starts)
        write_campaign(self.root, **kwargs)
        for (build_name, rule_set, index), started in starts.items():
            values = {"fixed-five": {"candidate": 89000, "v012": 88500},
                      "default-nine": {"candidate": 99000, "v012": 98500}}[rule_set][build_name]
            write_batch(self.root, rule_set, build_name, index,
                        samples=[values + index] * 6,
                        apk=APK_A if build_name == "candidate" else APK_B,
                        content=(LEGACY_TOKEN if build_name in kwargs.get("legacy", set())
                                 else identity(TOKEN_A, TOKEN_A, TOKEN_A)),
                        started_at=started)
        return self.root

    def _run(self) -> tuple[int, dict]:
        status, output = recompute(self.root)
        return status, (json.loads(output) if output.strip() else {})

    # ---- the positive control ----

    def test_a_complete_provable_campaign_gets_a_formal_verdict(self) -> None:
        write_formal_campaign(self.root)
        status, document = self._run()
        self.assertEqual(status, 0, document.get("problems"))
        layer = document["layer"]
        self.assertTrue(layer["samples_valid"])
        self.assertTrue(layer["inputs_proven"])
        self.assertTrue(layer["order_proven"])
        self.assertTrue(layer["formally_comparable"])
        self.assertEqual({entry["rule_set"] for entry in document["comparisons"]},
                         {"fixed-five", "default-nine"}, "one comparison per rule set")
        verdicts = {row["build"]: row["verdict"] for row in document["threshold"]}
        self.assertEqual(verdicts["candidate"], "FAIL", "89 001 kB is over 84.6 MiB")
        self.assertEqual(len(document["executed_order"]), 12)

    # ---- order / time evidence ----

    def test_missing_attempts_withhold_the_formal_comparison(self) -> None:
        self._formal(record_attempts=False)
        status, document = self._run()
        self.assertNotEqual(status, 0)
        self.assertEqual(document["comparisons"], [])
        self.assertFalse(document["layer"]["order_proven"])
        self.assertTrue(any("no `attempts` list" in problem
                            for problem in document["order_problems"]))

    def test_a_rerun_recorded_out_of_order_withholds_the_comparison(self) -> None:
        # The delivered bundle's real shape: the six v0.1.2 batches ran *after* all six candidate
        # batches. The attempt stamps say so even though the plan's `order` claims alternation.
        self._formal()
        record_path = self.root / "campaign.json"
        record = json.loads(record_path.read_text())
        for entry in record["attempts"]:
            if entry["cell"][0] == "v012":
                entry["started_at"] = "2026-11-13T01:30:00Z"
                entry["finished_at"] = "2026-11-13T01:40:00Z"
        record_path.write_text(json.dumps(record))
        status, document = self._run()
        self.assertNotEqual(status, 0)
        self.assertEqual(document["comparisons"], [], "a non-alternating run gets no formal comparison")
        self.assertFalse(document["layer"]["order_proven"])
        joined = "\n".join(document["order_problems"])
        self.assertIn("consecutively", joined)

    def test_a_forged_plan_order_does_not_rescue_the_order_claim(self) -> None:
        # `order` in the campaign file is a claim; the attempts are the evidence. Rewriting `order`
        # to match the plan must not turn a non-alternating run into a valid one.
        self._formal()
        record_path = self.root / "campaign.json"
        record = json.loads(record_path.read_text())
        for entry in record["attempts"]:
            if entry["cell"][0] == "v012":
                entry["started_at"] = "2026-11-13T01:30:00Z"
                entry["finished_at"] = "2026-11-13T01:40:00Z"
        record["order"] = [["v012", "fixed-five", i] for i in (1, 2, 3)] + \
                          [["candidate", "fixed-five", i] for i in (1, 2, 3)]
        record_path.write_text(json.dumps(record))
        status, document = self._run()
        self.assertNotEqual(status, 0)
        self.assertEqual(document["comparisons"], [])
        self.assertTrue(any("consecutively" in problem for problem in document["order_problems"]))

    def test_one_second_samples_withhold_the_comparison(self) -> None:
        self._formal()
        for result in self.root.glob("*/result.txt"):
            lines = []
            for line in result.read_text().splitlines():
                if re.match(r"^\d+\t", line):
                    parts = line.split("\t")
                    parts[1] = parts[0]
                    line = "\t".join(parts)
                lines.append(line)
            result.write_text("\n".join(lines) + "\n")
        status, document = self._run()
        self.assertNotEqual(status, 0)
        self.assertEqual(document["comparisons"], [])
        self.assertTrue(any("s apart but the batch declares" in problem
                            for problem in document["order_problems"]))

    def test_a_rerun_that_overwrote_an_earlier_batch_cannot_restore_the_order(self) -> None:
        # The delivered bundle's actual defect: the six v0.1.2 batches were re-run *after* the whole
        # candidate block and written into the same directories, so the directories' contents are the
        # re-run's while the plan's `order` still claims alternation. What exposes it is that the
        # result file's own `at=` stamp and the attempt record disagree with the claimed slot: the
        # batch that "ran second" carries a start later than the batch that "ran last".
        self._formal()
        rerun = "2026-11-13T03:40:00Z"
        for index in range(1, 4):
            for rule_set in ("fixed-five", "default-nine"):
                batch_dir = self.root / f"{rule_set}--v012--b{index}"
                result = batch_dir / "result.txt"
                lines = [re.sub(r"at=\S+", f"at={rerun}", line) if line.startswith("#") else line
                         for line in result.read_text().splitlines()]
                result.write_text("\n".join(lines) + "\n")
        status, document = self._run()
        self.assertNotEqual(status, 0)
        self.assertEqual(document["comparisons"], [],
                         "a re-run stuffed into the past slot is not an alternating measurement")
        self.assertTrue(document["order_problems"], "the disagreement must be stated, not ignored")
        self.assertTrue(any("does not describe this batch" in problem
                            or "result file says" in problem
                            for problem in document["order_problems"]),
                        document["order_problems"])

    def test_reversed_sample_times_withhold_the_comparison(self) -> None:
        # A batch whose elapsed column runs backwards is not one clock reading of one process. The
        # gaps are all >= 60 s, so only the monotonicity rule can catch it — which is why it exists
        # separately from the interval rule.
        self._formal()
        for result in self.root.glob("*/result.txt"):
            lines = [line for line in result.read_text().splitlines()]
            rows = [line for line in lines if re.match(r"^\d+\t", line)]
            other = [line for line in lines if not re.match(r"^\d+\t", line)]
            rewritten = []
            for line in rows:
                parts = line.split("\t")
                parts[1] = str((len(rows) - int(parts[0])) * 60)
                rewritten.append("\t".join(parts))
            result.write_text("\n".join(other + rewritten) + "\n")
        status, document = self._run()
        self.assertNotEqual(status, 0)
        self.assertTrue(any("strictly increase" in problem
                            for problem in document["order_problems"]),
                        document["order_problems"])

    def test_overlapping_attempts_withhold_the_comparison(self) -> None:
        # A batch lasts ~8 min in the fixture, so starting the next one 2 min later means it began
        # while the previous was still sampling — two runs on one phone at once. The batch stamps are
        # squeezed to match, because the attempt record is cross-checked against them.
        self._formal()
        record_path = self.root / "campaign.json"
        record = json.loads(record_path.read_text())
        base = memory_profile.parse_stamp("2026-11-13T00:00:00Z")
        for position, entry in enumerate(record["attempts"]):
            started = base + datetime.timedelta(minutes=2 * position)
            entry["started_at"] = started.strftime("%Y-%m-%dT%H:%M:%SZ")
            entry["finished_at"] = (started + datetime.timedelta(minutes=8)).strftime(
                "%Y-%m-%dT%H:%M:%SZ")
        record_path.write_text(json.dumps(record))
        for (build_name, rule_set, index), entry in zip(
                [(e["cell"][0], e["cell"][1], e["index"]) for e in record["attempts"]],
                record["attempts"]):
            batch_dir = self.root / f"{rule_set}--{build_name}--b{index}"
            lines = (batch_dir / "result.txt").read_text().splitlines()
            lines[0] = (f"# idle PSS — label={rule_set}-{build_name}-b{index} "
                        f"at={entry['started_at']}")
            (batch_dir / "result.txt").write_text("\n".join(lines) + "\n")
        status, document = self._run()
        self.assertNotEqual(status, 0)
        self.assertEqual(document["comparisons"], [])
        self.assertTrue(any("overlaps" in problem for problem in document["order_problems"]),
                        document["order_problems"])

    def test_attempt_stamps_that_disagree_with_the_result_file_withhold_the_comparison(self) -> None:
        self._formal()
        record_path = self.root / "campaign.json"
        record = json.loads(record_path.read_text())
        record["attempts"][0]["started_at"] = "2026-11-13T05:00:00Z"
        record["attempts"][0]["finished_at"] = "2026-11-13T05:08:00Z"
        record_path.write_text(json.dumps(record))
        status, document = self._run()
        self.assertNotEqual(status, 0)
        self.assertTrue(any("does not describe this batch" in problem
                            for problem in document["order_problems"]))

    def test_an_attempt_without_an_identity_withholds_the_comparison(self) -> None:
        self._formal()
        record_path = self.root / "campaign.json"
        record = json.loads(record_path.read_text())
        record["attempts"][0].pop("attempt_id", None)
        record_path.write_text(json.dumps(record))
        status, document = self._run()
        self.assertNotEqual(status, 0)
        self.assertEqual(document["comparisons"], [])
        self.assertTrue(any("attempt_id" in problem for problem in document["order_problems"]))

    # ---- input evidence ----

    def test_missing_input_records_withhold_the_formal_comparison(self) -> None:
        self._formal(inputs=False)
        status, document = self._run()
        self.assertNotEqual(status, 0)
        self.assertEqual(document["comparisons"], [])
        self.assertFalse(document["layer"]["inputs_proven"])
        self.assertTrue(any("no input record" in problem for problem in document["input_problems"]))

    def test_an_input_record_missing_a_content_hash_withholds_the_comparison(self) -> None:
        self._formal()
        record_path = self.root / "campaign.json"
        record = json.loads(record_path.read_text())
        record["plan"]["inputs"]["candidate/fixed-five"]["user_rules_sha256"] = ""
        record_path.write_text(json.dumps(record))
        status, document = self._run()
        self.assertNotEqual(status, 0)
        self.assertEqual(document["comparisons"], [])
        self.assertTrue(any("user_rules_sha256" in problem
                            for problem in document["input_problems"]))

    def test_an_input_record_with_the_wrong_lists_withholds_the_comparison(self) -> None:
        self._formal()
        record_path = self.root / "campaign.json"
        record = json.loads(record_path.read_text())
        record["plan"]["inputs"]["candidate/fixed-five"]["lists"] = [
            {"id": "adguard-base", "enabled": True, "sha256": "a" * 64}]
        record_path.write_text(json.dumps(record))
        status, document = self._run()
        self.assertNotEqual(status, 0)
        self.assertEqual(document["comparisons"], [])
        self.assertTrue(any("did not measure the declared lists" in problem
                            for problem in document["input_problems"]))

    def test_a_legacy_build_claiming_artifact_hashes_withholds_the_comparison(self) -> None:
        # v0.1.2 prints byte counts, not content hashes; a hash recorded for it did not come from the
        # device, and a formal equivalence comparison may not rest on it.
        self._formal(legacy={"v012"})
        record_path = self.root / "campaign.json"
        record = json.loads(record_path.read_text())
        record["plan"]["inputs"]["v012/fixed-five"]["loaded_artifacts_sha256"] = {
            "dns": TOKEN_A, "engine": TOKEN_A, "extras": TOKEN_A}
        record_path.write_text(json.dumps(record))
        status, document = self._run()
        self.assertNotEqual(status, 0)
        self.assertEqual(document["comparisons"], [])
        self.assertTrue(any("cannot produce a content identity" in problem
                            for problem in document["input_problems"]))

    def test_a_legacy_cell_without_artifact_hashes_blocks_only_the_formal_comparison(self) -> None:
        # The legacy record legitimately lacks `loaded_artifacts_sha256`. Its *sample numbers* are
        # still valid and are shown; what cannot be stated is a formal equivalence comparison.
        self._formal(legacy={"v012"})
        status, document = self._run()
        self.assertNotEqual(status, 0)
        self.assertTrue(document["layer"]["samples_valid"])
        self.assertFalse(document["layer"]["inputs_proven"])
        self.assertTrue(any("loaded_artifacts_sha256" in problem
                            for problem in document["input_problems"]))
        # ... and the numbers are still printed, marked diagnostic rather than formal.
        row = next(row for row in document["cells"] if row["build"] == "v012")
        self.assertIsNotNone(row["centre_mib"])
        self.assertTrue(all(entry["verdict"] != "PASS" for entry in document["threshold"]))

    # ---- threshold scope ----

    def test_only_the_fixed_five_has_a_threshold(self) -> None:
        write_campaign(
            self.root, diagnostic=False,
            builds={"candidate": APK_A, "v012": APK_B}, legacy={"v012"},
            rule_sets={"fixed-five": list(memory_profile.FIXED_FIVE),
                       "default-nine": list(memory_profile.RULE_SETS["default-nine"])})
        for rule_set in ("fixed-five", "default-nine"):
            for index in range(1, 4):
                write_batch(self.root, rule_set, "candidate", index, samples=[89000] * 6,
                            started_at=f"2026-11-13T0{index}:00:00Z")
                write_batch(self.root, rule_set, "v012", index, samples=[88500] * 6,
                            apk=APK_B, content=LEGACY_TOKEN,
                            started_at=f"2026-11-13T0{index}:30:00Z")
        status, document = self._run()
        self.assertEqual(document["thresholds_mib"], {"fixed-five": 84.6})
        self.assertEqual({row["rule_set"] for row in document["threshold"]}, {"fixed-five"},
                         "the nine-list set has no gate and must not borrow the five-list one")

    def test_a_diagnostic_campaign_states_no_formal_verdict(self) -> None:
        self._formal(diagnostic=True)
        status, document = self._run()
        # A diagnostic campaign keeps its numbers but is not acceptance data, so its exit status
        # says so: a shell caller must not read it as evidence just because the tool ran.
        self.assertNotEqual(status, 0, "a diagnostic campaign is not acceptance evidence")
        self.assertTrue(document["layer"]["diagnostic"])
        self.assertEqual(document["comparisons"], [])
        self.assertEqual({row["verdict"] for row in document["threshold"]}, {"DIAGNOSTIC"})
        self.assertTrue(document["comparisons_withheld"])


class TheRunEntryRefusesBeforeTouchingTheDevice(CampaignFixture):
    """`run` must refuse before any adb call until the transaction protocol is accepted.

    The card is unambiguous: the preparation/sampling/recovery transaction is not complete (the
    serial and package were not passed to the sampler, there is a lock gap between preparation and
    sampling, and there is no recovery transaction), and until it is, `run` has to say so and stop.
    A silent degradation to "best effort" is exactly what would put another task's phone at risk.
    """

    def _plan(self) -> Path:
        path = self.root / "plan.json"
        document = _plan_document()
        document["diagnostic"] = True
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_run_refuses_and_calls_no_external_command(self) -> None:
        calls: list[str] = []

        def spy(name: str):
            def inner(*args, **kwargs):
                calls.append(name)
                raise AssertionError(f"{name} must not be called by a refusing run")
            return inner

        saved = {name: getattr(memory_profile, name)
                 for name in ("device_apk_sha", "select_rule_set",
                              "verify_selection_identity", "DeviceLock")}
        saved_run = subprocess.run
        for name in saved:
            setattr(memory_profile, name, spy(name))
        memory_profile.subprocess.run = spy("subprocess.run")
        try:
            out = self.root / "out"
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                status = memory_profile.main(["run", "--plan", str(self._plan()),
                                              "--out", str(out), "--issue", "MYS-2840"])
            self.assertNotEqual(status, 0, "run must refuse until the transaction protocol is done")
            self.assertEqual(calls, [], f"nothing external may run: {calls}")
            message = err.getvalue()
            self.assertIn("事务协议", message)
            self.assertIn("recompute", message, "the refusal tells the reader what still works")
            self.assertFalse(out.exists(), "a refused run creates no campaign directory")
        finally:
            for name, function in saved.items():
                setattr(memory_profile, name, function)
            memory_profile.subprocess.run = saved_run

    def test_plan_check_and_recompute_still_work(self) -> None:
        # The refusal is scoped to `run`; the offline paths must keep working.
        self.assertTrue(self._plan().is_file())
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(memory_profile.main(["plan-check", "--plan", str(self._plan())]), 0)
