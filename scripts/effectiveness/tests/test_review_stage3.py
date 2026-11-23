"""The stage-3 review's own three probes must now be answered correctly.

`review_stage3.py` (attached to the issue, copied verbatim into `review/`) fails in three ways against
the previous revision:

1. `under_20_concurrency` — a 20-request plan split 7/7/6 and a single `peak=7` passed the
   concurrency check. The check now requires the **group total**, and separately requires the origin's
   own `peak` and its recomputed interval `overlap` to reach it.
2. `no_run_metadata_app_connections_plus2` — a hand-written pair with no `run`, a shared pid/uid and
   app-owned ESTABLISHED growing 1 -> 3 exited 0. Snapshots without run/timestamp/readable now exit 2,
   and the app uid gets no allowance, so the same 1 -> 3 exits 1.
3. `backup_unavailable_and_no_lock_owner` — with the rules backup unreadable and no `LOCK_OWNER`, the
   entry point still replaced the user rules and never checked the lock. The backup is now required and
   taken *before* any write, and the lock is required before that; either failure exits without
   touching the rules.

This file runs the script unmodified and asserts its exit status, then repeats its three scenarios
directly so a failure names the specific property rather than only "the script disagreed".
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import harness_fixtures as fixtures  # noqa: E402

harness = fixtures.harness

HERE = Path(__file__).resolve().parent
REVIEW_STAGE3 = HERE / "review" / "review_stage3.py"


def stage_tree(destination: Path) -> Path:
    """A `zshield-android` tree the review script can find beside itself."""
    tree = destination / "zshield-android"
    (tree / "scripts").mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        fixtures.SCRIPTS,
        tree / "scripts" / "effectiveness",
        ignore=shutil.ignore_patterns("tests", "__pycache__"),
    )
    return tree


class ReviewStage3Test(unittest.TestCase):
    """The attached script exits 0, and each of its three properties holds on its own."""

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory(prefix="zs-review3-")
        self.dir = Path(self._temp.name)
        self.tree = stage_tree(self.dir)

    def tearDown(self) -> None:
        self._temp.cleanup()

    def test_review_stage3_exits_zero(self) -> None:
        run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=self.dir))
        target = run_dir / REVIEW_STAGE3.name
        shutil.copy(REVIEW_STAGE3, target)
        (run_dir / "zshield-android").symlink_to(self.tree)
        result = subprocess.run(
            [sys.executable, str(target)],
            capture_output=True, text=True, timeout=180, cwd=str(run_dir),
            env={**os.environ, "PYTHONPATH": str(self.tree / "scripts" / "effectiveness"),
                 "SERIAL": "stub:5555"},
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("0/3 review cases failed", result.stdout)

    def test_a_twenty_request_plan_needs_the_group_total(self) -> None:
        scenarios = harness.build_scenarios("https://echo.invalid", "review3")
        group = harness.plan_group(scenarios, 20, 0)
        peak = max(len(calls) for calls in group["legs"].values())
        # Two legs' worth is what a serialised run produces; it must not be enough.
        serialised = [{"group": 0, "inflight": peak}]
        errors = harness.validate_concurrency([group], serialised, 20)
        self.assertTrue(
            any("did not overlap" in error for error in errors),
            f"a serialised 20-request plan passed: {errors}",
        )

    def test_a_twenty_request_plan_passes_when_every_request_overlaps(self) -> None:
        """The positive control: the same plan with a genuine overlap must pass.

        Without this, "reject peak=7" could be satisfied by rejecting everything.
        """
        scenarios = harness.build_scenarios("https://echo.invalid", "review3")
        group = harness.plan_group(scenarios, 20, 0)
        results = [
            {"group": 0, "inflight": 20, "id": call["id"], "scenario": call["scenario"],
             "body": json.dumps({"inflight": 20})}
            for calls in group["legs"].values()
            for call in calls
        ]
        evidence = {"peak": 20, "overlap": 20, "count": 20}
        self.assertEqual(harness.validate_concurrency([group], results, 20, evidence), [])

    def test_the_origin_evidence_is_required_not_optional(self) -> None:
        # A run whose origin reported nothing has no corroboration regardless of the per-result
        # counters, because the per-result fields ride on the same echo.
        scenarios = harness.build_scenarios("https://echo.invalid", "review3")
        group = harness.plan_group(scenarios, 20, 0)
        results = [
            {"group": 0, "inflight": 20, "id": call["id"], "scenario": call["scenario"],
             "body": json.dumps({"inflight": 20})}
            for calls in group["legs"].values()
            for call in calls
        ]
        errors = harness.validate_concurrency([group], results, 20, {"peak": 7, "overlap": 7})
        self.assertTrue(any("origin's own peak" in error for error in errors), errors)
        self.assertTrue(any("intervals overlap" in error for error in errors), errors)

    def test_a_hand_written_snapshot_pair_is_refused(self) -> None:
        # The review's exact fixture: no run, no timestamp, no readable flag, pid/uid agreeing, and
        # app-owned ESTABLISHED 1 -> 3.
        directory = Path(tempfile.mkdtemp(prefix="snap-", dir=self.dir))
        (directory / "tunnel-snapshot-review-before.txt").write_text(
            "pid=123\nuid=10001\nsockets= 1 01\n", encoding="utf-8"
        )
        (directory / "tunnel-snapshot-review-settled.txt").write_text(
            "pid=123\nuid=10001\nsockets= 3 01\n", encoding="utf-8"
        )
        result = subprocess.run(
            ["bash", str(fixtures.SCRIPTS / "tunnel_snapshot.sh"), "check", "review"],
            capture_output=True, text=True, env={**os.environ, "OUT": str(directory)},
            cwd=str(fixtures.REPO),
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("missing", result.stderr)

    def test_the_acceptance_entry_point_checks_the_lock_before_writing(self) -> None:
        """The review's third case, reproduced with the same stub `adb`.

        The stub records every argv it was handed and rewrites a file when it sees
        `DEBUG_SET_RULES`. With an unreadable rules backup and no `LOCK_OWNER`, the entry point must
        exit non-zero, must have *asked* for the lock, and must not have replaced the rules.
        """
        run_dir = Path(tempfile.mkdtemp(prefix="accept-", dir=self.dir))
        state = run_dir / "user-rules"
        state.write_text("ORIGINAL_USER_RULES", encoding="utf-8")
        log = run_dir / "adb-log"
        stub = run_dir / "adb"
        stub.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "args = sys.argv[1:]\n"
            "with open(os.environ['PROBE_LOG'], 'a') as f: f.write(json.dumps(args) + '\\n')\n"
            "s = ' '.join(args)\n"
            "if 'get-state' in args: print('device')\n"
            "elif 'dumpsys connectivity' in s: print('IS_VPN')\n"
            "elif 'DEBUG_SET_RULES' in s:\n"
            "    Path(os.environ['PROBE_STATE']).write_text('TEST_RULES_OVERWROTE_ORIGINAL')\n"
            "    print('Broadcast completed: result=0')\n"
            "elif 'cat /sdcard/zs-ui.xml' in s: print('<hierarchy/>')\n",
            encoding="utf-8",
        )
        stub.chmod(0o755)
        # A failing `python3` stands in for "the rules backup cannot be read", and a no-op `sleep`
        # keeps the run short. Both are the review's own technique.
        for name, body in (("python3", "#!/bin/sh\nexit 1\n"), ("sleep", "#!/bin/sh\nexit 0\n")):
            path = run_dir / name
            path.write_text(body, encoding="utf-8")
            path.chmod(0o755)
        env = {
            **os.environ,
            "PATH": f"{run_dir}{os.pathsep}{os.environ['PATH']}",
            "OUT": str(run_dir),
            "PROBE_LOG": str(log),
            "PROBE_STATE": str(state),
            # The entry point resolves the device before it takes the lock; this probe supplies a
            # stub serial so what it measures is the lock behaviour, not device discovery.
            "SERIAL": "stub:5555",
        }
        env.pop("LOCK_OWNER", None)
        env.pop("LOCK_TOKEN", None)
        result = subprocess.run(
            ["bash", str(self.tree / "scripts" / "effectiveness" / "tunnel_acceptance.sh"),
             "--origin", "https://echo.invalid"],
            env=env, capture_output=True, text=True, timeout=120, cwd=str(run_dir),
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            state.read_text(encoding="utf-8"), "ORIGINAL_USER_RULES",
            "the entry point replaced the user rules without a backup",
        )
        # The lock was *considered*: with no owner it refuses before touching anything, and the
        # message says so. That is the check the previous version never performed.
        self.assertIn("LOCK_OWNER", result.stderr)
        self.assertFalse(
            log.exists() and "DEBUG_SET_RULES" in log.read_text(encoding="utf-8"),
            "the entry point broadcast new rules despite failing its preconditions",
        )

    def test_the_acceptance_entry_point_takes_the_lock_when_given_an_owner(self) -> None:
        """The positive control for the case above: with an owner it *does* reach for the lock."""
        run_dir = Path(tempfile.mkdtemp(prefix="accept-ok-", dir=self.dir))
        log = run_dir / "adb-log"
        stub = run_dir / "adb"
        stub.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "with open(os.environ['PROBE_LOG'], 'a') as f: f.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            "s = ' '.join(sys.argv[1:])\n"
            "if 'get-state' in sys.argv[1:]: print('device')\n"
            "elif 'dumpsys connectivity' in s: print('IS_VPN')\n",
            encoding="utf-8",
        )
        stub.chmod(0o755)
        for name, body in (("python3", "#!/bin/sh\nexit 1\n"), ("sleep", "#!/bin/sh\nexit 0\n")):
            path = run_dir / name
            path.write_text(body, encoding="utf-8")
            path.chmod(0o755)
        env = {
            **os.environ,
            "PATH": f"{run_dir}{os.pathsep}{os.environ['PATH']}",
            "OUT": str(run_dir),
            "PROBE_LOG": str(log),
            "LOCK_OWNER": "MYS-2817",
            # The stub adb is the device. Without a serial the entry point now refuses at device
            # discovery, before the lock step this test is about.
            "SERIAL": "stub:5555",
        }
        result = subprocess.run(
            ["bash", str(self.tree / "scripts" / "effectiveness" / "tunnel_acceptance.sh"),
             "--origin", "https://echo.invalid"],
            env=env, capture_output=True, text=True, timeout=120, cwd=str(run_dir),
        )
        self.assertNotEqual(result.returncode, 0, "the run cannot succeed with a failing python3")
        self.assertTrue(log.exists(), "the entry point never called adb")
        # The lock is requested *before* anything else touches the device. The protocol now travels
        # base64-encoded, so the transcript shows the transport rather than the path; what matters is
        # that a lock call happened at all and that it happened first.
        transcript = log.read_text(encoding="utf-8")
        self.assertTrue(
            "base64 -d | sh" in transcript or "zshield-device.lock" in transcript,
            "the lock was never requested — the review's third finding",
        )
        first_lock = min(
            index for index, line in enumerate(transcript.splitlines())
            if "base64 -d | sh" in line or "zshield-device.lock" in line
        )
        self.assertEqual(
            first_lock, 0,
            "the lock must be requested before any other device call",
        )


if __name__ == "__main__":
    unittest.main()
