"""The reference fixtures themselves are held to the criterion they exist to demonstrate.

`build_formal_fixture.py` and `formal_evidence_probes.py` are the reviewer-facing pair: one writes a
campaign that *should* be acceptable, the other applies defects to it. Both are only useful if the
positive side really reaches the judged criterion — a fixture that fails for a missing file makes
every rejection meaningless. That property is easy to break with a schema change and impossible to
notice from the probe's own output, so it is asserted here as well.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent
REPO = SCRIPTS.parent.parent


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


fixture_tool = load("build_formal_fixture", HERE / "build_formal_fixture.py")
memory_profile = load("memory_profile", SCRIPTS / "memory_profile.py")


class TheReferenceFixtureIsGenuinelyAcceptable(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="zs-formal-fixture-")
        self.root = Path(self._tmp.name) / "campaign"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _recompute(self) -> tuple[int, dict]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            status = memory_profile.main(["recompute", str(self.root), "--json"])
        return status, json.loads(out.getvalue())

    def test_the_fixture_reaches_a_formal_verdict(self) -> None:
        fixture_tool.build(self.root)
        status, document = self._recompute()
        # Exit 0 here means "valid acceptance evidence", not "the tool ran". If this ever fails,
        # every probe built on the fixture is measuring nothing.
        self.assertEqual(status, 0, document.get("problems") or document.get("input_problems"))
        self.assertTrue(document["ok"])
        self.assertEqual(document["layer"], {
            "diagnostic": False, "formally_comparable": True, "inputs_proven": True,
            "order_proven": True, "samples_valid": True})
        self.assertEqual({entry["rule_set"] for entry in document["comparisons"]},
                         {"fixed-five", "default-nine"})
        self.assertEqual(len(document["executed_order"]), 12,
                         "two builds × two rule sets × three batches, alternating")

    def test_the_fixture_is_labelled_synthetic(self) -> None:
        # A fixture that could be mistaken for device data is worse than none: the provenance note
        # travels with the directory, and its values are the ones the card would call a FAIL.
        fixture_tool.build(self.root)
        note = (self.root / "provenance.md").read_text(encoding="utf-8")
        self.assertIn("构造出来的", note)
        self.assertIn("不是", note)
        status, document = self._recompute()
        verdicts = {row["build"]: row["verdict"] for row in document["threshold"]}
        self.assertEqual(verdicts["candidate"], "FAIL", "86.9 MiB is over the 84.6 MiB gate")

    def test_the_fixture_refuses_to_overwrite_a_campaign(self) -> None:
        fixture_tool.main([str(self.root)])
        with self.assertRaises(SystemExit) as raised:
            fixture_tool.main([str(self.root)])
        self.assertIn("refusing to overwrite", str(raised.exception))


class TheProbeScriptRefusesEveryDefect(unittest.TestCase):
    """Run the reviewer-facing probe script end to end, as a reviewer would."""

    def test_every_defect_is_refused_with_a_stated_reason(self) -> None:
        run = subprocess.run([sys.executable, str(HERE / "formal_evidence_probes.py"), str(REPO)],
                             capture_output=True, text=True, timeout=300)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        # The positive control must be reported as accepted, not merely absent from the failures.
        self.assertIn("valid_formal_campaign: exit=0 ok=True", run.stdout)
        self.assertIn("comparisons=2", run.stdout)
        self.assertIn("probe failures: 0", run.stdout)
        # And every defect must have been refused for a reason, not by accident.
        refusals = [line for line in run.stdout.splitlines() if "expected=refused" in line]
        self.assertGreaterEqual(len(refusals), 10)


if __name__ == "__main__":
    unittest.main()
