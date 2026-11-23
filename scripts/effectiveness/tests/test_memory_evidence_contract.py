"""Black-box review regressions, each starting from a complete synthetic campaign."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from build_formal_fixture import build

TOOL = Path(__file__).resolve().parents[1] / "memory_profile.py"


class EvidenceContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = build(Path(self.temp.name) / "campaign")
        self.path = self.root / "campaign.json"
        self.record = json.loads(self.path.read_text())

    def verdict(self):
        self.path.write_text(json.dumps(self.record))
        result = subprocess.run([sys.executable, str(TOOL), "recompute", str(self.root),
                                 "--json"], capture_output=True, text=True)
        self.assertTrue(result.stdout.startswith("{"), result.stderr)
        return result.returncode, json.loads(result.stdout)

    def refused(self, reason):
        code, report = self.verdict()
        self.assertNotEqual(code, 0)
        self.assertFalse(report["ok"])
        self.assertEqual(report["comparisons"], [])
        self.assertNotIn("PASS", [row["verdict"] for row in report["threshold"]])
        errors = report["problems"] + report["input_problems"] + report["order_problems"]
        self.assertTrue(any(reason in item for item in errors), errors)

    def test_complete_synthetic_control(self):
        code, report = self.verdict()
        self.assertEqual(code, 0)
        self.assertTrue(report["ok"])
        self.assertEqual(len(report["comparisons"]), 2)
        self.assertEqual({row["rule_set"] for row in report["threshold"]}, {"fixed-five"})

    def test_different_source_inputs(self):
        original = copy.deepcopy(self.record)
        for field in ("lists", "user_rules_sha256", "allowlist_sha256"):
            with self.subTest(field=field):
                self.record = copy.deepcopy(original)
                cell = self.record["plan"]["inputs"]["candidate/fixed-five"]
                if field == "lists":
                    cell[field][0]["sha256"] = "9" * 64
                else:
                    cell[field] = "9" * 64
                self.refused("different source inputs")

    def test_malformed_inputs(self):
        original = copy.deepcopy(self.record)
        cases = [("lists", "invented"), ("user_rules_sha256", "x"),
                 ("allowlist_sha256", 1), ("loaded_artifacts_sha256", {"engine": "x"})]
        for field, value in cases:
            with self.subTest(field=field):
                self.record = copy.deepcopy(original)
                self.record["plan"]["inputs"]["candidate/fixed-five"][field] = value
                self.refused("invalid")

    def test_duplicate_list_and_non_boolean_enabled(self):
        cell = self.record["plan"]["inputs"]["candidate/fixed-five"]
        cell["lists"].append(copy.deepcopy(cell["lists"][0]))
        self.refused("duplicate")
        cell["lists"].pop()
        cell["lists"][0]["enabled"] = "false"
        self.refused("enabled")

    def test_loaded_artifact_differs_from_batch(self):
        self.record["plan"]["inputs"]["candidate/fixed-five"]["loaded_artifacts_sha256"][
            "engine"] = "sha256:" + "9" * 64 + ":1000"
        self.refused("loaded artifacts disagree")

    def test_attempts_must_cover_every_batch(self):
        self.record["attempts"] = self.record["attempts"][:1]
        self.refused("exactly one successful attempt")

    def test_duplicate_successful_attempt(self):
        extra = copy.deepcopy(self.record["attempts"][0])
        extra["attempt_id"] = "another-id"
        self.record["attempts"].append(extra)
        self.refused("exactly one successful attempt")

    def test_outcomes_must_cover_every_batch(self):
        self.record["batches"] = [entry for entry in self.record["batches"] if entry["index"] == 1]
        self.refused("per-batch outcomes must cover")

    def test_unknown_attempt_cell_is_not_a_substitute(self):
        self.record["attempts"][0]["cell"][0] = "unknown"
        self.refused("unknown cell/index")

    def test_failed_attempt_cannot_overlap_successful_run(self):
        previous = copy.deepcopy(self.record["attempts"][0])
        previous.update(attempt_id="failed-overlapping", outcome="void", reason="adb lost",
                        directory="failed-overlapping")
        (self.root / previous["directory"]).mkdir()
        self.record["attempts"].append(previous)
        self.refused("overlaps")

    def test_attempt_directory_must_exist(self):
        self.record["attempts"][0]["directory"] = "does-not-exist"
        self.refused("directory")

    def test_attempt_cannot_point_outside_campaign(self):
        self.record["attempts"][0]["directory"] = "../outside"
        self.refused("directory")

    def test_reversed_or_short_attempt_interval(self):
        for stamp in ("2026-11-12T00:00:00Z", "2026-11-13T00:00:01Z"):
            with self.subTest(stamp=stamp):
                self.record["attempts"][0]["finished_at"] = stamp
                self.refused("duration")

    def test_invalid_finish_stamp_is_explained(self):
        self.record["attempts"][0]["finished_at"] = "not-a-time"
        self.refused("stamp")

    def test_shortened_declared_interval_is_not_a_new_protocol(self):
        for result in self.root.glob("*/result.txt"):
            lines = []
            for line in result.read_text().replace("interval=60s", "interval=1s").splitlines():
                fields = line.split("\t")
                if len(fields) == 8 and fields[0].isdigit():
                    fields[1] = fields[0]
                    line = "\t".join(fields)
                lines.append(line)
            result.write_text("\n".join(lines) + "\n")
        self.refused("plan requires 60s")

    def test_failed_attempt_history_is_preserved_on_retry(self):
        previous = copy.deepcopy(self.record["attempts"][0])
        previous.update(attempt_id="failed-before-retry", outcome="void", reason="adb lost",
                        started_at="2026-11-12T23:50:00Z", finished_at="2026-11-12T23:58:00Z",
                        directory="failed-before-retry")
        (self.root / previous["directory"]).mkdir()
        (self.root / previous["directory"] / "failure.txt").write_text("adb lost\n")
        self.record["attempts"].insert(0, previous)
        accepted = self.record["attempts"][1]
        old = self.root / accepted["directory"]
        accepted["directory"] += "-retry2"
        old.rename(self.root / accepted["directory"])
        code, report = self.verdict()
        self.assertEqual(code, 0, report)
        self.assertTrue(report["ok"])


if __name__ == "__main__":
    unittest.main()
