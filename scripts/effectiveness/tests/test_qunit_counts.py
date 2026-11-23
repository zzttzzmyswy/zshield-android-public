"""Regression cases copied from completed and interrupted QUnit DOM summaries."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from testpages import parse_qunit_counts


class QunitCountsTest(unittest.TestCase):
    def test_actual_element_hiding_summary(self):
        counts = parse_qunit_counts(
            "10 tests completed in 85.9 milliseconds, with 2 failed, 0 skipped, and 0 todo."
            "15 assertions of 17 passed, 2 failed.Rerun 2 failed tests"
        )
        self.assertEqual((counts['testsPassed'], counts['tests']), (8, 10))
        self.assertEqual((counts['assertionsPassed'], counts['assertionsFailed'],
                          counts['assertionsTotal']), (15, 2, 17))

    def test_actual_removeparam_summary(self):
        counts = parse_qunit_counts(
            "14 tests completed in 3737 milliseconds, with 12 failed, 0 skipped, and 0 todo."
            "2 assertions of 14 passed, 12 failed.Rerun 12 failed tests"
        )
        self.assertEqual((counts['assertionsPassed'], counts['assertionsTotal']), (2, 14))

    def test_interrupted_count_is_not_planned_total(self):
        counts = parse_qunit_counts("11 / 14 tests completed.Running: Testcase 12 — pending")
        self.assertEqual(counts, {'tests': 11, 'testsPlanned': 14, 'aborted': True})


if __name__ == '__main__':
    unittest.main()
