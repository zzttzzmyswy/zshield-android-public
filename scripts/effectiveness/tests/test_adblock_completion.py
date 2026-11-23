"""A stable interim score is not proof that asynchronous page checks finished."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import testpages


class Page:
    def __init__(self, readings):
        self.readings = readings
        self.calls = 0

    def evaluate(self, script):
        reading = self.readings[min(self.calls, len(self.readings) - 1)]
        self.calls += 1
        return reading


class AdblockCompletionTest(unittest.TestCase):
    def run_reader(self, page, timeout=10):
        clock = [0.0]

        def sleep(seconds):
            clock[0] += seconds

        with patch.object(testpages.time, "sleep", sleep), \
             patch.object(testpages.time, "time", lambda: clock[0]), \
             patch.object(testpages.time, "monotonic", lambda: clock[0]):
            testpages.wait_for_adblock_score(page, timeout)

    def test_stable_score_with_pending_check_is_not_final(self):
        pending = {"score": "64", "statuses": ["blocked", "pending"]}
        complete = {"score": "68", "statuses": ["blocked", "likelyBlocked"]}
        page = Page([pending, pending, pending, complete, complete])
        self.run_reader(page)
        self.assertEqual(page.calls, 5)

    def test_permanently_pending_check_times_out(self):
        with self.assertRaises(testpages.cdp.CdpError):
            self.run_reader(Page([{"score": "96", "statuses": ["pending"]}]), 3)

    def test_missing_checks_do_not_mean_complete(self):
        with self.assertRaises(testpages.cdp.CdpError):
            self.run_reader(Page([{"score": "100", "statuses": []}]), 3)

    def test_failed_and_unknown_checks_are_terminal_and_zero_is_valid(self):
        page = Page([{"score": "0", "statuses": ["blocked", "likelyBlocked",
                     "unblocked", "likelyUnblocked", "unknown"]}])
        self.run_reader(page)
        self.assertEqual(page.calls, 2)

    def test_missing_unknown_status_or_invalid_score_is_refused(self):
        for state in ({"score": "68", "statuses": [None]},
                      {"score": "68", "statuses": ["new-site-state"]},
                      {"score": "", "statuses": ["blocked"]},
                      {"score": None, "statuses": ["blocked"]}):
            with self.subTest(state=state), self.assertRaises(testpages.cdp.CdpError):
                self.run_reader(Page([state]), 3)

    def test_score_must_settle_after_checks_complete(self):
        page = Page([{"score": s, "statuses": ["blocked"]} for s in ("64", "68", "68")])
        self.run_reader(page)
        self.assertEqual(page.calls, 3)


if __name__ == "__main__":
    unittest.main()
