"""The entry point itself: a real run over real sockets must PASS, and a broken one must FAIL.

Every other test file checks one judgement. This one checks the program: it starts a real controlled
origin, drives the harness's own `plan_group` → `batch_script` → `validate_*` → `check_one` path with a
**real HTTP client** instead of a phone, and asserts the verdict. That is the difference between "the
checker rejects bad input" and "the tool reports the truth about a run".

Two shapes are proven here:

  each leg in parallel  three origins (plaintext, TLS/H1, TLS/H2) driven concurrently from threads —
                        the layout a device run uses when the browser exposes three page targets;
  each leg in sequence  one origin per leg, full concurrency each — the layout used when it exposes
                        fewer. The origin's in-flight peak is what proves each of them either way.

The device legs themselves (a browser behind a VPN on the Pixel 5) are **not** covered here and are
recorded as unverified in the delivery notes: `docs/TESTING.md` §14 explains that a host test cannot
stand in for the tunnel, and pretending otherwise is the exact defect these tools were rebuilt for.
"""

from __future__ import annotations

import json
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import harness_fixtures as fixtures  # noqa: E402

harness = fixtures.harness


def flatten(group: dict) -> list[dict]:
    return [call for calls in group["legs"].values() for call in calls]

#: The parameters the scenarios expect to be removed. The host client plays the role of the core's
#: rewrite here: it drops exactly those, on the decrypted legs only, so the harness's assertions have
#: a real upstream record to read.
DROP = {"track", "rxparam"}


def send(call: dict) -> dict:
    """Perform one planned call on the host and shape the answer like a page batch member.

    The leg is taken from the call's own transport, and the `protocol` field from what the upstream
    says it negotiated — not assumed from the URL scheme. A double that guessed would make the
    TLS/H1 leg indistinguishable from the TLS/H2 one, which is the defect this whole stage removes.
    """
    from urllib.parse import urlsplit, urlunsplit

    split = urlsplit(call["url"])
    decrypted = call["transport"] != "plain"
    if decrypted:
        kept = [
            pair
            for pair in split.query.split("&")
            if pair.split("=", 1)[0] not in DROP
        ]
        target = urlunsplit(split._replace(query="&".join(kept)))
    else:
        # The plaintext leg must arrive with its parameters intact, which is what the design requires.
        target = call["url"]
    h2_leg = call["transport"] == "tls-h2"
    status, body, response_headers = fixtures.request(
        target,
        method=call["init"].get("method", "GET"),
        body=call["init"].get("body", "").encode() or None,
        headers=call["init"].get("headers", {}),
        # The TLS/H2 leg speaks h2 for real; the TLS/H1 leg offers h2 and the listener refuses it.
        prefer_h2=h2_leg,
        alpn=("h2", "http/1.1") if decrypted and not h2_leg else None,
    )
    negotiated = response_headers.get("X-Negotiated-ALPN") or ""
    if not negotiated:
        try:
            negotiated = json.loads(body).get("alpn") or "http/1.1"
        except (json.JSONDecodeError, AttributeError):
            negotiated = "http/1.1"
    return {
        "id": call["id"],
        "index": call["index"],
        "scenario": call["scenario"],
        "status": status,
        "url": call["url"],
        "redirected": False,
        "type": "basic",
        "protocol": negotiated,
        "ms": 1.0,
        "body": body,
    }


class RealRunTest(unittest.TestCase):
    """A full run against three real listeners, driven exactly as `main` drives a browser."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.origin = fixtures.OriginFixture(tls=True, tls1=True, hold_ms=150).start()
        cls.scenarios = harness.build_scenarios(
            cls.origin.base_tls, "hostrun",
            http_origin=cls.origin.base,
            https_origin=cls.origin.base_tls,
            tls1_origin=cls.origin.base_tls1,
        )
        cls.by_name = {scenario["name"]: scenario for scenario in cls.scenarios}

    @classmethod
    def tearDownClass(cls) -> None:
        cls.origin.stop()

    def _deliver(self, calls: list[dict]) -> list[dict]:
        """Send every call of a group, all at once, from threads — a real concurrent batch."""
        results: list[dict] = []
        lock = threading.Lock()

        def worker(call: dict) -> None:
            result = send(call)
            with lock:
                results.append(result)

        threads = [threading.Thread(target=worker, args=(call,)) for call in calls]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        return results

    def _judge(self, results: list[dict], run_id: str) -> list[str]:
        problems: list[str] = []
        for result in results:
            scenario = self.by_name[result["scenario"]]
            expect = dict(scenario["expect"])
            # The host client offers h2 on the TLS/H2 leg; the TLS/H1 listener answers http/1.1.
            for found in harness.check_one(result, {"run_id": run_id}, expect):
                problems.append(f"{result['scenario']}: {found}")
        return problems

    def test_a_real_run_passes(self) -> None:
        group = harness.plan_group(self.scenarios, 12, 0)
        for result in flatten(group):
            result["round"] = 1
            result["group"] = 0
        results = self._deliver(flatten(group))
        self.assertEqual(len(results), 12)

        structural = harness.validate_structure([group], results, 1, 12)
        self.assertEqual(structural, [])
        self.assertEqual(self._judge(results, "hostrun"), [])

        # The upstream really saw these requests: the ids it recorded are the plan's ids.
        planned = {call["id"] for call in flatten(group)}
        recorded = {record["id"] for record in self.origin.records() if not record["probe"]}
        self.assertEqual(planned & recorded, planned)

        # And they overlapped: a serialised run would have peak 1.
        peak = max(record["inflight"] for record in self.origin.records() if not record["probe"])
        self.assertGreaterEqual(peak, 6, f"the origin saw at most {peak} in flight")

    def test_a_run_with_a_dropped_parameter_left_in_place_fails(self) -> None:
        # The reverse of the run above: send the URL *without* rewriting, so the upstream records a
        # parameter the design says must be gone. The harness must reject it — and for that reason.
        calls = harness.plan_group(self.scenarios, 4, 0, transport="tls-h2")["legs"]["tls-h2"]
        rewrite_target = next(call for call in calls if call["scenario"] == "removeparam")
        status, body, _ = fixtures.request(
            rewrite_target["url"], headers=rewrite_target["init"]["headers"], insecure=True
        )
        result = {
            "id": rewrite_target["id"], "scenario": "removeparam", "status": status,
            "url": rewrite_target["url"], "protocol": "h2", "body": body,
        }
        problems = harness.check_one(
            result, {"run_id": "hostrun"}, self.by_name["removeparam"]["expect"]
        )
        self.assertTrue(any("still carries 'track'" in problem for problem in problems), problems)

    def test_the_plaintext_leg_must_not_be_rewritten(self) -> None:
        # The control for the case above: the same parameter on the plaintext leg must arrive intact,
        # so a harness that demanded its removal on http would contradict the design.
        calls = harness.plan_group(self.scenarios, 4, 0, transport="plain")["legs"]["plain"]
        scoped = next(call for call in calls if call["scenario"] == "h1-removeparam-scoped")
        status, body, _ = fixtures.request(scoped["url"], headers=scoped["init"]["headers"])
        result = {
            "id": scoped["id"], "scenario": "h1-removeparam-scoped", "status": status,
            "url": scoped["url"], "protocol": "http/1.1", "body": body,
        }
        self.assertEqual(
            harness.check_one(
                result, {"run_id": "hostrun"}, self.by_name["h1-removeparam-scoped"]["expect"]
            ),
            [],
        )

    def test_a_body_that_the_upstream_received_differently_fails(self) -> None:
        calls = harness.plan_group(self.scenarios, 3, 0, transport="tls-h2")["legs"]["tls-h2"]
        post = next(call for call in calls if call["scenario"] == "h2-post-removeparam")
        # Send a body the scenario did not plan: the upstream records those bytes honestly, and the
        # comparison is over bytes, so the mismatch is detected rather than normalised away.
        status, body, _ = fixtures.request(
            post["url"].replace("track=DROP_ME", "track=DROP_ME"),
            method="POST",
            body=b"tampered=1",
            headers=post["init"]["headers"],
            insecure=True,
        )
        result = {
            "id": post["id"], "scenario": "h2-post-removeparam", "status": status,
            "url": post["url"], "protocol": "h2", "body": body,
        }
        problems = harness.check_one(result, {"run_id": "hostrun"}, self.by_name["h2-post-removeparam"]["expect"])
        self.assertTrue(any("upstream body digest" in problem for problem in problems), problems)


class SequentialLegLayoutTest(unittest.TestCase):
    """The layout used when the browser exposes fewer page targets than transports.

    Each leg runs on its own with the full concurrency, and the origin's in-flight peak proves it.
    This is the mode that replaced "two `Browser.open()` calls on `targets[0]`", which produced
    results that looked concurrent and were not.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.origin = fixtures.OriginFixture(tls=True, tls1=True, hold_ms=120).start()
        cls.scenarios = harness.build_scenarios(
            cls.origin.base_tls, "seqrun",
            http_origin=cls.origin.base,
            https_origin=cls.origin.base_tls,
            tls1_origin=cls.origin.base_tls1,
        )
        cls.by_name = {scenario["name"]: scenario for scenario in cls.scenarios}

    @classmethod
    def tearDownClass(cls) -> None:
        cls.origin.stop()

    def test_each_leg_reaches_the_full_concurrency_on_its_own(self) -> None:
        groups = []
        results: list[dict] = []
        for round_index in range(2):
            for transport in harness.TRANSPORTS:
                group = harness.plan_group(self.scenarios, 8, round_index, transport=transport)
                group_index = len(groups)
                calls = group["legs"][transport]
                lock = threading.Lock()

                def worker(call: dict) -> None:
                    result = send(call)
                    result["round"] = round_index + 1
                    result["group"] = group_index
                    with lock:
                        results.append(result)

                threads = [threading.Thread(target=worker, args=(call,)) for call in calls]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
                groups.append(group)

        # The overlap check runs once over the whole run, exactly as `main` runs it.
        self.assertEqual(harness.validate_concurrency(groups, results, 8), [])
        for group in groups:
            self.assertGreaterEqual(
                group["peak"], 8,
                f"a leg only reached {group['peak']} in flight, so a shared page would be invisible",
            )

    def test_a_shared_target_cannot_reach_the_full_concurrency(self) -> None:
        # The negative control for the layout above: when both legs are *the same page*, only one
        # batch can be in flight, and the origin's peak says so. This is precisely the defect the
        # review measured — two `Browser.open()` calls that both picked `targets[0]`.
        page = fixtures.PageDouble("only-target", [])
        problems = harness.validate_isolation(
            {"plain": page, "tls-h1": page, "tls-h2": page}
        )
        self.assertTrue(problems)
        self.assertTrue(any("share page target" in problem for problem in problems))


if __name__ == "__main__":
    unittest.main()
