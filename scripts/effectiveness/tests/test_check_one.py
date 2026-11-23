"""`check_one`: every way one result can be wrong, and the positive controls that keep it honest.

Two rules for this file:

1. **A reverse case must name its reason.** "It failed" is not a test of a checker; the assertion is
   on the specific problem text, because a checker that rejects everything for the wrong reason would
   pass a test that only looked at "not empty".
2. **Every group of reverse cases is paired with a positive control.** The last review round found a
   harness that could have passed by rejecting everything just as easily as by accepting everything;
   the controls are what make that impossible.

The cases marked `ORIGINAL` are the four the first stage-2 review reproduced by hand
(`review_stage2_harness.py`); the ones marked `R2` are the three the second review added
(`review_stage2_r2.py`). Both scripts are run unmodified against this tree later
(`test_review_scripts.py`).
"""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import harness_fixtures as fixtures  # noqa: E402
from harness_fixtures import origin_record  # noqa: E402

harness = fixtures.harness


def flatten(group: dict) -> list[dict]:
    """Every call of a plan group, whatever legs it was split across."""
    return [call for calls in group["legs"].values() for call in calls]

CLIENT_URL = "https://origin.test/anything/get?keep=1&track=DROP_ME&zs_rid=run-1"
RUN_ID = "run-1"


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def healthy_expect(**overrides) -> dict:
    expect = {
        "status": 200,
        "scheme": "https",
        "transport": "tls-h2",
        "protocol": "h2",
        "tls": True,
        "method": "GET",
        "drop_params": ["track"],
        "keep_params": [],
        "client_url": CLIENT_URL,
        "require_upstream_id": True,
    }
    expect.update(overrides)
    return expect


def result(body: str, **overrides) -> dict:
    base = {
        "id": "req-1",
        "status": 200,
        "url": CLIENT_URL,
        "protocol": "h2",
        "body": body,
    }
    base.update(overrides)
    return base


def good_record(**overrides) -> str:
    """An upstream record of exactly what the scenario asked for, minus the dropped parameter."""
    record = {
        "id": "req-1",
        "method": "GET",
        "path": "/anything/get?keep=1&zs_rid=run-1",
        "body": "",
        "body_sha256": digest(""),
        "alpn": "h2",
        "tls": True,
        "inflight": 20,
        "probe": False,
    }
    record.update(overrides)
    return json.dumps(record)


class CorrectResultTest(unittest.TestCase):
    """The positive control: a correct result produces no problem at all."""

    def test_a_fully_correct_result_passes(self) -> None:
        self.assertEqual(
            harness.check_one(result(good_record()), {"run_id": RUN_ID}, healthy_expect()), []
        )

    def test_a_plaintext_result_passes_with_the_parameter_kept(self) -> None:
        url = "http://origin.test/anything/get?keep=1&track=KEEP&zs_rid=run-1"
        expect = healthy_expect(
            scheme="http",
            transport="plain",
            protocol="http/1.1",
            tls=False,
            drop_params=[],
            keep_params=["track"],
            client_url=url,
        )
        record = good_record(path="/anything/get?keep=1&track=KEEP&zs_rid=run-1", alpn=None, tls=False)
        self.assertEqual(
            harness.check_one(
                result(record, url=url, protocol="http/1.1"), {"run_id": RUN_ID}, expect
            ),
            [],
        )

    def test_a_correct_post_passes_with_a_byte_exact_body(self) -> None:
        body = "alpha=1&beta=2"
        url = "https://origin.test/anything/post?keep=1&track=DROP_ME&zs_rid=run-1"
        expect = healthy_expect(client_url=url, method="POST", body_exact=body)
        record = good_record(
            path="/anything/post?keep=1&zs_rid=run-1",
            method="POST",
            body=body,
            body_sha256=digest(body),
        )
        self.assertEqual(
            harness.check_one(result(record, url=url), {"run_id": RUN_ID}, expect), []
        )


class OriginalFourTest(unittest.TestCase):
    """ORIGINAL — the four the first stage-2 review reproduced: all four must be detected."""

    def test_empty_result_batches_are_structural_not_a_pass(self) -> None:
        # The review's first finding was the *entry point* accepting `[]` for every round; that is
        # covered by `test_harness_entry.py`. Here: a result whose body is empty is "the upstream did
        # not answer", which is the per-result half of the same defect.
        problems = harness.check_one(result(""), {"run_id": RUN_ID}, healthy_expect())
        self.assertTrue(any("did not answer" in problem for problem in problems), problems)

    def test_missing_protocol_evidence_fails(self) -> None:
        problems = harness.check_one(
            result(good_record(), protocol=""), {"run_id": RUN_ID}, healthy_expect()
        )
        self.assertTrue(any("no protocol evidence" in problem for problem in problems), problems)

    def test_a_wrong_path_and_method_fails(self) -> None:
        problems = harness.check_one(
            result(good_record(path="/UNREQUESTED?keep=1&zs_rid=run-1", method="DELETE")),
            {"run_id": RUN_ID},
            healthy_expect(),
        )
        self.assertTrue(any("upstream target" in problem for problem in problems), problems)
        self.assertTrue(any("upstream method" in problem for problem in problems), problems)

    def test_a_corrupted_post_body_fails_even_though_it_contains_the_sent_text(self) -> None:
        sent = "alpha=1&beta=2"
        url = "https://origin.test/anything/post?keep=1&track=DROP_ME&zs_rid=run-1"
        expect = healthy_expect(client_url=url, method="POST", body_exact=sent)
        corrupted = "alpha=1WRONG&beta=2WRONG"
        problems = harness.check_one(
            result(
                good_record(
                    path="/anything/post?keep=1&zs_rid=run-1",
                    method="POST",
                    body=corrupted,
                    body_sha256=digest(corrupted),
                ),
                url=url,
            ),
            {"run_id": RUN_ID},
            expect,
        )
        self.assertTrue(any("upstream body digest" in problem for problem in problems), problems)


class SecondReviewThreeTest(unittest.TestCase):
    """R2 — the three the second review reproduced: all three must be detected."""

    def test_a_wrong_upstream_request_id_fails(self) -> None:
        problems = harness.check_one(
            result(good_record(id="WRONG-UPSTREAM-ID")),
            {"run_id": RUN_ID},
            healthy_expect(request_id="req-1"),
        )
        self.assertTrue(any("request id" in problem for problem in problems), problems)

    def test_a_missing_upstream_request_id_fails(self) -> None:
        problems = harness.check_one(
            result(good_record(id="")), {"run_id": RUN_ID}, healthy_expect(request_id="req-1")
        )
        self.assertTrue(any("no request id" in problem for problem in problems), problems)

    def test_a_replayed_result_from_another_plan_fails(self) -> None:
        # The review's third case replayed a result from a previous round: the client's id looked
        # fine, the upstream's did not match the plan.
        problems = harness.check_one(
            result(good_record(id="earlier-plan-id")),
            {"run_id": RUN_ID},
            healthy_expect(request_id="this-plan-id"),
        )
        self.assertTrue(any("planned" in problem for problem in problems), problems)


class SnapshotAndIdentityTest(unittest.TestCase):
    """Missing observations, TLS evidence, method drift, and a probe answering instead of an echo."""

    def test_a_block_page_is_not_an_echo(self) -> None:
        problems = harness.check_one(
            result("<html><body>blocked</body></html>"), {"run_id": RUN_ID}, healthy_expect()
        )
        self.assertTrue(any("did not answer" in problem for problem in problems), problems)

    def test_a_probe_answer_is_rejected(self) -> None:
        problems = harness.check_one(
            result(good_record(probe=True)), {"run_id": RUN_ID}, healthy_expect()
        )
        self.assertTrue(any("probe" in problem for problem in problems), problems)

    def test_a_transport_error_is_reported_as_such(self) -> None:
        problems = harness.check_one(
            {"id": "req-1", "error": "TypeError: Failed to fetch"}, {"run_id": RUN_ID},
            healthy_expect(),
        )
        self.assertTrue(any("transport error" in problem for problem in problems), problems)

    def test_a_wrong_alpn_fails_even_when_the_browser_says_h2(self) -> None:
        problems = harness.check_one(
            result(good_record(alpn="http/1.1")), {"run_id": RUN_ID}, healthy_expect()
        )
        self.assertTrue(any("ALPN" in problem for problem in problems), problems)

    def test_a_wrong_method_fails(self) -> None:
        problems = harness.check_one(
            result(good_record(method="DELETE")), {"run_id": RUN_ID}, healthy_expect()
        )
        self.assertTrue(any("upstream method" in problem for problem in problems), problems)

    def test_a_plaintext_connection_where_tls_was_expected_fails(self) -> None:
        problems = harness.check_one(
            result(good_record(tls=False, alpn=None)), {"run_id": RUN_ID}, healthy_expect()
        )
        self.assertTrue(any("tls=" in problem for problem in problems), problems)

    def test_a_dropped_parameter_that_survives_fails(self) -> None:
        problems = harness.check_one(
            result(good_record(path="/anything/get?keep=1&track=DROP_ME&zs_rid=run-1")),
            {"run_id": RUN_ID},
            healthy_expect(),
        )
        self.assertTrue(any("still carries 'track'" in problem for problem in problems), problems)

    def test_a_kept_parameter_that_vanishes_fails(self) -> None:
        url = "http://origin.test/anything/get?keep=1&track=KEEP&zs_rid=run-1"
        expect = healthy_expect(
            scheme="http", transport="plain", protocol="http/1.1", tls=False,
            drop_params=[], keep_params=["track"], client_url=url,
        )
        problems = harness.check_one(
            result(good_record(path="/anything/get?keep=1&zs_rid=run-1", tls=False, alpn=None),
                   url=url, protocol="http/1.1"),
            {"run_id": RUN_ID},
            expect,
        )
        self.assertTrue(any("lost 'track'" in problem for problem in problems), problems)

    def test_a_missing_body_digest_fails_the_body_comparison(self) -> None:
        sent = "alpha=1"
        url = "https://origin.test/anything/post?keep=1&track=DROP_ME&zs_rid=run-1"
        record = {
            "id": "req-1", "method": "POST", "path": "/anything/post?keep=1&zs_rid=run-1",
            "alpn": "h2", "tls": True, "inflight": 1, "probe": False,
        }
        problems = harness.check_one(
            result(json.dumps(record), url=url),
            {"run_id": RUN_ID},
            healthy_expect(client_url=url, method="POST", body_exact=sent),
        )
        self.assertTrue(any("byte-level body evidence" in problem for problem in problems), problems)

    def test_a_normalised_form_is_not_body_evidence(self) -> None:
        url = "https://origin.test/anything/post?keep=1&track=DROP_ME&zs_rid=run-1"
        body = json.dumps(
            {"url": url, "method": "POST", "form": {"alpha": ["1"]}, "data": ""}
        )
        problems = harness.check_one(
            result(body, url=url),
            {"run_id": RUN_ID},
            healthy_expect(client_url=url, method="POST", body_exact="alpha=1"),
        )
        self.assertTrue(any("byte-level body evidence" in problem for problem in problems), problems)

    def test_an_httpbin_echo_cannot_prove_a_request_id(self) -> None:
        # A weaker echo is not a pass: it reports no id, so the assertion it cannot support fails.
        body = json.dumps({"url": CLIENT_URL, "method": "GET", "data": ""})
        problems = harness.check_one(result(body), {"run_id": RUN_ID}, healthy_expect())
        self.assertTrue(any("no request id" in problem for problem in problems), problems)

    def test_a_wrong_status_short_circuits(self) -> None:
        problems = harness.check_one(
            result(good_record(), status=500), {"run_id": RUN_ID}, healthy_expect()
        )
        self.assertEqual(problems, ["status 500 != 200"])

    def test_a_missing_client_url_fails(self) -> None:
        problems = harness.check_one(
            result(good_record(), url=""), {"run_id": RUN_ID}, healthy_expect()
        )
        self.assertTrue(any("no final URL" in problem for problem in problems), problems)

    def test_a_wrong_scheme_fails(self) -> None:
        problems = harness.check_one(
            result(good_record(), url=CLIENT_URL.replace("https://", "http://")),
            {"run_id": RUN_ID},
            healthy_expect(),
        )
        self.assertTrue(any("client scheme" in problem for problem in problems), problems)

    def test_a_run_id_missing_upstream_fails(self) -> None:
        problems = harness.check_one(
            result(good_record(path="/anything/get?keep=1")), {"run_id": RUN_ID}, healthy_expect()
        )
        self.assertTrue(any("run" in problem for problem in problems), problems)

    def test_a_url_that_merely_contains_the_target_is_not_the_target(self) -> None:
        # The substring hole the review found: `/x?keep=1&next=/anything/get?keep=1` contains the
        # expected target as text and must not pass.
        problems = harness.check_one(
            result(good_record(path="/x?keep=1&next=/anything/get?keep=1&zs_rid=run-1")),
            {"run_id": RUN_ID},
            healthy_expect(),
        )
        self.assertTrue(any("upstream target" in problem for problem in problems), problems)


class ScenarioTableTest(unittest.TestCase):
    """The scenario table itself: transports really differ, and the expectations follow the design."""

    def setUp(self) -> None:
        self.scenarios = harness.build_scenarios(
            "https://origin.test/anything", "run-9",
            "http://origin.test/anything", "https://origin.test/anything",
            "https://origin.test:8443/anything",
        )
        self.by_name = {scenario["name"]: scenario for scenario in self.scenarios}

    def test_every_transport_has_get_and_post(self) -> None:
        transports = {scenario["transport"] for scenario in self.scenarios}
        self.assertEqual(transports, {"plain", "tls-h1", "tls-h2"})
        for name in ("h1-get", "h1-post", "tls1-get", "tls1-post-removeparam", "h2-get",
                     "h2-post-removeparam"):
            self.assertIn(name, self.by_name)

    def test_the_tls_h1_leg_uses_its_own_origin_and_protocol(self) -> None:
        scenario = self.by_name["tls1-get"]
        self.assertTrue(scenario["url"].startswith("https://origin.test:8443/"))
        self.assertEqual(scenario["expect"]["protocol"], "http/1.1")
        self.assertTrue(scenario["expect"]["tls"])
        # The h2 leg is a different listener, not the same one relabelled.
        self.assertNotEqual(self.by_name["h2-get"]["url"], scenario["url"])
        self.assertEqual(self.by_name["h2-get"]["expect"]["protocol"], "h2")

    def test_the_plaintext_leg_forbids_rewriting(self) -> None:
        # DESIGN: `$removeparam` only fires on a decrypted connection, so the plaintext case asserts
        # the parameter **survives**. Asserting a removal there would contradict the design.
        scenario = self.by_name["h1-removeparam-scoped"]
        self.assertEqual(scenario["expect"]["drop_params"], [])
        self.assertEqual(scenario["expect"]["keep_params"], ["track"])

    def test_the_decrypted_legs_require_a_removal(self) -> None:
        for name, parameter in (("removeparam", "track"), ("removeparam-regex", "rxparam"),
                                ("tls1-removeparam", "track"),
                                ("tls1-removeparam-regex", "rxparam"),
                                ("h2-post-removeparam", "track"),
                                ("tls1-post-removeparam", "track")):
            self.assertEqual(self.by_name[name]["expect"]["drop_params"], [parameter])

    def test_a_navigation_expects_the_clean_url_and_a_fetch_does_not(self) -> None:
        navigation = self.by_name["nav-h2"]
        self.assertTrue(navigation["navigation"])
        # The core answers a rewritten navigation with a 302, so the browser's final URL is clean.
        self.assertNotIn("track=", navigation["expect"]["client_url"])
        self.assertIn("track=DROP_ME", self.by_name["removeparam"]["expect"]["client_url"])

    def test_the_plaintext_navigation_keeps_the_parameter(self) -> None:
        navigation = self.by_name["nav-plain"]
        self.assertIn("track=KEEP_ON_PLAINTEXT", navigation["expect"]["client_url"])
        self.assertEqual(navigation["expect"]["keep_params"], ["track"])

    def test_every_scenario_requires_an_upstream_id_or_is_a_navigation(self) -> None:
        # A `fetch` scenario must carry the upstream's ID: that is the only per-request identity the
        # upstream can report. A document navigation cannot set a custom header, so it is identified
        # by the `zs_rid` in its target and the exact target comparison — it must therefore *not*
        # claim the header evidence, or the run would fail for a browser limitation.
        for scenario in self.scenarios:
            if scenario["navigation"]:
                self.assertFalse(scenario["expect"]["require_upstream_id"], scenario["name"])
                self.assertIn("zs_rid=", scenario["url"], scenario["name"])
            else:
                self.assertTrue(scenario["expect"]["require_upstream_id"], scenario["name"])

    def test_the_plan_deals_every_scenario_and_unique_ids(self) -> None:
        group = harness.plan_group(self.scenarios, 20, 0)
        calls = flatten(group)
        scenarios_used = {call["scenario"] for call in calls}
        batchable = {
            scenario["name"] for scenario in self.scenarios if not scenario["navigation"]
        }
        # 20 calls over 12 batchable scenarios covers every one of them at least once.
        self.assertEqual(scenarios_used, batchable)
        ids = [call["id"] for call in calls]
        # `group["ids"]` is the plan's own record of what it asked for; the legs must carry all of it.
        self.assertEqual(sorted(group["ids"]), sorted(ids))
        self.assertEqual(len(ids), len(set(ids)))
        # The id encodes its round, so cross-round reuse is detectable.
        self.assertTrue(all(harness.round_of(request_id) == 0 for request_id in ids))

    def test_a_transport_scoped_plan_uses_only_that_transport(self) -> None:
        group = harness.plan_group(self.scenarios, 20, 1, transport="tls-h2")
        self.assertEqual(len(group["legs"]["tls-h2"]), 20)
        for call in group["legs"]["tls-h2"]:
            self.assertEqual(call["transport"], "tls-h2")
            self.assertEqual(harness.round_of(call["id"]), 1)

    def test_navigations_are_never_batch_members(self) -> None:
        for round_index in range(3):
            for call in flatten(harness.plan_group(self.scenarios, 7, round_index)):
                self.assertFalse(call["scenario"].startswith("nav-"), call["scenario"])


class StructureAndConcurrencyTest(unittest.TestCase):
    """The checks no per-result comparison can make: counts, ids, distribution, overlap, isolation."""

    def setUp(self) -> None:
        self.scenarios = harness.build_scenarios("https://origin.test/anything", "run-2")
        self.group = harness.plan_group(self.scenarios, 6, 0)

    def _results(self, group: dict, inflight: int | None = 6) -> list[dict]:
        out = []
        for call in flatten(group):
            record = json.loads(origin_record())
            record["id"] = call["id"]
            if inflight is not None:
                record["inflight"] = inflight
            else:
                record.pop("inflight")
            # `group` is what ties a result to the plan group it answers, exactly as `main` sets it.
            out.append({"id": call["id"], "scenario": call["scenario"], "round": 1, "group": 0,
                        "inflight": record.get("inflight"), "body": json.dumps(record)})
        return out

    def test_a_complete_group_passes_every_structural_check(self) -> None:
        results = self._results(self.group)
        self.assertEqual(harness.validate_structure([self.group], results, 1, 6), [])
        self.assertEqual(harness.validate_concurrency([self.group], results, 6), [])

    def test_a_missing_result_fails(self) -> None:
        results = self._results(self.group)[:-1]
        problems = harness.validate_structure([self.group], results, 1, 6)
        self.assertTrue(any("no result" in problem for problem in problems), problems)
        self.assertTrue(any("result(s) !=" in problem for problem in problems), problems)

    def test_a_duplicate_result_fails(self) -> None:
        results = self._results(self.group)
        results.append(dict(results[0]))
        problems = harness.validate_structure([self.group], results, 1, 6)
        self.assertTrue(any("duplicate" in problem for problem in problems), problems)

    def test_an_unplanned_result_fails(self) -> None:
        results = self._results(self.group)
        extra = dict(results[0])
        extra["id"] = "never-planned-0"
        extra["scenario"] = results[0]["scenario"]
        results.append(extra)
        problems = harness.validate_structure([self.group], results, 1, 6)
        self.assertTrue(any("never issued" in problem for problem in problems), problems)

    def test_a_cross_round_result_fails(self) -> None:
        # Same ids, but filed under the wrong round: the id encodes round 0, the result claims 2.
        results = self._results(self.group)
        for entry in results:
            entry["round"] = 2
        problems = harness.validate_structure([self.group], results, 2, 6)
        self.assertTrue(any("belongs to round" in problem for problem in problems), problems)

    def test_a_skipped_scenario_fails(self) -> None:
        # Every result claims the same scenario, so the per-scenario distribution cannot match.
        results = self._results(self.group)
        for entry in results:
            entry["scenario"] = results[0]["scenario"]
        problems = harness.validate_structure([self.group], results, 1, 6)
        self.assertTrue(
            any("result(s) !=" in problem and "planned" in problem for problem in problems), problems
        )

    def test_a_serialised_group_fails_the_overlap_check(self) -> None:
        results = self._results(self.group, inflight=1)
        problems = harness.validate_concurrency([self.group], results, 6)
        self.assertTrue(any("in flight" in problem for problem in problems), problems)

    def test_a_group_with_no_inflight_observation_fails(self) -> None:
        results = self._results(self.group, inflight=None)
        problems = harness.validate_concurrency([self.group], results, 6)
        self.assertTrue(any("unproven" in problem for problem in problems), problems)

    def test_two_legs_on_one_target_fail_the_isolation_check(self) -> None:
        shared = fixtures.PageDouble("same-target", [])
        problems = harness.validate_isolation(
            {"plain": shared, "tls-h1": shared, "tls-h2": shared}
        )
        self.assertTrue(any("share page target" in problem for problem in problems), problems)

    def test_independent_targets_pass_the_isolation_check(self) -> None:
        pages = {
            name: fixtures.PageDouble(f"target-{name}", [])
            for name in harness.TRANSPORTS
        }
        self.assertEqual(harness.validate_isolation(pages), [])

    def test_a_page_without_a_target_id_fails_the_isolation_check(self) -> None:
        class Anonymous(fixtures.PageDouble):
            def __init__(self) -> None:
                super().__init__("x", [])
                self.target = {}

        pages = {name: Anonymous() for name in harness.TRANSPORTS}
        problems = harness.validate_isolation(pages)
        self.assertTrue(any("no target id" in problem for problem in problems), problems)


if __name__ == "__main__":
    unittest.main()
