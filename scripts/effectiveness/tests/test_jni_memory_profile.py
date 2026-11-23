"""`jni_memory_profile.py` must refuse evidence that does not support the claims made from it.

The first delivery's suite passed while the checker accepted nine contradictory documents, so the
fixtures here are the lesson: each case is a **complete campaign** — real artifacts on disk, a real
journal, a real command record, a real manifest — and each negative changes exactly one semantic
fact while re-sealing the manifest. A checker that only re-reads hashes cannot pass these, because
every one of them is hash-consistent.

Two properties are tested deliberately and separately:

* **negatives** are refusals whose *reason* is asserted, since "everything is refused" would satisfy
  a test that only looked at exit codes while telling nobody whether the checker can still say yes;
* **positives** are the same campaign unmutated, and the reviewer's restored control, which must still
  be accepted after nine refusals in a row.

The synthetic campaign is small but structurally identical to a real one: the same phases, the same
round numbering, the same window/journal/command relationships. `CANONICAL` and `GROUPS` are patched
for it because the real five-list bodies are 22 MB each; the *logic* under test is identical, and one
test additionally runs the real checker against the real shipped package when it is present.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import math
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent

SPEC = importlib.util.spec_from_file_location(
    "jni_memory_profile", SCRIPTS / "jni_memory_profile.py"
)
jni_memory_profile = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules["jni_memory_profile"] = jni_memory_profile
SPEC.loader.exec_module(jni_memory_profile)

#: The synthetic bodies. Small, but real files that the checker re-hashes.
SMALL_LISTS = {
    "adguard-base": b"||ads.test^\n||tracker.test^\n",
    "adguard-tracking": b"||track.test^\n",
    "adguard-mobile": b"||mads.test^\n",
    "adguard-url-tracking": b"||url.test^\n",
    "adguard-chinese": b"||cn.test^\n",
    # The nine-list group's extra four, so a complete nine-group campaign can be built too.
    "adguard-dns": b"||dns.test^\n",
    "easylist-china": b"||elcn.test^\n",
    "ublock-unbreak": b"||unbreak.test^\n",
    "ublock-quick-fixes": b"||quick.test^\n",
}


def envelope(payload: bytes) -> bytes:
    """A compiled artifact: 20-byte header then the payload, which is all the checker parses."""
    return b"TESTMAG\x00\x00\x01" + b"\x00" * 12 + payload


def effects_across_rounds() -> list[str]:
    return []


class Campaign:
    """Builds a complete, self-consistent campaign on disk that the real checker accepts."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.inputs = root / "inputs"
        for prefix, ids in (("lists-five", jni_memory_profile.GROUPS["five"]),
                            ("lists-nine", jni_memory_profile.GROUPS["nine"])):
            directory = self.inputs / prefix
            directory.mkdir(parents=True, exist_ok=True)
            for list_id in ids:
                (directory / f"{list_id}.txt").write_bytes(SMALL_LISTS[list_id])
        self.pids = {"five": [101, 102, 103], "nine": [201, 202, 203]}
        for group, pids in self.pids.items():
            for index, pid in enumerate(pids, start=1):
                self.write_run(group, index, pid)
        jni_memory_profile.manifest_targets(self.root)  # touch, for clarity
        self.seal()

    # ---- per-run construction ---------------------------------------------------------------

    def run_dir(self, group: str, index: int) -> Path:
        return self.root / f"{group}-run{index:02d}"

    def artifacts(self, group: str, role: str) -> dict[str, bytes]:
        """Artifact bodies for one side of the A/B control."""
        rule = (
            b"||ab-memory.test^$xmlhttprequest,removeparam=/^old=/\n"
            if role == "a"
            else b"||ab-memory.test^$xmlhttprequest,removeparam=/^new=/\n"
        )
        return {
            "dns.bin": envelope(f"dns-{group}".encode()),
            "engine.bin": envelope(f"engine-{group}".encode()),
            "extras.txt": envelope(b"||plain.test^$popup\n" + rule),
        }

    def write_run(self, group: str, index: int, pid: int) -> Path:
        directory = self.run_dir(group, index)
        directory.mkdir(parents=True)
        artifacts = {}
        for role in ("a", "b"):
            side = directory / f"compiled-{role}"
            side.mkdir()
            bodies = self.artifacts(group, role)
            facts = {}
            for name, raw in bodies.items():
                path = side / name
                path.write_bytes(raw)
                payload = raw[20:]
                facts[name] = {
                    "artifact": name,
                    "path": str(path),
                    "bytes": len(raw),
                    "file_sha256": hashlib.sha256(raw).hexdigest(),
                    "payload_sha256": hashlib.sha256(payload).hexdigest(),
                    "payload_bytes": len(payload),
                    "payload_token": f"sha256:{hashlib.sha256(payload).hexdigest()}:{len(payload)}",
                }
            artifacts[role] = facts

        document = self.document(group, index, pid, directory, artifacts)
        (directory / "run.json").write_text(json.dumps(document, indent=1) + "\n")
        (directory / "journal.jsonl").write_text(self.journal(document))
        (directory / "command.json").write_text(
            json.dumps(
                {
                    "argv": [
                        "i2_jni_memory_profile",
                        "--group",
                        group,
                        "--run",
                        str(index),
                    ],
                    "started_at": "2026-11-14T00:00:00+00:00",
                    "returncode": 0,
                    "group": group,
                    "index": index,
                },
                indent=1,
            )
            + "\n"
        )
        return directory

    def document(self, group: str, index: int, pid: int, directory: Path, artifacts: dict) -> dict:
        order = jni_memory_profile.GROUPS[group]
        lists = []
        for list_id in order:
            path = self.inputs / f"lists-{group}" / f"{list_id}.txt"
            raw = path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            lists.append(
                {
                    "id": list_id,
                    "path": str(path),
                    "bytes": len(raw),
                    "sha256": digest,
                    "lines": len(raw.decode().splitlines()),
                    "expected_bytes": len(raw),
                    "expected_sha256": digest,
                }
            )

        effect_a = jni_memory_profile.derive_effect_url(jni_memory_profile.AB_RULE_A)
        effect_b = jni_memory_profile.derive_effect_url(jni_memory_profile.AB_RULE_B)

        def counts(live: int, peak: int | None = None) -> dict:
            value = {"live_bytes": live, "live_mib": live / (1024 * 1024), "scope": "test"}
            if peak is not None:
                value["peak_bytes"] = peak
                value["peak_mib"] = peak / (1024 * 1024)
                value["peak_scope"] = "this operation's own window"
            return value

        def window(peak: int, live: int, start_ns: int) -> dict:
            return {
                "operation": "test",
                "started_monotonic_ns": start_ns,
                "ended_monotonic_ns": start_ns + 1_000_000,
                "duration_ms": 1.0,
                "started_live_bytes": live,
                "ended_live_bytes": live,
                "peak_bytes": peak,
                "peak_mib": peak / (1024 * 1024),
                "retained_bytes": 0,
                "scope": "this operation only",
            }

        steady = 40 * 1024 * 1024
        tokens = {
            role: {name: artifacts[role][name]["payload_token"] for name in artifacts[role]}
            for role in ("a", "b")
        }

        def identities(role: str) -> dict:
            return {
                "dns": tokens[role]["dns.bin"],
                "engine": tokens[role]["engine.bin"],
                "extras": tokens[role]["extras.txt"],
            }

        smaps = {"Rss": 90000, "Pss_Anon": 80000, "Anonymous": 80000, "Private_Dirty": 80000}

        points = [
            self.point("process-baseline", pid, counts(4096), None, "no-handle-yet", None, smaps, None),
            self.point(
                "compiled-a", pid, counts(400_000, 118 * 1024 * 1024),
                window(118 * 1024 * 1024, 400_000, 10), "released", None, smaps, None,
            ),
            self.point(
                "started-a", pid, counts(steady, 119 * 1024 * 1024),
                window(119 * 1024 * 1024, steady, 20), "live", 1, smaps, identities("a"),
            ),
            self.point(
                "first-removeparam-evaluation", pid, counts(steady + 4096, steady + 100_000),
                window(steady + 100_000, steady + 4096, 30), "live", 1, smaps, identities("a"),
            ),
            self.point(
                "unchanged-reloads-done", pid, counts(steady + 4096, steady + 600_000),
                window(steady + 600_000, steady + 4096, 40), "live", 1, smaps, identities("a"),
            ),
            self.point(
                "compiled-b", pid, counts(steady + 8192, 160 * 1024 * 1024),
                window(160 * 1024 * 1024, steady + 8192, 50), "live", 1, smaps, identities("a"),
            ),
            self.point(
                "reloaded-b", pid, counts(steady, 106 * 1024 * 1024),
                window(106 * 1024 * 1024, steady, 60), "live", 2, smaps, identities("b"),
            ),
            self.point("settled", pid, counts(steady), None, "live", 2, smaps, identities("b")),
        ]
        settled = points.pop()
        settled["generation"] = 2 + jni_memory_profile.AB_ROUNDS

        rounds = []
        for number in range(1, jni_memory_profile.UNCHANGED_RELOADS + 1):
            rounds.append(
                {
                    "kind": "unchanged",
                    "round": number,
                    "returned": True,
                    "generation": 1,
                    "objects_reused": True,
                    "effect_url": effect_a,
                    "effect_ok": True,
                    "identities_match_ondisk": True,
                    "window": window(steady + 600_000 + number, steady + 4096, 100 + number),
                }
            )
        generation = 2
        for number in range(1, jni_memory_profile.AB_ROUNDS + 1):
            generation += 1
            loaded = "a" if number % 2 == 1 else "b"
            rounds.append(
                {
                    "kind": "ab",
                    "round": number,
                    "loaded": loaded,
                    "returned": True,
                    "generation": generation,
                    "effect_url": effect_a if loaded == "a" else effect_b,
                    "effect_expected": effect_a if loaded == "a" else effect_b,
                    "identities_match_ondisk": True,
                    "previous_rules_released": True,
                    "filter_object_stable": True,
                    "window": window(106 * 1024 * 1024 + number, steady, 200 + number),
                }
            )
            # The window name carries the peak, so no two rounds are byte-identical.
            rounds[-1]["window"]["ended_monotonic_ns"] += number
            points.append(self.point(
                f"ab-round-{number:02}", pid, counts(steady, rounds[-1]["window"]["peak_bytes"]),
                copy.deepcopy(rounds[-1]["window"]), "live", generation, smaps, identities(loaded),
            ))
        points.append(settled)

        ab_peak = max(
            item["window"]["peak_bytes"] for item in rounds if item["kind"] == "ab"
        )
        unchanged_peak = max(
            item["window"]["peak_bytes"] for item in rounds if item["kind"] == "unchanged"
        )
        # `unchanged-reloads-done` must report the highest of the unchanged rounds' windows, exactly as
        # the probe does; otherwise the summary and the rounds describe different observations.
        for point in points:
            if point["phase"] == "unchanged-reloads-done":
                point["window"] = copy.deepcopy(max(
                    (r for r in rounds if r["kind"] == "unchanged"),
                    key=lambda r: r["window"]["peak_bytes"],
                )["window"])
                point["counted"]["peak_bytes"] = unchanged_peak
                point["counted"]["peak_mib"] = unchanged_peak / (1024 * 1024)

        started_a = next(p for p in points if p["phase"] == "started-a")["window"]["peak_bytes"]
        stopped = self.point(
            "stopped", pid, counts(500_000, steady + 700_000),
            window(steady + 700_000, 500_000, 300), "released", None, smaps, None,
        )
        points.append(stopped)

        summary = {
            "baseline_live_bytes": 4096,
            "holding_live_bytes": steady,
            "post_stop_live_bytes": 500_000,
            "released_by_stop_bytes": steady - 500_000,
            "unchanged_reload_peak_bytes": unchanged_peak,
            "reload_peak_bytes": ab_peak,
            "unchanged_reload_excess_bytes": unchanged_peak - (steady + 4096),
            "reload_excess_max_bytes": ab_peak - steady,
            "holding_rss_kib": 90000,
            "scope": "test",
        }

        assertions = [
            {"name": f"control/{number}", "ok": True, "detail": ""} for number in range(1, 22)
        ]

        return {
            "schema": jni_memory_profile.SCHEMA,
            "run_id": f"{group}-r{index}",
            "group": group,
            "formal": True,
            "run_index": index,
            "pid": pid,
            "started_unix_ns": 1_700_000_000_000_000_000 + index,
            "duration_seconds": 10.0,
            "note": "synthetic campaign for the checker's own tests",
            "binary": {"path": "test", "bytes": 1, "sha256": "a" * 64},
            "work_dir": str(directory),
            "journal": str(directory / "journal.jsonl"),
            "inputs": {
                "lists_dir": str(self.inputs / f"lists-{group}"),
                "lists": lists,
                "user_rule_a": "||ab-memory.test^$xmlhttprequest,removeparam=/^old=/",
                "user_rule_a_sha256": "b" * 64,
                "user_rule_b": "||ab-memory.test^$xmlhttprequest,removeparam=/^new=/",
                "user_rule_b_sha256": "c" * 64,
                "effect_url": "https://ab-memory.test/p?old=1&new=2&keep=3",
                "expected_with_a": effect_a,
                "expected_with_b": effect_b,
            },
            "artifacts": {
                "roles": {role: str(directory / f"compiled-{role}") for role in ("a", "b")},
                "by_dir": {
                    str(directory / f"compiled-{role}"): artifacts[role] for role in ("a", "b")
                },
            },
            "points": points,
            "rounds": rounds,
            "assertions": assertions,
            "assertion_count": len(assertions),
            "failures": [],
            "summary": summary,
            "result": "pass",
        }

    @staticmethod
    def point(phase, pid, counted, window, handle_state, generation, smaps, identities) -> dict:
        return {
            "phase": phase,
            "note": "synthetic",
            "monotonic_ns": 1,
            "elapsed_seconds": 0.1,
            "pid": pid,
            "run_id": "synthetic",
            "group": "five",
            "formal": True,
            "handle_state": handle_state,
            "generation": generation,
            "identities": identities,
            "counted": counted,
            "window": window,
            "ondisk_identity": {"dns.bin": {}} if identities is not None else None,
            "smaps_source": "/proc/self/smaps_rollup",
            "smaps_unit": "kB",
            "smaps": smaps,
            "fd_count": 5 if handle_state != "live" else 10,
            "thread_count": 1 if handle_state != "live" else 3,
            "vm_peak_kib": 400 * 1024,
            "weaks": {name: 1 if handle_state == "live" else 0 for name in
                      ("filter_strong", "dns_strong", "engine_strong", "extras_strong")},
        }

    @staticmethod
    def journal(document: dict) -> str:
        lines = []
        for point in document["points"]:
            lines.append(json.dumps({"record": "point", "value": point}))
        for item in document["rounds"]:
            lines.append(json.dumps({"record": "round", "value": item}))
        for item in document["assertions"]:
            lines.append(json.dumps({"record": "assertion", "value": item}))
        return "\n".join(lines) + "\n"

    # ---- sealing ----------------------------------------------------------------------------

    def seal(self) -> None:
        jni_memory_profile.write_manifest.__wrapped__ = None
        entries = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and path.name != "MANIFEST.sha256":
                entries.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(self.root)}")
        (self.root / "MANIFEST.sha256").write_text("\n".join(entries) + "\n")

    def rewrite(self, group: str, index: int, document: dict) -> None:
        directory = self.run_dir(group, index)
        (directory / "run.json").write_text(json.dumps(document, indent=1) + "\n")
        (directory / "journal.jsonl").write_text(self.journal(document))
        self.seal()


class CampaignTest(unittest.TestCase):
    """A complete synthetic campaign: one shared fixture, one mutation per test."""

    @classmethod
    def setUpClass(cls) -> None:
        # The real five-list bodies are 22 MB each, so the synthetic campaign registers its own small
        # ones as canonical for the duration of this class. Everything restored afterwards, so a test
        # that uses the real manifest (RealPackageTest) cannot inherit the substitution.
        cls._saved_canonical = dict(jni_memory_profile.CANONICAL)
        cls._saved_groups = copy.deepcopy(jni_memory_profile.GROUPS)
        for list_id, body in SMALL_LISTS.items():
            jni_memory_profile.CANONICAL[list_id] = (
                len(body),
                hashlib.sha256(body).hexdigest(),
            )

    @classmethod
    def tearDownClass(cls) -> None:
        jni_memory_profile.CANONICAL.clear()
        jni_memory_profile.CANONICAL.update(cls._saved_canonical)
        jni_memory_profile.GROUPS = cls._saved_groups

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "campaign"
        self.campaign = Campaign(self.root)
        self.document_path = self.campaign.run_dir("five", 1) / "run.json"
        self.document = json.loads(self.document_path.read_text())

    # ---- helpers ----------------------------------------------------------------------------

    def verdict(self):
        try:
            return 0, jni_memory_profile.check_tree(self.root)
        except jni_memory_profile.Refusal as error:
            return 1, str(error)

    def refuse(self, expected: str) -> None:
        code, detail = self.verdict()
        self.assertNotEqual(code, 0, f"expected a refusal containing {expected!r}, got acceptance")
        self.assertIn(expected, str(detail))

    def accept(self) -> dict:
        code, detail = self.verdict()
        self.assertEqual(code, 0, f"expected acceptance, got: {detail}")
        return detail

    # ---- positives --------------------------------------------------------------------------

    def test_a_complete_campaign_is_accepted(self) -> None:
        report = self.accept()
        self.assertEqual(report["groups"], ["five", "nine"])
        self.assertEqual(len(report["runs"]), 6)
        self.assertTrue(report["manifest"]["verified"])

    def test_the_campaign_is_accepted_after_every_refusal(self) -> None:
        # The reviewer's restored positive control: nine refusals in a row must not leave the checker
        # in a state where it refuses a good package.
        original = self.document_path.read_bytes()
        for mutation in (
            lambda d: d["summary"].update(reload_peak_bytes=2**60),
            lambda d: d["summary"].update(unchanged_reload_peak_bytes=-1),
            lambda d: next(p for p in d["points"] if p["phase"] == "started-a")["identities"].update(
                extras="sha256:" + "0" * 64 + ":1"
            ),
        ):
            changed = copy.deepcopy(self.document)
            mutation(changed)
            self.campaign.rewrite("five", 1, changed)
            self.assertNotEqual(self.verdict()[0], 0)
            self.campaign.rewrite("five", 1, json.loads(original))
        self.campaign.seal()
        self.accept()

    # ---- summary ----------------------------------------------------------------------------

    def test_summary_reload_peak_not_observed(self) -> None:
        self.document["summary"]["reload_peak_bytes"] = 2**60
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("summary reload_peak_bytes")

    def test_negative_unchanged_peak(self) -> None:
        self.document["summary"]["unchanged_reload_peak_bytes"] = -1
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("summary unchanged_reload_peak_bytes")

    def test_invented_release_figure(self) -> None:
        self.document["summary"]["released_by_stop_bytes"] += 4096
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("summary released_by_stop_bytes")

    def test_excess_measured_against_the_wrong_instant(self) -> None:
        # The first report subtracted a later steady state instead of the same instant, turning
        # 0.50 MiB of excess into 0.30. The summary must use the same-instant figure.
        self.document["summary"]["unchanged_reload_excess_bytes"] += 1024
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("summary unchanged_reload_excess_bytes")

    # ---- identity ---------------------------------------------------------------------------

    def test_loaded_extras_identity_does_not_match_disk(self) -> None:
        next(p for p in self.document["points"] if p["phase"] == "started-a")["identities"].update(
            extras="sha256:" + "0" * 64 + ":1"
        )
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("the artifact of record for role a")

    def test_loaded_dns_identity_does_not_match_disk(self) -> None:
        next(p for p in self.document["points"] if p["phase"] == "reloaded-b")["identities"].update(
            dns="sha256:" + "1" * 64 + ":9"
        )
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("the artifact of record for role b")

    def test_artifact_payload_hash_does_not_match_the_file(self) -> None:
        roles = self.document["artifacts"]["roles"]
        side = self.document["artifacts"]["by_dir"][roles["b"]]
        side["extras.txt"]["payload_sha256"] = "2" * 64
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("payload hashes to")

    def test_the_artifacts_are_not_extras_only(self) -> None:
        # Move engine.bin on side B: the case is no longer the transition it claims.
        directory = self.campaign.run_dir("five", 1)
        path = directory / "compiled-b" / "engine.bin"
        path.write_bytes(envelope(b"engine-five-different"))
        roles = self.document["artifacts"]["roles"]
        side = self.document["artifacts"]["by_dir"][roles["b"]]
        raw = path.read_bytes()
        side["engine.bin"]["payload_sha256"] = hashlib.sha256(raw[20:]).hexdigest()
        side["engine.bin"]["payload_bytes"] = len(raw[20:])
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("also moved engine.bin")

    def test_the_ab_rule_is_not_in_the_extras(self) -> None:
        directory = self.campaign.run_dir("five", 1)
        path = directory / "compiled-b" / "extras.txt"
        raw = envelope(b"||plain.test^$popup\nremoveparam=/^other=/")
        path.write_bytes(raw)
        roles = self.document["artifacts"]["roles"]
        side = self.document["artifacts"]["by_dir"][roles["b"]]
        side["extras.txt"]["payload_sha256"] = hashlib.sha256(raw[20:]).hexdigest()
        side["extras.txt"]["payload_bytes"] = len(raw[20:])
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("does not contain")

    def test_self_declared_expectation_that_contradicts_the_rule(self) -> None:
        self.document["inputs"]["expected_with_a"] = "https://ab-memory.test/p?old=1&new=2&keep=3"
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("the A/B rule implies")

    # ---- observations -----------------------------------------------------------------------

    def test_missing_phase_peak_observation(self) -> None:
        next(p for p in self.document["points"] if p["phase"] == "started-a")["counted"].pop(
            "peak_bytes"
        )
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("no operation peak in `counted`")

    def test_counted_peak_disagrees_with_the_window(self) -> None:
        point = next(p for p in self.document["points"] if p["phase"] == "started-a")
        point["counted"]["peak_bytes"] += 1
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("its window peak is")

    def test_an_operation_point_without_a_window(self) -> None:
        # The exact defect the review found: `started-a` reporting an earlier phase's high-water mark.
        point = next(p for p in self.document["points"] if p["phase"] == "started-a")
        point["window"] = None
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("no measurement window of its own")

    def test_a_state_point_claiming_an_operation_window(self) -> None:
        point = next(p for p in self.document["points"] if p["phase"] == "settled")
        point["window"] = {
            "operation": "x",
            "started_monotonic_ns": 1,
            "ended_monotonic_ns": 2,
            "started_live_bytes": 1,
            "ended_live_bytes": 1,
            "peak_bytes": 1,
        }
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("claims an operation window")

    def test_a_window_peak_below_its_own_live_heap(self) -> None:
        point = next(p for p in self.document["points"] if p["phase"] == "started-a")
        point["window"]["peak_bytes"] = 1024
        point["counted"]["peak_bytes"] = 1024
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("below its own live heap")

    def test_a_window_peak_above_the_address_space(self) -> None:
        point = next(p for p in self.document["points"] if p["phase"] == "started-a")
        point["window"]["peak_bytes"] = 2**60
        point["counted"]["peak_bytes"] = 2**60
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("exceeds the process address-space high-water mark")

    def test_a_removed_phase(self) -> None:
        self.document["points"] = [
            p for p in self.document["points"] if p["phase"] != "settled"
        ]
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("required phase settled was never observed")

    def test_no_smaps_fields(self) -> None:
        next(p for p in self.document["points"] if p["phase"] == "started-a")["smaps"] = None
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("no smaps_rollup fields")

    # ---- inputs -----------------------------------------------------------------------------

    def test_actual_input_body_changed_but_declared_hash_unchanged(self) -> None:
        # The review's case: the body is edited on disk while the document still declares the
        # original size and hash. Only re-hashing the file catches it.
        body = self.campaign.inputs / "lists-five" / "adguard-base.txt"
        body.write_bytes(body.read_bytes() + b"\n! mutation\n")
        self.campaign.seal()
        self.refuse("does not describe the compiled input")

    def test_a_declared_hash_that_contradicts_the_manifest(self) -> None:
        self.document["inputs"]["lists"][0]["sha256"] = "9" * 64
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("the manifest says")

    def test_a_reordered_list_set(self) -> None:
        lists = self.document["inputs"]["lists"]
        lists[0], lists[1] = lists[1], lists[0]
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("must compile")

    # ---- rounds -----------------------------------------------------------------------------

    def test_one_unchanged_observation_duplicated_twenty_times(self) -> None:
        unchanged = [r for r in self.document["rounds"] if r["kind"] == "unchanged"][0]
        self.document["rounds"] = (
            [copy.deepcopy(unchanged) for _ in range(20)]
            + [r for r in self.document["rounds"] if r["kind"] == "ab"]
        )
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("each exactly once")

    def test_identical_rounds_with_renumbered_indices(self) -> None:
        unchanged = [r for r in self.document["rounds"] if r["kind"] == "unchanged"][0]
        copies = []
        for number in range(1, 21):
            item = copy.deepcopy(unchanged)
            item["round"] = number
            copies.append(item)
        self.document["rounds"] = copies + [
            r for r in self.document["rounds"] if r["kind"] == "ab"
        ]
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("one observation repeated")

    def test_wrong_ab_effect_and_self_declared_expected(self) -> None:
        # Both the actual URL and the round's own `effect_expected` are moved together, so trusting
        # either would accept it. The verdict comes from the artifact's rule.
        first = next(r for r in self.document["rounds"] if r["kind"] == "ab")
        first["effect_url"] = "https://ab-memory.test/p?old=1&new=2&keep=3"
        first["effect_expected"] = "https://ab-memory.test/p?old=1&new=2&keep=3"
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("the rule in force requires")

    def test_unchanged_reload_that_moved_the_generation(self) -> None:
        [r for r in self.document["rounds"] if r["kind"] == "unchanged"][3]["generation"] = 2
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("moved the generation")

    def test_ab_alternation_out_of_order(self) -> None:
        ab = [r for r in self.document["rounds"] if r["kind"] == "ab"]
        ab[0]["loaded"], ab[1]["loaded"] = ab[1]["loaded"], ab[0]["loaded"]
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("the alternation requires")

    def test_ab_generation_gap(self) -> None:
        ab = [r for r in self.document["rounds"] if r["kind"] == "ab"]
        for item in ab[5:]:
            item["generation"] += 1
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("advanced the generation")

    def test_ab_left_the_previous_rules_alive(self) -> None:
        [r for r in self.document["rounds"] if r["kind"] == "ab"][4][
            "previous_rules_released"
        ] = False
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("left the previous rule set strongly referenced")

    def test_too_few_ab_rounds(self) -> None:
        self.document["rounds"] = [
            r for r in self.document["rounds"] if not (r["kind"] == "ab" and r["round"] > 6)
        ]
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("A/B rounds recorded")

    # ---- resources, journal, command --------------------------------------------------------

    def test_nine_list_body_cannot_borrow_five_list_copy(self) -> None:
        path = self.root / "inputs/lists-nine/adguard-base.txt"
        path.write_bytes(path.read_bytes() + b"! nine-only mutation\n")
        self.campaign.seal()
        self.refuse("on disk, the manifest says")

    def test_missing_nine_list_body_cannot_borrow_five_list_copy(self) -> None:
        (self.root / "inputs/lists-nine/adguard-base.txt").unlink()
        self.campaign.seal()
        self.refuse("nine input body")

    def test_journal_content_conflict_is_refused(self) -> None:
        path = self.document_path.with_name("journal.jsonl")
        records = [json.loads(line) for line in path.read_text().splitlines()]
        next(r["value"] for r in records if r["record"] == "round")["effect_url"] = "https://wrong.test/"
        path.write_text("".join(json.dumps(r) + "\n" for r in records))
        self.campaign.seal()
        self.refuse("content does not match the report")

    def test_json_float_roundtrip_does_not_reject_real_observation(self) -> None:
        value = self.document["points"][1]["counted"]["live_mib"]
        self.document["points"][1]["counted"]["live_mib"] = math.nextafter(value, math.inf)
        self.document_path.write_text(json.dumps(self.document))
        self.campaign.seal()
        self.accept()

    def test_integer_byte_counts_are_compared_exactly(self) -> None:
        self.document["points"][1]["counted"]["live_bytes"] += 1
        self.document_path.write_text(json.dumps(self.document))
        self.campaign.seal()
        self.refuse("content does not match the report")

    def test_float_tolerance_cannot_hide_a_changed_measurement(self) -> None:
        self.document["points"][1]["counted"]["live_mib"] += 0.01
        self.document_path.write_text(json.dumps(self.document))
        self.campaign.seal()
        self.refuse("content does not match the report")

    def test_each_ab_point_checks_loaded_identity(self) -> None:
        next(p for p in self.document["points"] if p["phase"] == "ab-round-01")["identities"]["extras"] = "wrong"
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("the artifact of record for role a")

    def test_each_ab_point_checks_generation(self) -> None:
        next(p for p in self.document["points"] if p["phase"] == "ab-round-01")["generation"] = 999
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("generation does not match its round")

    def test_settled_generation_matches_last_ab_round(self) -> None:
        next(p for p in self.document["points"] if p["phase"] == "settled")["generation"] = 2
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("settled generation does not match")

    def test_ab_point_window_matches_round(self) -> None:
        next(p for p in self.document["points"] if p["phase"] == "ab-round-01")["window"]["started_monotonic_ns"] = 1
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("window does not match its round")

    def test_stopped_rule_must_have_no_strong_owner(self) -> None:
        next(p for p in self.document["points"] if p["phase"] == "stopped")["weaks"]["extras_strong"] = 1
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("stopped extras_strong")

    def add_trim_point(self) -> dict:
        point = copy.deepcopy(next(p for p in self.document["points"] if p["phase"] == "settled"))
        point["phase"] = "trim-diagnostic-rules-held"
        point["smaps"] = {name: copy.deepcopy(point["smaps"]) for name in ("before", "after_first", "after_second")}
        source = next(p for p in self.document["points"] if p["phase"] == "started-a")["window"]
        point["windows"] = [copy.deepcopy(source), copy.deepcopy(source)]
        self.document["points"].insert(-1, point)
        return point

    def test_complete_trim_readings_are_accepted(self) -> None:
        self.add_trim_point()
        self.campaign.rewrite("five", 1, self.document)
        self.accept()

    def test_missing_trim_reading_is_refused(self) -> None:
        point = self.add_trim_point()
        del point["smaps"]["after_first"]
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("after_first is missing smaps")

    def test_missing_trim_window_is_refused(self) -> None:
        self.add_trim_point()["windows"].pop()
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("two separate trim windows")

    def test_descriptors_left_open(self) -> None:
        point = next(p for p in self.document["points"] if p["phase"] == "stopped")
        point["fd_count"] = 99
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("descriptors remain after the stop")

    def test_stop_that_did_not_release_the_handle(self) -> None:
        next(p for p in self.document["points"] if p["phase"] == "stopped")[
            "handle_state"
        ] = "live"
        self.campaign.rewrite("five", 1, self.document)
        self.refuse("not a released handle")

    def test_journal_contains_no_observations(self) -> None:
        (self.campaign.run_dir("five", 1) / "journal.jsonl").write_text("{}\n")
        self.campaign.seal()
        self.refuse("a journal record names no kind")

    def test_journal_missing_a_phase(self) -> None:
        directory = self.campaign.run_dir("five", 1)
        lines = [
            line
            for line in directory.joinpath("journal.jsonl").read_text().splitlines()
            if '"phase": "settled"' not in line
        ]
        directory.joinpath("journal.jsonl").write_text("\n".join(lines) + "\n")
        self.campaign.seal()
        self.refuse("do not match the journal")

    def test_command_disagreeing_with_the_document(self) -> None:
        path = self.campaign.run_dir("five", 1) / "command.json"
        command = json.loads(path.read_text())
        command["group"] = "nine"
        path.write_text(json.dumps(command))
        self.campaign.seal()
        self.refuse("the invocation ran group")

    # ---- campaign completeness --------------------------------------------------------------

    def test_all_three_nine_list_runs_missing(self) -> None:
        for index in (1, 2, 3):
            directory = self.campaign.run_dir("nine", index)
            for path in sorted(directory.rglob("*"), reverse=True):
                if path.is_file():
                    path.unlink()
                else:
                    path.rmdir()
            directory.rmdir()
        self.campaign.seal()
        self.refuse("the nine-list group is missing entirely")

    def test_too_few_processes(self) -> None:
        directory = self.campaign.run_dir("five", 3)
        for path in sorted(directory.rglob("*"), reverse=True):
            if path.is_file():
                path.unlink()
            else:
                path.rmdir()
        directory.rmdir()
        self.campaign.seal()
        self.refuse("2 independent process(es), 3 required")

    def test_two_runs_share_a_pid(self) -> None:
        for index, pid in ((1, 101), (2, 101), (3, 101)):
            document = json.loads((self.campaign.run_dir("five", index) / "run.json").read_text())
            document["pid"] = pid
            self.campaign.rewrite("five", index, document)
        self.refuse("share a pid")

    # ---- manifest ---------------------------------------------------------------------------

    def test_a_file_present_but_unlisted(self) -> None:
        (self.campaign.root / "five-run01" / "extra.log").write_text("smuggled")
        self.refuse("not in the MANIFEST")

    def test_a_listed_file_that_is_gone(self) -> None:
        (self.campaign.run_dir("five", 2) / "stderr.log").unlink(missing_ok=True)
        (self.campaign.run_dir("five", 2) / "run.json").unlink()
        self.refuse("does not exist")

    def test_the_manifest_excludes_itself(self) -> None:
        text = (self.campaign.root / "MANIFEST.sha256").read_text()
        self.assertNotIn("MANIFEST.sha256", text)
        self.accept()

    def test_a_manifest_listing_itself_is_refused(self) -> None:
        path = self.campaign.root / "MANIFEST.sha256"
        path.write_text(path.read_text() + "0" * 64 + "  MANIFEST.sha256\n")
        self.refuse("lists itself")


class ThresholdTest(unittest.TestCase):
    """The checker must not acquire a device memory verdict by accident."""

    def test_the_device_threshold_is_never_compared_against(self) -> None:
        source = (SCRIPTS / "jni_memory_profile.py").read_text(encoding="utf-8")
        for name in ("THRESHOLD", "threshold_mib", "pss_threshold", "MIB_LIMIT", "LIMIT_MIB"):
            self.assertNotIn(f"{name} =", source, f"{name} is assigned in the checker")
        for line_number, line in enumerate(source.splitlines(), start=1):
            if "84.6" not in line:
                continue
            for operator in ("<=", ">=", "<", ">"):
                self.assertNotIn(
                    f"{operator} 84.6",
                    line,
                    f"line {line_number} compares against the device threshold: {line!r}",
                )

    def test_no_pss_verdict_is_printed(self) -> None:
        source = (SCRIPTS / "jni_memory_profile.py").read_text(encoding="utf-8")
        self.assertNotIn("def pss_verdict", source)
        for line_number, line in enumerate(source.splitlines(), start=1):
            if "PASS" not in line:
                continue
            self.assertFalse(
                line.lstrip().startswith(("print(", "sys.stdout")),
                f"line {line_number} prints PASS: {line!r}",
            )

    def test_the_report_states_what_it_does_not_claim(self) -> None:
        source = (SCRIPTS / "jni_memory_profile.py").read_text(encoding="utf-8")
        self.assertIn("not_claimed", source)
        self.assertIn("Android PSS", source)


class RealPackageTest(unittest.TestCase):
    """When the real sealed campaign is present, the real checker must accept it end to end."""

    def test_the_shipped_campaign_verifies(self) -> None:
        root = os.environ.get("ZSHIELD_JNI_EVIDENCE")
        if not root:
            self.skipTest("set ZSHIELD_JNI_EVIDENCE to a sealed campaign directory to run this")
        report = jni_memory_profile.check_tree(Path(root))
        self.assertEqual(report["groups"], ["five", "nine"])
        self.assertEqual(len(report["runs"]), 6)

    def test_real_probe_trim_lifecycle(self) -> None:
        binary = os.environ.get("ZSHIELD_JNI_PROBE")
        if not binary:
            self.skipTest("set ZSHIELD_JNI_PROBE to run the real trim lifecycle")
        with tempfile.TemporaryDirectory() as work:
            result = subprocess.run([str(Path(binary).resolve()), "--work", work, "--lists", work,
                                     "--group", "selftest", "--run", "1", "--trim-diagnostic"],
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            document = json.loads(result.stdout)
            self.assertEqual(document["result"], "pass")
            points = jni_memory_profile.verify_points(document, work)
            jni_memory_profile.verify_resources(document, work, points)
            summary = jni_memory_profile.verify_summary(document, work, points)
            self.assertEqual(summary["holding_live_bytes"], points["settled"]["counted"]["live_bytes"])
            for phase in ("trim-diagnostic-rules-held", "trim-diagnostic-after-stop"):
                self.assertEqual(len(points[phase]["windows"]), 2)


if __name__ == "__main__":
    unittest.main()
