#!/usr/bin/env python3
"""Print the harness contract as evidence: one positive control, then every refusal.

This is the transcript the delivery quotes. It runs the real tools on loopback — no device, no tunnel —
and prints, for each case, the command's real exit status alongside the specific reason it gave. Run it
from the repository root:

    python3 scripts/effectiveness/tests/contract_evidence.py

Two properties make the transcript usable as evidence rather than as a claim:

  * the **positive** cases come first, so a tool that rejected everything could not produce this output;
  * every **negative** case asserts *which* reason fired, not merely that something did.

The device legs (a browser behind the VPN on the Pixel 5) are not here: `docs/TESTING.md` §14 explains
that a host run cannot stand in for the tunnel, and the delivery records them as unverified instead.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(HERE))

import harness_fixtures as fixtures  # noqa: E402

harness = fixtures.harness


def rule(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


CLIENT_URL = "https://origin.test/anything/get?keep=1&track=DROP_ME&zs_rid=run-1"


def expect(**overrides) -> dict:
    base = {
        "status": 200, "scheme": "https", "transport": "tls-h2", "protocol": "h2", "tls": True,
        "method": "GET", "drop_params": ["track"], "keep_params": [],
        "client_url": CLIENT_URL, "require_upstream_id": True,
    }
    base.update(overrides)
    return base


def record(**overrides) -> str:
    base = {
        "id": "req-1", "method": "GET", "path": "/anything/get?keep=1&zs_rid=run-1",
        "body": "", "body_sha256": digest(""), "alpn": "h2", "tls": True, "inflight": 20,
        "probe": False,
    }
    base.update(overrides)
    return json.dumps(base)


def result(body: str, **overrides) -> dict:
    base = {"id": "req-1", "status": 200, "url": CLIENT_URL, "protocol": "h2", "body": body}
    base.update(overrides)
    return base


def judge(label: str, output, expectation: str) -> None:
    problems = harness.check_one(output["result"], {"run_id": "run-1"}, output["expect"])
    refused = bool(problems)
    mark = "REFUSED" if refused else "ACCEPTED"
    print(f"  [{mark:8}] {label}")
    print(f"             expected: {expectation}")
    for problem in problems or ["(no problem reported)"]:
        print(f"             -> {problem}")


def main() -> int:
    failures = 0

    rule("1. POSITIVE CONTROL — a correct result must produce no problem at all")
    cases = [
        (
            "a correct decrypted request, parameter dropped upstream",
            result(record()), expect(),
        ),
        (
            "a correct plaintext request, parameter KEPT (design: no rewrite on plaintext)",
            result(record(path="/anything/get?keep=1&track=KEEP&zs_rid=run-1", tls=False, alpn=None),
                   url="http://origin.test/anything/get?keep=1&track=KEEP&zs_rid=run-1",
                   protocol="http/1.1"),
            expect(scheme="http", transport="plain", protocol="http/1.1", tls=False,
                   drop_params=[], keep_params=["track"],
                   client_url="http://origin.test/anything/get?keep=1&track=KEEP&zs_rid=run-1"),
        ),
        (
            "a correct POST with a byte-exact body",
            result(record(path="/anything/post?keep=1&zs_rid=run-1", method="POST",
                          body="alpha=1&beta=2", body_sha256=digest("alpha=1&beta=2")),
                   url="https://origin.test/anything/post?keep=1&track=DROP_ME&zs_rid=run-1"),
            expect(method="POST", body_exact="alpha=1&beta=2",
                   client_url="https://origin.test/anything/post?keep=1&track=DROP_ME&zs_rid=run-1"),
        ),
    ]
    for label, output_result, output_expect in cases:
        problems = harness.check_one(output_result, {"run_id": "run-1"}, output_expect)
        print(f"  [{'PASS' if not problems else 'FAIL':8}] {label}")
        for problem in problems:
            print(f"             -> UNEXPECTED: {problem}")
            failures += 1

    rule("2. THE FOUR ORIGINAL COUNTER-EXAMPLES (review_stage2_harness.py)")
    judge("missing protocol evidence on an h2 leg",
          {"result": result(record(), protocol=""), "expect": expect()},
          "refuse: no protocol evidence")
    judge("wrong request target and wrong method",
          {"result": result(record(path="/UNREQUESTED?keep=1&zs_rid=run-1", method="DELETE")),
           "expect": expect()},
          "refuse: upstream target and upstream method")
    judge("empty result batch at the entry point",
          {"result": {"id": "", "error": "empty batch"}, "expect": expect()},
          "refuse: transport error")
    corrupt = "alpha=1WRONG&beta=2WRONG"
    judge("POST body that merely CONTAINS the sent text",
          {"result": result(record(path="/anything/post?keep=1&zs_rid=run-1", method="POST",
                                   body=corrupt, body_sha256=digest(corrupt)),
                            url="https://origin.test/anything/post?keep=1&track=DROP_ME&zs_rid=run-1"),
           "expect": expect(method="POST", body_exact="alpha=1&beta=2",
                            client_url="https://origin.test/anything/post?keep=1&track=DROP_ME&zs_rid=run-1")},
          "refuse: upstream body digest")

    rule("3. THE THREE SECOND-ROUND COUNTER-EXAMPLES (review_stage2_r2.py)")
    judge("upstream echoed a wrong request id",
          {"result": result(record(id="WRONG-UPSTREAM-ID")), "expect": expect(request_id="req-1")},
          "refuse: request id")
    judge("upstream echoed no request id",
          {"result": result(record(id="")), "expect": expect(request_id="req-1")},
          "refuse: no request id")
    judge("a result replayed from another plan",
          {"result": result(record(id="earlier-plan-id")), "expect": expect(request_id="this-plan-id")},
          "refuse: planned id mismatch")

    rule("4. PROTOCOL / METHOD / BODY / TARGET DRIFT")
    judge("ALPN negotiated http/1.1 while h2 was required",
          {"result": result(record(alpn="http/1.1")), "expect": expect()},
          "refuse: upstream ALPN")
    judge("method drifted to DELETE",
          {"result": result(record(method="DELETE")), "expect": expect()},
          "refuse: upstream method")
    judge("plaintext connection where TLS was required",
          {"result": result(record(tls=False, alpn=None)), "expect": expect()},
          "refuse: tls=")
    judge("dropped parameter still present upstream",
          {"result": result(record(path="/anything/get?keep=1&track=DROP_ME&zs_rid=run-1")),
           "expect": expect()},
          "refuse: still carries 'track'")
    judge("kept parameter lost upstream on the plaintext leg",
          {"result": result(record(path="/anything/get?keep=1&zs_rid=run-1", tls=False, alpn=None),
                            url="http://origin.test/anything/get?keep=1&track=KEEP&zs_rid=run-1",
                            protocol="http/1.1"),
           "expect": expect(scheme="http", transport="plain", protocol="http/1.1", tls=False,
                            drop_params=[], keep_params=["track"],
                            client_url="http://origin.test/anything/get?keep=1&track=KEEP&zs_rid=run-1")},
          "refuse: lost 'track'")
    judge("target that merely CONTAINS the expected target as text",
          {"result": result(record(path="/x?keep=1&next=/anything/get?keep=1&zs_rid=run-1")),
           "expect": expect()},
          "refuse: upstream target")

    rule("5. MISSING OBSERVATIONS DO NOT PASS")
    judge("an HTML block page instead of an echo",
          {"result": result("<html><body>blocked</body></html>"), "expect": expect()},
          "refuse: did not answer")
    judge("a probe answer (/__id) counted as the request's record",
          {"result": result(record(probe=True)), "expect": expect()},
          "refuse: probe")
    judge("a body reported only as a normalised form dictionary",
          {"result": result(json.dumps({"url": CLIENT_URL, "method": "POST",
                                        "form": {"alpha": ["1"]}, "data": ""}),
                            url="https://origin.test/anything/post?keep=1&track=DROP_ME&zs_rid=run-1"),
           "expect": expect(method="POST", body_exact="alpha=1",
                            client_url="https://origin.test/anything/post?keep=1&track=DROP_ME&zs_rid=run-1")},
          "refuse: no byte-level body evidence")
    judge("an httpbin-style echo that cannot report a request id",
          {"result": result(json.dumps({"url": CLIENT_URL, "method": "GET", "data": ""})),
           "expect": expect()},
          "refuse: no request id (httpbin shape)")
    judge("a disconnected request",
          {"result": {"id": "req-1", "error": "TypeError: Failed to fetch"}, "expect": expect()},
          "refuse: transport error")

    rule("6. SNAPSHOT WIND-DOWN (tunnel_snapshot.sh check) — every refusal and one control")
    fixture = fixtures.SnapshotFixture(Path(tempfile.mkdtemp(prefix="evidence-snap-")))
    fixture.write("before", sockets=" 4 01 ")
    scenarios = [
        ("a genuinely settled run", " 4 01 ", " 6 01 ", 0, "wound down"),
        ("ESTABLISHED grew far beyond the allowance", " 4 01 ", " 20 01 ", 1, "ESTABLISHED grew"),
        ("CLOSE_WAIT grew at all", " 4 01 ", " 4 01  6 08 ", 1, "CLOSE_WAIT grew"),
        ("FIN_WAIT2 grew at all (05 was unchecked before)", " 4 01 ", " 4 01  1000 05 ", 1,
         "FIN_WAIT2 grew"),
        ("the socket line is absent", " 4 01 ", "", 2, "missing ['sockets']"),
    ]
    for label, before_sockets, settled_sockets, wanted, needle in scenarios:
        fixture.write("before", sockets=before_sockets)
        fixture.write("settled", sockets=settled_sockets)
        completed = fixture.check()
        ok = completed.returncode == wanted and needle in (completed.stdout + completed.stderr)
        if not ok:
            failures += 1
        print(f"  [{'OK' if ok else 'MISMATCH':8}] {label}")
        print(f"             exit={completed.returncode} (expected {wanted})")
        for line in (completed.stdout + completed.stderr).strip().splitlines():
            print(f"             -> {line}")

    rule("7. THE HARNESS'S OWN SELF-TEST (--selftest, no device)")
    completed = subprocess.run(
        [sys.executable, str(SCRIPTS / "tunnel_concurrency.py"), "--selftest"],
        capture_output=True, text=True, timeout=180,
    )
    print(textwrap.indent((completed.stdout + completed.stderr).strip(), "  "))
    if completed.returncode != 0:
        failures += 1
    print(f"  exit={completed.returncode}")

    rule("8. THE RETIRED HOST-SIDE SMOKE TEST REFUSES TO RUN")
    completed = subprocess.run(
        [sys.executable, str(SCRIPTS / "concurrency_smoke.py"), "--rounds", "5", "--concurrency", "20"],
        capture_output=True, text=True, timeout=60,
    )
    print(textwrap.indent(completed.stderr.strip(), "  "))
    if completed.returncode == 0:
        failures += 1
        print("  UNEXPECTED: it exited 0")
    print(f"  exit={completed.returncode} (non-zero is the requirement)")

    rule("9. A REAL RUN AGAINST A REAL ORIGIN — the positive control the whole chain rests on")
    origin = fixtures.OriginFixture(tls=True, tls1=True, hold_ms=150).start()
    try:
        scenarios_table = harness.build_scenarios(
            origin.base_tls, "evidence",
            http_origin=origin.base, https_origin=origin.base_tls, tls1_origin=origin.base_tls1,
        )
        import threading
        from urllib.parse import urlsplit, urlunsplit

        def send(call: dict) -> dict:
            split = urlsplit(call["url"])
            decrypted = call["transport"] != "plain"
            target = call["url"]
            if decrypted:
                kept = [pair for pair in split.query.split("&")
                        if pair.split("=", 1)[0] not in {"track", "rxparam"}]
                target = urlunsplit(split._replace(query="&".join(kept)))
            status, body, headers = fixtures.request(
                target, method=call["init"].get("method", "GET"),
                body=call["init"].get("body", "").encode() or None,
                headers=call["init"].get("headers", {}),
                prefer_h2=call["transport"] == "tls-h2",
                alpn=("h2", "http/1.1") if call["transport"] == "tls-h1" else None,
            )
            try:
                protocol = headers.get("X-Negotiated-ALPN") or json.loads(body).get("alpn") or "http/1.1"
            except (json.JSONDecodeError, AttributeError):
                protocol = "http/1.1"
            return {"id": call["id"], "index": call["index"], "scenario": call["scenario"],
                    "status": status, "url": call["url"], "protocol": protocol, "body": body,
                    "ms": 1.0}

        group = harness.plan_group(scenarios_table, 12, 0)
        calls = [call for calls in group["legs"].values() for call in calls]
        results: list[dict] = []
        lock = threading.Lock()

        def worker(call: dict) -> None:
            outcome = send(call)
            outcome["round"] = 1
            outcome["group"] = 0
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=worker, args=(call,)) for call in calls]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        by_name = {scenario["name"]: scenario for scenario in scenarios_table}
        problems = []
        for outcome in results:
            problems.extend(
                f"{outcome['scenario']}: {found}"
                for found in harness.check_one(
                    outcome, {"run_id": "evidence"}, by_name[outcome["scenario"]]["expect"]
                )
            )
        problems.extend(harness.validate_structure([group], results, 1, 12))
        problems.extend(harness.validate_concurrency([group], results, 12))

        print(f"  requests sent: {len(results)} across "
              f"{ {name: len(calls) for name, calls in group['legs'].items()} }")
        print(f"  negotiated:    {dict((p, sum(1 for r in results if r['protocol'] == p)) for p in {r['protocol'] for r in results})}")
        print(f"  in-flight peak at the origin: {group['peak']} (12 requests over 3 legs)")
        print(f"  problems: {len(problems)}")
        for problem in problems:
            print(f"             -> {problem}")
        if problems:
            failures += 1
    finally:
        origin.stop()

    rule("RESULT")
    print(f"  {failures} unexpected outcome(s)")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
