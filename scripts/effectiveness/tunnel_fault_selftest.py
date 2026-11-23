#!/usr/bin/env python3
"""Prove that the acceptance harness fails when it should — *through the tunnel*, on the phone.

`--selftest` in `tunnel_concurrency.py` proves the detection logic against a local origin. This
script proves the whole chain: the same checks, the same browser, the same VPN, with the upstream
deliberately misbehaving. It is the difference between "the harness can spot a fault" and "the
harness spots a fault that happened on the device".

The four injections the task card requires, plus a positive control:

  http-500       the upstream answers 500
  wrong-url      the request reaches the upstream at a different URL than the client sent
  post-body      the POST body does not arrive intact
  disconnect     the connection is torn down with no response
  control        a healthy request, which must NOT be reported as a failure

Each case is expressed as a scenario + expectation pair and run through `check_one`, so this
exercises the same code path the acceptance run does. An injection whose expectation is still met is
a **missed** detection, and the script exits non-zero.

Usage:
    scripts/effectiveness/tunnel_fault_selftest.py --origin https://ECHO/anything
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import device_serial  # noqa: E402 - device selection, same rules as every other tool
from tunnel_concurrency import check_one  # noqa: E402 - the checker under test


def say(message: str) -> None:
    print(message, flush=True)


def _acceptance_gate_is_nonzero() -> tuple[bool, str]:
    """Feed the acceptance entry point an empty batch and require a non-zero exit.

    This is the review's first finding, checked directly: a stubbed page that returns `[]` for every
    round produced `PASS: 0 request(s)` and exit 0. The same stub is used here, so the check fails if
    that behaviour ever comes back. It runs in-process with `cdp` replaced, so it needs no device.
    """
    import contextlib
    import importlib.util
    import io
    import types

    module_path = Path(__file__).resolve().parent / "tunnel_concurrency.py"
    spec = importlib.util.spec_from_file_location("zs_gate_probe", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class FakePage:
        def evaluate(self, script, **kwargs):
            if script == "location.href":
                return "https://echo.invalid/"
            if "navigation" in script:
                return "h2"
            return "[]"

    class FakeBrowser:
        @staticmethod
        def attach(*args, **kwargs):
            return FakeBrowser()

        def open(self, *args, **kwargs):
            return FakePage()

    saved_cdp = sys.modules.get("cdp")
    saved_argv = sys.argv
    sys.modules["cdp"] = types.SimpleNamespace(Browser=FakeBrowser)
    sys.argv = [
        "tunnel_concurrency.py",
        "--origin",
        "https://echo.invalid/anything",
        "--rounds",
        "2",
        "--concurrency",
        "4",
    ]
    output = io.StringIO()
    try:
        with contextlib.redirect_stdout(output):
            code = module.main()
    finally:
        sys.argv = saved_argv
        if saved_cdp is not None:
            sys.modules["cdp"] = saved_cdp
        else:
            sys.modules.pop("cdp", None)
    tail = output.getvalue().strip().splitlines()
    summary = tail[-1] if tail else "(no output)"
    ok = isinstance(code, int) and code != 0
    return ok, f"empty batch -> exit={code} ({summary[:160]})"


def _healthy(scheme: str, supports_h2: bool, drop: list[str]) -> dict:
    """The expectation for a request that must succeed on the origin actually being tested.

    Two things follow the origin rather than being assumed:

    * the **scheme** — a plaintext origin cannot serve an `https://` request, and asserting https
      there would report a working request as failed;
    * whether `$removeparam` may fire at all — it is decrypted-only by design
      (`core/src/http/relay.rs`), so on a plaintext origin the parameter must still be **present**
      upstream. Asserting "removed" on http would be asserting behaviour the design forbids.
    """
    is_https = scheme == "https"
    return {
        "status": 200,
        "scheme": scheme,
        # When the ALPN probe could not answer, the case does not constrain the protocol: asserting
        # either one would be a guess, and a wrong guess here fails the `control` case for a reason
        # that has nothing to do with the fault being injected.
        "protocol": (
            None if supports_h2 is None else ("h2" if supports_h2 else "http/1.1")
        ) if is_https else "http/1.1",
        "method": "GET",
        "drop_params": drop if is_https else [],
        "keep_params": [] if is_https else ["track"],
    }


def probe_alpn(host: str, port: int = 443) -> bool | None:
    """Whether the origin negotiates h2. An h1-only origin cannot satisfy an h2 assertion.

    `port` is taken from the origin URL rather than assumed to be 443. Hard-coding it meant a
    controlled origin on any other port — a loopback fixture, an `adb reverse` port, a tunnel entry —
    always reported "h1 only", and the `control` case then demanded `http/1.1` from a connection the
    origin was perfectly happy to serve over h2. That is a probe defect reported as a harness
    detection failure, which is the wrong thing to hand a reviewer.
    """
    try:
        with socket.create_connection((host, port), timeout=10) as raw:
            context = ssl.create_default_context()
            context.set_alpn_protocols(["h2", "http/1.1"])
            with context.wrap_socket(raw, server_hostname=host) as tls:
                negotiated = tls.selected_alpn_protocol() == "h2"
                SAY_ALPN.append(negotiated)
                return negotiated
    except OSError as error:
        # `None`, not `False`: a handshake that never completed says nothing about which protocol the
        # origin would serve. Returning `False` here made "could not ask" indistinguishable from "the
        # origin only speaks http/1.1", and the control case then demanded h1 from an origin that was
        # serving h2 — a probe failure reported as a harness detection failure.
        say(f"could not probe ALPN for {host}:{port}: {error}")
        return None


#: Filled once by `probe_alpn` so `main` can print what it found without a second handshake.
SAY_ALPN: list[bool] = []


def _rule_is_in_force(cdp, arguments, host: str, parameter: str, attempts: int = 8) -> bool:
    """Prove the `$removeparam` rule is live by observing the upstream, not by reading a count.

    One `fetch` carrying `parameter` goes through the tunnel to the controlled origin; the origin's
    own record says whether the parameter survived. Retried, because the compile is debounced and a
    fixed sleep is either too short (flaky) or too slow (wasteful).

    The previous check grepped `logcat` for a `removeparam` count against a catalog size written into
    this file. That number describes a **list snapshot**, not this run's rules: it can be satisfied by
    a stale line from an earlier run, it goes wrong the moment the catalog changes, and it says nothing
    about whether the rule matched anything. Behaviour is the only answer that means what the caller
    needs.
    """
    base = arguments.origin.rstrip("/").replace("/anything", "")
    for _ in range(attempts):
        probe = {
            "name": "rule-in-force",
            "url": f"{base}/get?rulecheck=1&{parameter}=DROP_ME&zs_rid=rulecheck",
            "init": {"method": "GET"},
            "expect": {
                "status": 200,
                "transport": "tls-h2",
                "scheme": "https",
                "protocol": "h2",
                "tls": True,
                "method": "GET",
                "drop_params": [parameter],
                "keep_params": ["rulecheck"],
                "require_upstream_id": True,
            },
        }
        probe["expect"]["client_url"] = probe["url"]
        page = cdp.Browser.attach(arguments.serial, arguments.browser, port=arguments.port).open(
            f"{base}/__id?zs_rid=rulecheck", timeout=arguments.timeout, settle=1.0
        )
        try:
            detected, detail = run_case(page, probe | {"must_pass": True}, "rulecheck")
        finally:
            try:
                page.close()
            except Exception:  # noqa: BLE001 - closing a scratch page is bookkeeping
                pass
        if detected:
            return True
        say(f"  rule probe not yet in force: {detail[:160]}")
        time.sleep(8)
    return False


def run_case(page, case: dict, run_id: str) -> tuple[bool, str]:
    """Drive one case through the page and report whether the harness caught it for the right reason."""
    if "synthetic" in case:
        # A result that never arrived. Fed straight to the checker, which is what the acceptance run
        # does with a transport error.
        result = {
            "id": case["name"] + "-" + run_id,
            "index": 0,
            "scenario": case["name"],
            "error": case["synthetic"]["error"],
        }
        problems = check_one(result, {"run_id": run_id}, case["expect"])
        return (True if case.get("must_pass") else bool(problems)), (
            "; ".join(problems)[:300] if problems else "no problems reported"
        )

    url = case["url"].format(run_id=run_id)
    init = dict(case["init"])
    init.pop("abort_ms", None)
    script = f"""(async()=>{{
  const url = {json.dumps(url)};
  const init = Object.assign({{cache:'no-store'}}, {json.dumps(init)});
  init.headers = Object.assign({{'X-ZS-Req': {json.dumps(case["name"] + "-" + run_id)}}}, init.headers || {{}});
  const abortMs = {int(case["init"].get("abort_ms", 0))};
  if (abortMs > 0) {{
    const controller = new AbortController();
    setTimeout(() => controller.abort(), abortMs);
    init.signal = controller.signal;
  }}
  const started = performance.now();
  try {{
    const response = await fetch(url, init);
    const text = await response.text();
    const entry = performance.getEntriesByName(response.url).slice(-1)[0] || {{}};
    return JSON.stringify({{id: init.headers['X-ZS-Req'], index: 0, scenario: {json.dumps(case["name"])},
                           status: response.status, url: response.url, redirected: response.redirected,
                           protocol: entry.nextHopProtocol || '', ms: performance.now() - started,
                           body: text.slice(0, 65536)}});
  }} catch (error) {{
    return JSON.stringify({{id: init.headers['X-ZS-Req'], index: 0, scenario: {json.dumps(case["name"])},
                           error: String(error), ms: performance.now() - started}});
  }}
}})()"""
    try:
        raw = page.evaluate(script, await_promise=True)
    except Exception as error:  # noqa: BLE001 - a dropped connection surfaces as a CDP failure
        # The page never answered: the browser gave up on the request. That IS the disconnect being
        # observed, so it is classified as a transport error rather than being allowed to abort the
        # whole self-test.
        problems = [f"transport error: {type(error).__name__}: {error}"]
        detected = bool(problems)
        if case.get("must_pass"):
            detected = not problems
        detail = "; ".join(problems)[:300]
        return detected, detail
    result = json.loads(raw) if isinstance(raw, str) else raw
    problems = check_one(result, {"run_id": run_id}, case["expect"])
    detected = bool(problems)
    if case.get("must_pass"):
        detected = not problems
    detail = "; ".join(problems)[:300] if problems else "no problems reported"
    return detected, detail


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--origin",
        default="https://httpbin.org/anything",
        help="echo base URL as the phone reaches it; `/anything` is where the echo lives",
    )
    parser.add_argument("--serial", default=None,
                        help="adb serial; defaults to $SERIAL, else the only attached device")
    parser.add_argument("--browser", default="org.lineageos.jelly")
    parser.add_argument("--package", default="top.zztweb.zshield")
    parser.add_argument("--port", type=int, default=9337)
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--json", default="")
    parser.add_argument(
        "--no-install-rules",
        action="store_true",
        help="use the rule set already in force instead of installing one. The acceptance script runs "
        "this under the rules it installed and proved, so the self-test exercises the same rule "
        "transaction rather than replacing it and leaving its own rule behind",
    )
    arguments = parser.parse_args()
    arguments.serial = device_serial.serial_from(arguments)

    # The same loader the harness uses, so a host-side run can substitute the browser with
    # `ZS_CDP_MODULE` instead of depending on `sys.path` order (see `tunnel_concurrency.load_cdp`).
    from tunnel_concurrency import load_cdp

    cdp = load_cdp()

    origin = arguments.origin.rstrip("/")
    base = origin.replace("/anything", "")
    # The host *and the port* come from the URL the caller gave. Treating the origin as "whatever is
    # on :443" broke every controlled origin on any other port (a loopback fixture, an `adb reverse`
    # port, a tunnel entry) and turned its ALPN answer into a false "h1 only".
    import urllib.parse as _urlparse

    base_urls = _urlparse.urlsplit(base)
    host = base_urls.hostname or base.split("://", 1)[-1].split("/")[0].split(":")[0]
    run_id = uuid.uuid4().hex[:8]

    # The rewrite assertions need a rule that applies to a `fetch` (an Xhr). An untyped
    # `$removeparam` fires only on documents *by design*, so the rule must carry `,all` — without it
    # the `control` case would "detect" a fault that is really a missing rule, and the run would stop
    # for the wrong reason. Installing it here keeps this check self-contained.
    #
    # The rule is **pushed as a file and read on the device** rather than passed through `--es`:
    # `adb shell` runs the command through the device's own `sh`, which expands `$removeparam` to an
    # empty string, so an inline broadcast silently installs `||httpbin.org^=track,all`. That was
    # measured on this device — the installed file read back as `||httpbin.org^=track,all`.
    #
    # `--no-install-rules` skips this whole block. It exists because the acceptance script now owns the
    # rule transaction: it installs the run's rules, proves them by behaviour, and restores them on
    # exit. A fault self-test that installed its own rule would overwrite that set, and its old
    # readiness check — waiting for a `removeparam` count to reach a catalog size written into this
    # file — described a list snapshot rather than this run's rules. Under `--no-install-rules` the
    # cases run against the rules already in force, which is what "the same path as the acceptance run"
    # is supposed to mean.
    rule_text = f"||{host}^$removeparam=track,all"
    if arguments.no_install_rules:
        say("rules: using the set already in force (--no-install-rules)")
    else:
        local_rule = Path(".effectiveness/results/fault-rule.txt")
        local_rule.parent.mkdir(parents=True, exist_ok=True)
        local_rule.write_text(rule_text + "\n", encoding="utf-8")
        cdp.adb(arguments.serial, "push", str(local_rule), "/data/local/tmp/zs-fault-rule.txt",
                check=False)
        installed = cdp.shell(
            arguments.serial,
            "sh -c 'am broadcast -a top.zztweb.zshield.action.DEBUG_SET_RULES "
            f"-n {arguments.package}/.filters.DebugCommandReceiver "
            "--es rules \"$(cat /data/local/tmp/zs-fault-rule.txt)\"'",
            timeout=60.0,
            check=False,
        )
        say(f"rule: {rule_text}")
        if "Broadcast completed" not in installed:
            print(f"could not install the $removeparam rule: {installed.strip()[:200]}", file=sys.stderr)
            return 1
        # Confirm the rule actually reached the engine by **behaviour**, not by a count against a
        # hard-coded catalog size: one probe carrying the parameter must come back without it. The
        # count-based check could be satisfied by a stale log line from an earlier run and said nothing
        # about whether this rule matched anything.
        if not _rule_is_in_force(cdp, arguments, host, "track"):
            say(
                "the $removeparam rule did not take effect: the probe's parameter still reached the "
                "origin. The rewrite assertions below would fail for the wrong reason.",
                file=sys.stderr,
            )
            return 1
        say("rules in force: proven by behaviour, not by a log count")

    # The H2 requirement is conditional on the origin actually speaking H2. An origin that only
    # offers HTTP/1.1 (the self-hosted `tunnel_origin.py` behind a tunnel that terminates TLS with
    # h1 only) can never satisfy it, and asserting it there would report a protocol limit as a
    # detection result — the opposite of what this check is for.
    origin_port = base_urls.port or 443
    supports_h2 = probe_alpn(host, origin_port)

    # Every case now drives a fault the **controlled origin really injects** (`/__fault/*`), and each
    # one asserts the *specific* reason it must be caught. The previous version changed the
    # expectation instead of the behaviour ("say the upstream should be at a path it was never asked
    # for"), and accepted any error as a detection, so an unrelated failure — a DNS error, a blocked
    # request, a wrong status — would have been counted as the injection being caught.
    #
    # `origin` here is the *echo base*; the controlled origin serves `/__fault/*` at its root, so the
    # base is where the echo lives for normal traffic and the root is where faults are injected.
    root = base
    scheme = base.split("://", 1)[0]
    # ALPN is only meaningful over TLS: probing port 443 of a plaintext-only origin times out.
    supports_h2 = probe_alpn(host, base_urls.port or 443) if scheme == "https" else False
    if supports_h2 is None:
        say("origin: ALPN unknown (the handshake was refused) — protocol assertions follow the "
            "transport the case declares")
    else:
        say(f"origin: {scheme}, ALPN {'h2' if supports_h2 else 'http/1.1 only (or plaintext)'}")

    post_form = {"Content-Type": "application/x-www-form-urlencoded"}
    cases = [
        {
            "name": "control",
            # The positive control: a healthy request must NOT be reported. Without it, a harness that
            # fails everything would look like a harness that catches every injection.
            "url": f"{root}/get?keep=1&track=DROP_ME&zs_rid={{run_id}}&fault=control",
            "init": {"method": "GET"},
            "expect": _healthy(scheme, supports_h2, drop=["track"]),
            "must_pass": True,
            "must_contain": [],
        },
        {
            "name": "http-500",
            # The origin really answers 500 here.
            "url": f"{root}/__fault/500?keep=1&zs_rid={{run_id}}",
            "init": {"method": "GET"},
            "expect": _healthy(scheme, supports_h2, drop=["track"]),
            "must_contain": ["status 500"],
        },
        {
            "name": "wrong-url",
            # The origin really answers as though the target were `/__wrong-url`.
            "url": f"{root}/__fault/url?keep=1&zs_rid={{run_id}}",
            "init": {"method": "GET"},
            "expect": _healthy(scheme, supports_h2, drop=["track"]),
            "must_contain": ["upstream target"],
        },
        {
            "name": "wrong-body",
            # The origin really answers with a body it was not sent.
            "url": f"{root}/__fault/body?keep=1&zs_rid={{run_id}}",
            "init": {"method": "POST", "body": "sent=this", "headers": dict(post_form)},
            "expect": _healthy(scheme, supports_h2, drop=["track"]) | {
                "method": "POST",
                "body_exact": "sent=this",
            },
            "must_contain": ["upstream body"],
        },
        {
            "name": "disconnect",
            # The origin really closes the socket with no response line, through the same VPN.
            "url": f"{root}/__fault/disconnect?keep=1&zs_rid={{run_id}}",
            # The origin closes the socket without a response line. A browser may sit on that for a
            # long time, and a hung `Runtime.evaluate` takes the CDP socket with it, so the case
            # carries its own abort budget.
            "init": {"method": "GET", "abort_ms": 12000},
            "expect": _healthy(scheme, supports_h2, drop=["track"]),
            "must_contain": ["transport error"],
        },
        {
            "name": "missing-result",
            # Not an upstream fault: the *result* is absent, which must also be a failure. This is the
            # shape the review's repro produced (empty batches read as a pass).
            "url": f"{root}/get?keep=1&zs_rid={{run_id}}",
            "init": {"method": "GET"},
            "expect": _healthy(scheme, supports_h2, drop=["track"]),
            "synthetic": {"error": "TypeError: Failed to fetch"},
            "must_contain": ["transport error"],
        },
    ]

    browser = cdp.Browser.attach(arguments.serial, arguments.browser, port=arguments.port)
    page = browser.open(f"{root}/get?zs_rid={run_id}&probe=faults", timeout=arguments.timeout, settle=4)
    say(f"page: {page.evaluate('location.href')}")

    # Order matters only for stability: the disconnect case can leave the page unable to answer, so
    # it runs last and the cases that need a healthy page are not put at risk by it.
    cases.sort(key=lambda case: case["name"] == "disconnect")
    results = []
    missed = 0
    for case in cases:
        detected, detail = run_case(page, case, run_id)
        # A case counts as handled only when the *expected reason* appears — not merely when something
        # went wrong. `must_contain` is what turns "an error happened" into "this injection was seen".
        if case["must_contain"]:
            reason_ok = all(needle in detail for needle in case["must_contain"])
            if detected and not reason_ok:
                detected = False
                detail = f"wrong reason: {detail}"
        verdict = "OK" if detected else "MISSED"
        if not detected:
            missed += 1
        say(f"  {case['name']:14} {verdict:7} {detail}")
        results.append({"case": case["name"], "detected": detected, "detail": detail})

    # Finally: the *acceptance entry point* must go non-zero when the harness is fed a broken batch.
    # A fault self-test that only proves `check_one` can fail does not prove the program refuses to
    # report PASS — and "the command exits 0 on an empty batch" was the review's first finding.
    gate_ok, gate_detail = _acceptance_gate_is_nonzero()
    say(f"  {'acceptance-gate':14} {'OK' if gate_ok else 'MISSED':7} {gate_detail}")
    results.append({"case": "acceptance-gate", "detected": gate_ok, "detail": gate_detail})
    if not gate_ok:
        missed += 1

    if arguments.json:
        Path(arguments.json).parent.mkdir(parents=True, exist_ok=True)
        Path(arguments.json).write_text(
            json.dumps({"origin": origin, "run_id": run_id, "cases": results}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    say("")
    say(f"fault selftest: {'PASS' if missed == 0 else f'FAIL ({missed} missed)'}")
    return 0 if missed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
