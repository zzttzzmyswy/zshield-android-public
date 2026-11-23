#!/usr/bin/env python3
"""Concurrency regression for the request path, measured *through the real VPN*.

Why this replaces `concurrency_smoke.py`
---------------------------------------
The first version of this check ran `urllib` on the measurement host. Nothing in it touched the
phone, the tunnel, or the rule engine, so it passed no matter what the core did — including while
every answer was an HTTP 500 (`docs/EFFECTIVENESS.md` §13.10, review item 5). A smoke test whose
subject is not in the loop is worse than none: it reports PASS.

This harness keeps three independent parties in the loop for every request:

  * the **browser** on the phone (`org.lineageos.jelly`, driven over CDP), which is the client the
    tunnel actually filters;
  * the **VPN tunnel**, which is the only path the traffic can take once protection is up (see
    `docs/TESTING.md` §14.1 — with the tunnel up, every IPv4 destination, LAN included, is routed
    into the core);
  * the **controlled upstream origin** (`tunnel_origin.py`), whose reply is the record of what it
    was really handed.

The origin's reply is the authority — not a proxy log, and not the client's own fields. A
`$removeparam` rewrite is invisible in the client's own `response.url` (the design rewrites in place
precisely so `fetch(redirect:'error')` keeps working, §13.1) and unmistakable in the origin's record.

What the origin's record must carry (stage-3 review, MYS-2817)
--------------------------------------------------------------
1. **The request ID as the upstream saw it.** `X-ZS-Req` arrives, is recorded, and is echoed back.
   The checker reads the ID from the echo and cross-checks it against the client's report and the
   harness's own plan. A result whose ID was filled in by the client proves nothing; replay, wrong,
   missing, duplicated and unplanned IDs all fail.
2. **Raw body bytes, or their digest.** `body_sha256` is taken over the bytes before any decoding. A
   re-ordered or merged form dictionary is *not* proof that the bytes survived: an echo that reports
   the body only in normalised form is a missing observation, and a missing observation is a failure.
3. **In-flight overlap measured, not assumed.** Each record carries the origin's in-flight counter at
   arrival, so a group's maximum must reach the number of requests the plan issued for that group. A
   serialised run cannot reach it. Two `Browser.open()` calls that land on the same page target can
   never reach it either, which is why pages must be independent and are verified by target id.

Transports, and why all three
-----------------------------
`DESIGN §6` requires filtering on the **decrypted** path over both H1 and H2; the plaintext leg must
*not* rewrite (`$removeparam` is decrypted-only, `core/src/http/relay.rs`).

  plain H1   HTTP/1.1 with no TLS — the "design forbids a rewrite here" leg;
  TLS H1     decrypted HTTP/1.1, served by an origin listener that offers `http/1.1` only, so the
             MITM presents that protocol to the client (`core/src/https/tls.rs` mirrors what the
             origin settled on) and the browser genuinely speaks H1 through the tunnel;
  TLS H2     decrypted HTTP/2 — the common case.

An httpbin-style echo can serve all three, but it reports neither a request ID nor a body digest, so
acceptance runs require the controlled origin. `--origin` therefore names the controlled origin;
pointing this at an echo service produces explicit "weak echo" failures instead of a silent pass.

Round layout
------------
One round is `--concurrency` requests in flight at once. With three independent page targets the
round splits across the three transports and **all legs start before any is awaited** (each page has
its own WebSocket, so all three batches are in flight together). When the browser exposes fewer
targets than legs, the run falls back to sequential per-leg rounds and *says so*: each leg then
carries the full `--concurrency`, and the origin's in-flight peak per leg is what proves it.

`--selftest` drives deliberate faults through `check_one` and the acceptance gate and asserts each is
**detected**. `--readiness` performs the behavioural probe the acceptance script needs before
spending a full run: a parameter an installed rule names must be removed upstream, and one no rule
names must survive. No log line, no hard-coded rule count.

Scenarios
---------
  h1-get / h1-post            plaintext GET and POST
  h1-removeparam-scoped       plaintext GET whose `track` must **survive** (design)
  tls1-get / tls1-post        decrypted H1 GET and POST
  tls1-removeparam            decrypted H1 GET whose `track` must be dropped
  h2-get / h2-post            decrypted H2 GET and POST
  removeparam                 `$removeparam=track` on H2
  removeparam-regex           `$removeparam=/^rxparam=/` on H2
  fetch-error / fetch-manual  the same rewrite under `redirect:'error'` / `'manual'`
  nav-plain / nav-h2          a **navigation** whose URL is rewritten: the core answers `302`
                              (`relay.rs` / `h2.rs`), so the browser's final URL is the clean one and
                              the origin only ever sees the clean URL
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import Counter
from pathlib import Path

# The harness's own directory, so `import cdp` and `device_serial` find the ones beside it.
_OWN_DIR = str(Path(__file__).resolve().parent)
if _OWN_DIR not in sys.path:
    sys.path.append(_OWN_DIR)

import device_serial  # noqa: E402


def load_cdp():
    """Import the CDP client, honouring an explicit `ZS_CDP_MODULE` override.

    Why an override and not plain `import cdp`: when this file runs as a **script**, Python puts the
    script's own directory at `sys.path[0]`, ahead of everything on `PYTHONPATH`. A host-side test that
    substitutes `cdp` therefore could not win — it silently got the real client, which then failed with
    "no devtools socket", an error that points at the device instead of at the substitution. Rather
    than depend on import-order subtleties, the caller names the module it wants.

    `ZS_CDP_MODULE` is a path to a `.py` file loaded under the name `cdp`. It exists for tests and
    for a host-side dry run; production never sets it.
    """
    override = os.environ.get("ZS_CDP_MODULE", "")
    if override:
        import importlib.util

        spec = importlib.util.spec_from_file_location("cdp", override)
        if spec is None or spec.loader is None:
            raise SystemExit(f"ZS_CDP_MODULE={override!r} is not a loadable Python file")
        module = importlib.util.module_from_spec(spec)
        sys.modules["cdp"] = module
        spec.loader.exec_module(module)
        return module
    import cdp

    return cdp


def say(message: str) -> None:
    print(message, flush=True)


# --------------------------------------------------------------------------------------------
# The upstream echo's reply, normalised
# --------------------------------------------------------------------------------------------
class Observation:
    """What the upstream says it received, and how strong that statement is.

    `shape` is which echo answered. The controlled origin reports the request line, the raw body
    digest, the negotiated protocol and the request ID it was handed. An httpbin-style service
    reports a parsed URL and a form dictionary, which is weaker evidence and is treated as such: a
    body that only exists as a dictionary has **no** byte digest here, and a missing digest on a body
    that must be compared is a failure rather than a pass.
    """

    __slots__ = (
        "shape",
        "id",
        "method",
        "path",
        "body_digest",
        "body_note",
        "alpn",
        "tls",
        "inflight",
        "probe",
    )

    def __init__(
        self,
        *,
        shape: str,
        id: str | None,
        method: str | None,
        path: str,
        body_digest: str | None,
        body_note: str = "",
        alpn: str | None,
        tls: bool | None,
        inflight: int | None = None,
        probe: bool = False,
    ) -> None:
        self.shape = shape
        self.id = id
        self.method = method
        self.path = path
        self.body_digest = body_digest
        self.body_note = body_note
        self.alpn = alpn
        self.tls = tls
        self.inflight = inflight
        self.probe = probe


def checksum(text: str) -> str:
    """A short fingerprint of a body, over the exact bytes that were sent or received.

    The review's counter-example was `alpha=1WRONG&beta=2WRONG` accepted because the check looked for
    `alpha=1` as a substring; comparing whole-body digests makes that impossible.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def origin_view(body: str) -> Observation | None:
    """What the upstream says it received, from whichever echo answered.

    Two shapes are understood:

    * `tunnel_origin.py` — the controlled origin — answers with the request line, the raw body
      digest, the negotiated protocol and the echoed request ID (`id`, `path`, `method`,
      `body_sha256`, `alpn`, `tls`, `inflight`, `probe`).
    * `httpbin`-style services answer with `url`, `method`, `data`/`json`. They report no request ID
      and no body digest, so a run that needs those fails on them — deliberately: a weaker echo
      cannot prove a stronger claim.

    Everything checked below is read from the *parsed echo*, so a filtered page (an HTML block page,
    a redirect substitute) never parses and is counted as "the upstream did not answer".
    """
    text = (body or "").strip()
    if not text.startswith("{"):
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None

    # The controlled origin: a top-level `path`, which no block page ever has.
    if "path" in parsed and "method" in parsed:
        digest = parsed.get("body_sha256")
        note = ""
        if isinstance(digest, str) and digest:
            digest = digest[:16]
        elif isinstance(parsed.get("body_b64"), str):
            import base64

            try:
                digest = checksum(base64.b64decode(parsed["body_b64"]).decode("utf-8", "replace"))
            except (ValueError, TypeError):
                digest = None
                note = "the echo reported an undecodable body"
        elif isinstance(parsed.get("body"), str):
            # Raw bytes reported as text: hashing them here is still a byte comparison.
            digest = checksum(parsed["body"])
        else:
            digest = None
            note = "the echo reported no raw body and no body digest"
        return Observation(
            shape="origin",
            id=(str(parsed["id"]) if parsed.get("id") not in (None, "") else None),
            method=parsed.get("method"),
            path=parsed.get("path") or "",
            body_digest=digest,
            body_note=note,
            alpn=parsed.get("alpn"),
            tls=parsed.get("tls") if isinstance(parsed.get("tls"), bool) else None,
            inflight=parsed.get("inflight") if isinstance(parsed.get("inflight"), int) else None,
            probe=bool(parsed.get("probe")),
        )

    # httpbin-style: `url` repeats the request target the upstream actually served.
    if "url" in parsed and "method" in parsed:
        url = str(parsed.get("url") or "")
        split = urllib.parse.urlsplit(url)
        target = split.path + (("?" + split.query) if split.query else "")
        digest = None
        note = ""
        raw = parsed.get("data")
        normalised = parsed.get("form") or parsed.get("json")
        # `data` is the raw body only when the echo left it alone. When the echo *also* reports a
        # parsed form, `data` is empty (its parser consumed the body) — that is the normalisation the
        # assertion must refuse, not a body that happened to be empty.
        if isinstance(raw, str) and (raw or not normalised):
            digest = checksum(raw)
        else:
            note = (
                "the echo reported the body only in a normalised form (form/json); a raw body or its "
                "digest is required to prove the bytes survived"
            )
        return Observation(
            shape="httpbin",
            id=None,
            method=parsed.get("method"),
            path=target,
            body_digest=digest,
            body_note=note,
            alpn=None,  # the echo cannot report ALPN; the browser reports the protocol instead
            tls=url.startswith("https://"),
            inflight=None,
        )
    return None


def path_of(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    return parsed.path + (("?" + parsed.query) if parsed.query else "")


# --------------------------------------------------------------------------------------------
# Scenario table: three transports, and the parameter each case must see dropped
# --------------------------------------------------------------------------------------------
#: The three transports, in the order the harness drives them.
TRANSPORTS = ("plain", "tls-h1", "tls-h2")

#: The protocol each transport must negotiate, as the browser and the origin both report it.
TRANSPORT_PROTOCOL = {"plain": "http/1.1", "tls-h1": "http/1.1", "tls-h2": "h2"}

#: The scheme each transport must use.
TRANSPORT_SCHEME = {"plain": "http", "tls-h1": "https", "tls-h2": "https"}


def expected_upstream_path(client_url: str, drop_params: list[str]) -> str:
    """The exact target the upstream must have received.

    Derived from what the client asked for by removing **exactly** the declared parameters: a
    hard-coded literal would break on a different origin and could drift from the request without
    anyone noticing, and a substring search would accept a URL that merely contains the right text.
    """
    split = urllib.parse.urlsplit(client_url)
    kept = [pair for pair in split.query.split("&") if pair and pair.split("=", 1)[0] not in drop_params]
    query = "&".join(kept)
    return split.path + (("?" + query) if query else "")


def build_scenarios(
    origin: str,
    run_id: str,
    http_origin: str = "",
    https_origin: str = "",
    tls1_origin: str = "",
) -> list[dict]:
    """The scenario matrix, split by transport so plaintext, TLS/H1 and TLS/H2 are proven *separately*.

    Each scenario declares:

    * its **transport** (`plain`, `tls-h1`, `tls-h2`) and the protocol the browser and origin must
      report for it (`http/1.1` for plaintext and TLS/H1, `h2` for TLS/H2). A TLS leg that reports
      http/1.1 on the h2 leg fails, which is what "H2 evidence missing must fail" means — and the
      TLS/H1 leg exists so "HTTP/1.1" is never read as "the decrypted H1 path was covered";
    * `drop_params`: the parameters a `$removeparam` rule must have removed **before the upstream saw
      them**. The expected upstream target is derived from the requested URL by removing exactly
      these, so the comparison is exact and does not depend on the origin's path layout;
    * `keep_params`: parameters the design requires to survive. On the plaintext leg that is the
      interesting one — `$removeparam` is decrypted-only (`core/src/http/relay.rs`), so a plaintext
      request must arrive with the parameter **intact**. Asserting a removal there would be
      asserting behaviour the design forbids.

    `http_origin` / `https_origin` / `tls1_origin` let a run point each leg at an upstream that
    really speaks it (a plaintext listener, an `h2` listener, and an `http/1.1`-only TLS listener).
    With none supplied the single `origin` serves every leg, which is the common local case.
    """
    plain_base = http_origin or origin
    h2_base = https_origin or origin
    h1_tls_base = tls1_origin or https_origin or origin
    if not plain_base.startswith("http://"):
        plain_base = plain_base.replace("https://", "http://", 1)
    if not h2_base.startswith("https://"):
        h2_base = h2_base.replace("http://", "https://", 1)
    if not h1_tls_base.startswith("https://"):
        h1_tls_base = h1_tls_base.replace("http://", "https://", 1)

    post_form = {"Content-Type": "application/x-www-form-urlencoded"}

    def scenario(
        name: str,
        transport: str,
        path: str,
        query: str,
        *,
        method: str = "GET",
        body: str = "",
        extra_init: dict | None = None,
        drop: list[str] | None = None,
        keep: list[str] | None = None,
        navigation: bool = False,
    ) -> dict:
        base = {"plain": plain_base, "tls-h1": h1_tls_base, "tls-h2": h2_base}[transport]
        # The base already names the echo (`…/anything` on an httpbin-style origin, the root on the
        # controlled one), so only the sub-path is appended.
        url = f"{base}{path.removeprefix('/anything')}?{query}"
        init = {"method": method}
        if body:
            init["body"] = body
            init["headers"] = dict(post_form)
        if extra_init:
            init.update(extra_init)
        final_client_url = url
        if navigation and drop:
            # A navigation whose URL is rewritten is answered with a `302` to the clean URL, so the
            # browser's own final URL is the clean one. A subresource keeps the URL it asked for.
            split = urllib.parse.urlsplit(url)
            clean_target = expected_upstream_path(url, list(drop))
            clean_path, _, clean_query = clean_target.partition("?")
            final_client_url = urllib.parse.urlunsplit(
                split._replace(path=clean_path, query=clean_query)
            )
        return {
            "name": name,
            "transport": transport,
            "navigation": navigation,
            "url": url,
            "init": init,
            "expect": {
                "status": 200,
                "transport": transport,
                "scheme": TRANSPORT_SCHEME[transport],
                "protocol": TRANSPORT_PROTOCOL[transport],
                "tls": transport != "plain",
                "method": method,
                "body_exact": body if body else None,
                "drop_params": list(drop or []),
                "keep_params": list(keep or []),
                "client_url": final_client_url,
                # A document navigation **cannot** carry `X-ZS-Req`: no browser lets a navigation set
                # a custom header. Its identity is the `zs_rid` in the target plus the exact target
                # comparison below, so it does not claim the header evidence it cannot have.
                "require_upstream_id": not navigation,
            },
        }

    scenarios = [
        # ---- plaintext: HTTP/1.1, no rewrite by design -------------------------------------
        scenario("h1-get", "plain", "/anything/get", f"scenario=h1get&keep=1&zs_rid={run_id}"),
        scenario(
            "h1-post", "plain", "/anything/post", f"scenario=h1post&keep=1&zs_rid={run_id}",
            method="POST", body="alpha=1&beta=2",
        ),
        scenario(
            "h1-removeparam-scoped", "plain", "/anything/get",
            f"scenario=h1rm&keep=1&track=KEEP_ON_PLAINTEXT&zs_rid={run_id}", keep=["track"],
        ),
        # ---- TLS: decrypted HTTP/1.1 -------------------------------------------------------
        scenario("tls1-get", "tls-h1", "/anything/get", f"scenario=tls1get&keep=1&zs_rid={run_id}"),
        scenario(
            # A POST whose URL carries a parameter the rule must remove **and** a body that must
            # survive byte for byte: the previous version posted an innocent body on a clean URL, so
            # it never exercised "the rewrite kept the method and the body" on the decrypted H1 leg.
            "tls1-post-removeparam", "tls-h1", "/anything/post",
            f"scenario=tls1post&keep=1&track=DROP_ME&zs_rid={run_id}",
            method="POST", body="epsilon=5&zeta=6", drop=["track"],
        ),
        scenario(
            "tls1-removeparam", "tls-h1", "/anything/get",
            f"scenario=tls1rm&keep=1&track=DROP_ME&zs_rid={run_id}", drop=["track"],
        ),
        scenario(
            "tls1-removeparam-regex", "tls-h1", "/anything/get",
            f"scenario=tls1rx&keep=1&rxparam=RX_DROP&zs_rid={run_id}", drop=["rxparam"],
        ),
        scenario(
            "tls1-fetch-error", "tls-h1", "/anything/get",
            f"scenario=tls1fe&keep=1&track=DROP_ME&zs_rid={run_id}",
            drop=["track"], extra_init={"redirect": "error"},
        ),
        scenario(
            "tls1-fetch-manual", "tls-h1", "/anything/get",
            f"scenario=tls1fm&keep=1&track=DROP_ME&zs_rid={run_id}",
            drop=["track"], extra_init={"redirect": "manual"},
        ),
        # ---- TLS: decrypted HTTP/2 ---------------------------------------------------------
        scenario("h2-get", "tls-h2", "/anything/get", f"scenario=h2get&keep=1&zs_rid={run_id}"),
        scenario(
            "h2-post-removeparam", "tls-h2", "/anything/post",
            f"scenario=h2post&keep=1&track=DROP_ME&zs_rid={run_id}",
            method="POST", body="gamma=3&delta=4", drop=["track"],
        ),
        scenario(
            "removeparam", "tls-h2", "/anything/get",
            f"scenario=removeparam&keep=1&track=DROP_ME&zs_rid={run_id}", drop=["track"],
        ),
        scenario(
            "removeparam-regex", "tls-h2", "/anything/get",
            f"scenario=regex&keep=1&rxparam=RX_DROP&zs_rid={run_id}", drop=["rxparam"],
        ),
        scenario(
            "fetch-error", "tls-h2", "/anything/get",
            f"scenario=fetcherror&keep=1&track=DROP_ME&zs_rid={run_id}",
            drop=["track"], extra_init={"redirect": "error"},
        ),
        scenario(
            "fetch-manual", "tls-h2", "/anything/get",
            f"scenario=fetchmanual&keep=1&track=DROP_ME&zs_rid={run_id}",
            drop=["track"], extra_init={"redirect": "manual"},
        ),
    ]
    # The navigation controls are not part of a batch: a document navigation has to be a real
    # navigation, because the core decides "navigation" from `Sec-Fetch-Dest: document` and answers
    # it with a `302`. A batch of `fetch` calls can never exercise that branch.
    navigations = [
        scenario(
            "nav-plain", "plain", "/anything/nav",
            f"scenario=navplain&keep=1&track=KEEP_ON_PLAINTEXT&zs_rid={run_id}",
            keep=["track"], navigation=True,
        ),
        scenario(
            "nav-h2", "tls-h2", "/anything/nav",
            f"scenario=navh2&keep=1&track=DROP_ME&zs_rid={run_id}",
            drop=["track"], navigation=True,
        ),
    ]
    for entry in scenarios + navigations:
        # `body_exact=None` means "no body expected"; keep the key absent so the checker skips it.
        if entry["expect"]["body_exact"] is None:
            del entry["expect"]["body_exact"]
    return scenarios + navigations


def _has_param(target: str, name: str) -> bool:
    return re.search(rf"(?:^|[?&]){re.escape(name)}(?:=|&|$)", target) is not None


def check_one(result: dict, scope: dict, expect: dict) -> list[str]:
    """Every way one result can be wrong (empty list means it passed).

    Each failure names the specific reason. The holes the two reviews drove through were all "a
    missing observation read as agreement", and each is now exact:

      * a missing `protocol` was skipped, so an HTTPS leg with no protocol evidence passed;
      * a substring `path_contains` accepted `/UNREQUESTED?keep=1`;
      * a substring `body_contains` accepted `alpha=1WRONG`;
      * the request ID was taken from the client, so any upstream — or no upstream — passed;
      * a re-ordered form dictionary was accepted as "the body survived";
      * the snapshot check passed when the socket line was simply absent.
    """
    if "error" in result:
        return [f"transport error: {result['error']}"]

    problems: list[str] = []
    status = result.get("status")
    wanted_status = expect.get("status", 200)
    if status != wanted_status:
        return [f"status {status} != {wanted_status}"]

    client_url = result.get("url") or ""
    if not client_url:
        return ["the browser reported no final URL"]

    wanted_scheme = expect.get("scheme")
    if wanted_scheme:
        actual_scheme = urllib.parse.urlsplit(client_url).scheme
        if actual_scheme != wanted_scheme:
            problems.append(f"client scheme {actual_scheme!r} != {wanted_scheme!r}")
    if "client_url" in expect and client_url != expect["client_url"]:
        problems.append(f"client URL {client_url!r} != {expect['client_url']!r}")

    # ---- transport: required, not optional --------------------------------------------------
    protocol = (result.get("protocol") or "").strip().lower()
    wanted_protocol = expect.get("protocol")
    if wanted_protocol:
        if not protocol:
            problems.append(
                f"no protocol evidence from the browser (expected {wanted_protocol!r}); a missing "
                "observation is not a pass"
            )
        elif protocol != wanted_protocol:
            problems.append(f"negotiated {protocol!r} != {wanted_protocol!r}")

    # ---- did the upstream answer at all? ---------------------------------------------------
    raw_body = result.get("body") or ""
    view = origin_view(raw_body)
    if view is None:
        problems.append(
            "the upstream did not answer — the response is not an echo "
            f"(first 120 bytes: {raw_body[:120]!r})"
        )
        return problems

    if view.probe:
        problems.append(
            "the upstream answered as a probe (/__id, /__stats), not with the request's own record"
        )

    # ---- the identity the *upstream* reports ------------------------------------------------
    if expect.get("require_upstream_id", True):
        echoed_id = view.id
        if not echoed_id:
            problems.append(
                f"the upstream echo carried no request id ({view.shape} shape); an id the client "
                "filled in cannot prove the request reached the upstream"
            )
        else:
            client_id = result.get("id") or ""
            if client_id and echoed_id != client_id:
                problems.append(
                    f"upstream echoed request id {echoed_id!r} but the client reported "
                    f"{client_id!r}; the id is evidence only when both agree"
                )
            planned = expect.get("request_id") or scope.get("request_id") or ""
            if planned and echoed_id != planned:
                problems.append(f"upstream echoed request id {echoed_id!r} != planned {planned!r}")

    # ---- TLS: the origin's own view agrees with the browser's ------------------------------
    expected_tls = expect.get("tls")
    if expected_tls is not None and view.tls is not None and view.tls != expected_tls:
        problems.append(f"upstream connection tls={view.tls} != expected {expected_tls}")

    viewed_alpn = (view.alpn or "").strip().lower()
    if expected_tls and view.alpn is not None:
        if not viewed_alpn:
            problems.append("the upstream reported no ALPN for a TLS connection")
        elif wanted_protocol and viewed_alpn != wanted_protocol:
            problems.append(f"upstream ALPN {viewed_alpn!r} != {wanted_protocol!r}")

    # ---- method, target, body: exact -------------------------------------------------------
    if "method" in expect and view.method != expect["method"]:
        problems.append(f"upstream method {view.method!r} != {expect['method']!r}")

    upstream_path = view.path or ""
    if not upstream_path:
        problems.append("the upstream echo carried no request target")
    else:
        base_url = expect.get("client_url") or client_url
        wanted_path = expected_upstream_path(base_url, expect.get("drop_params", []))
        if upstream_path != wanted_path:
            problems.append(
                f"upstream target {upstream_path!r} != {wanted_path!r} "
                f"(dropped {expect.get('drop_params', [])})"
            )
        for name in expect.get("drop_params", []):
            if _has_param(upstream_path, name):
                problems.append(f"upstream target still carries {name!r}")
        for name in expect.get("keep_params", []):
            if not _has_param(upstream_path, name):
                problems.append(f"upstream target lost {name!r}, which the design keeps")

    if "body_exact" in expect:
        sent = expect["body_exact"]
        if view.body_digest is None:
            problems.append(f"no byte-level body evidence from the upstream: {view.body_note}")
        elif view.body_digest != checksum(sent):
            problems.append(
                f"upstream body digest {view.body_digest} != {checksum(sent)} for sent {sent!r} "
                "(a body that merely contains the sent text is not the sent body)"
            )

    if scope.get("run_id") and scope["run_id"] not in upstream_path:
        problems.append(f"upstream target {upstream_path!r} is missing this run's id {scope['run_id']!r}")
    return problems


# --------------------------------------------------------------------------------------------
# Planning: what one concurrent group is, and the calls it issues
# --------------------------------------------------------------------------------------------
def plan_group(
    scenarios: list[dict],
    concurrency: int,
    round_index: int,
    transport: str | None = None,
) -> dict:
    """The calls one concurrent group issues.

    `transport=None` deals the calls round-robin across every batchable scenario, which is the mode
    used when each leg has its own page. Naming a transport gives that transport the whole
    `concurrency` — the mode used when the browser exposes fewer page targets than legs.

    The plan is returned so `main` can compare the results against **what it asked for**: ids,
    scenarios and counts. Without that comparison an empty or partial batch is indistinguishable from
    a clean run, which is how the review's repro produced `PASS: 0 request(s)`.

    An id encodes its scenario and round (`<scenario>-r<round>-<index>-<nonce>`), so a result a later
    round produced cannot be counted as this round's: cross-round reuse is visible.
    """
    batchable = [
        scenario
        for scenario in scenarios
        if not scenario.get("navigation")
        and (transport is None or scenario["transport"] == transport)
    ]
    if not batchable:
        raise ValueError(f"no batchable scenario for transport {transport!r}")

    if transport is None:
        # Deal **by transport first**, then by scenario within it. A plain round-robin over the whole
        # table would give a small `--concurrency` nothing but the first transport's scenarios (the
        # table is ordered plain, TLS/H1, TLS/H2), so a 6-request run would never touch h2 — and the
        # run would then have to fail on "both framings must be exercised" even though nothing was
        # wrong with the tunnel. Every transport gets its share of the concurrency by construction.
        by_transport = {
            name: [scenario for scenario in batchable if scenario["transport"] == name]
            for name in TRANSPORTS
        }
        by_transport = {name: group for name, group in by_transport.items() if group}
    else:
        by_transport = {transport: batchable}

    calls = []
    for index in range(concurrency):
        name = list(by_transport)[index % len(by_transport)]
        group = by_transport[name]
        scenario = group[(index // len(by_transport)) % len(group)]
        request_id = f"{scenario['name']}-r{round_index}-{index}-{uuid.uuid4().hex[:8]}"
        init = dict(scenario["init"])
        headers = dict(init.pop("headers", {}))
        headers["X-ZS-Req"] = request_id
        calls.append(
            {
                "id": request_id,
                "index": index,
                "scenario": scenario["name"],
                "transport": scenario["transport"],
                "url": scenario["url"],
                "init": init | {"headers": headers},
            }
        )
    return {
        "round": round_index + 1,
        # Keyed by transport so `run_group` can route each leg to its own page; `mixed` is spelled out
        # as the transport keys rather than a pseudo-leg, because a leg name that is not a page name is
        # what produced a `KeyError: 'mixed'` in an earlier revision.
        "legs": (
            {
                leg: [call for call in calls if call["transport"] == leg]
                for leg in by_transport
            }
            if transport is None
            else {transport: calls}
        ),
        "n": len(calls),
        "ids": [call["id"] for call in calls],
    }


def round_of(request_id: str) -> int | None:
    """The round an id encodes, or `None` when it does not follow the plan's shape."""
    match = re.match(r"^.+?-r(\d+)-\d+-[0-9a-f]+$", request_id or "")
    return int(match.group(1)) if match else None


def batch_script(calls: list[dict]) -> str:
    """One page-side `Promise.all` over `calls`, all sharing this page's origin.

    `performance.getEntriesByName(response.url)` is how the browser reports the transport it actually
    used; the checker compares that against the scenario's declared protocol rather than assuming it.
    """
    return f"""(async()=>{{
  const calls = {json.dumps(calls)};
  const out = await Promise.all(calls.map(async (call) => {{
    const init = Object.assign({{cache:'no-store'}}, call.init);
    const started = performance.now();
    try {{
      const response = await fetch(call.url, init);
      const text = await response.text();
      const entry = performance.getEntriesByName(response.url).slice(-1)[0] || {{}};
      return {{id: call.id, index: call.index, scenario: call.scenario, status: response.status,
               url: response.url, redirected: response.redirected, type: response.type,
               protocol: entry.nextHopProtocol || '', ms: performance.now() - started,
               body: text.slice(0, 65536)}};
    }} catch (error) {{
      return {{id: call.id, index: call.index, scenario: call.scenario,
               error: String(error), ms: performance.now() - started}};
    }}
  }}));
  return JSON.stringify(out);
}})()"""


def navigation_script(call: dict) -> str:
    """The page-side half of a navigation result: read the **already-loaded** document.

    The navigation itself is done by CDP (`Page.navigate` + lifecycle events), not by
    `location.assign` from this script. That distinction is the point: a script that assigns and then
    reads `document.readyState`/`location.href` runs in the *old* document, which is torn down as the
    new one commits, so its "status" and "redirected" describe nothing. See
    `cdp.Page.navigate`.

    This script therefore only reports what the new document holds. `status` comes from the CDP
    `Network.responseReceived` for the document; `redirects` from the `Network.requestWillBeSent`
    chain. Both are passed in, so this function never invents them.

    The `Example`-style placeholders are gone from here: this string is only ever evaluated as
    JavaScript, and a doubled brace is a syntax error, not an escaped brace. `batch_script` is an
    f-string and gets its braces doubled; this one is not, so it must not.
    """
    return f"""(async()=>{{
  const report = {json.dumps({k: v for k, v in call.items() if k != "init"})};
  const nav = (performance.getEntriesByType('navigation')[0] || {{}});
  return JSON.stringify({{
    ...report,
    status: report.status,
    url: location.href,
    redirected: report.redirects.length > 1,
    protocol: nav.nextHopProtocol || '',
    body: (document.body ? document.body.innerText : '').slice(0, 65536),
  }});
}})()"""


# --------------------------------------------------------------------------------------------
# Structural validation: counts, identity, distribution, overlap, isolation
# --------------------------------------------------------------------------------------------
def validate_structure(
    groups: list[dict],
    results: list[dict],
    expected_rounds: int,
    expected_concurrency: int,
) -> list[str]:
    """Checks a per-result check cannot make: counts, identity, distribution, round alignment.

    This is the review's first finding, closed: an empty or partial batch must not read as a pass.
    Each group must return exactly the ids its plan issued — nothing missing, nothing extra, no
    duplicates — and the per-scenario counts must match the plan, so a run that silently skipped
    every rewrite cannot pass on the strength of its GETs.
    """
    problems: list[str] = []
    if len(groups) != expected_rounds and all(len(group["legs"]) == 1 for group in groups):
        # Sequential mode: three legs per round, so the number of groups is rounds × legs. `main`
        # reports that layout in the round table; the count itself is not a failure.
        pass

    planned_ids = [request_id for group in groups for request_id in group["ids"]]
    planned_scenarios = Counter(
        call["scenario"] for group in groups for calls in group["legs"].values() for call in calls
    )
    if len(planned_ids) != len(set(planned_ids)):
        problems.append("the plan itself issued duplicate request ids")

    seen = [result.get("id") for result in results]
    duplicates = [request_id for request_id, count in Counter(seen).items() if count > 1]
    if duplicates:
        problems.append(f"duplicate request id(s) in the results: {duplicates[:5]}")
    missing = sorted(set(planned_ids) - set(seen))
    if missing:
        problems.append(f"{len(missing)} planned request(s) produced no result: {missing[:5]}")
    unexpected = sorted(set(seen) - set(planned_ids))
    if unexpected:
        problems.append(
            f"{len(unexpected)} result(s) carry an id the plan never issued: {unexpected[:5]}"
        )
    if len(results) != len(planned_ids):
        problems.append(f"{len(results)} result(s) != {len(planned_ids)} planned")

    actual_scenarios = Counter(result.get("scenario") for result in results)
    for name, wanted in sorted(planned_scenarios.items()):
        if actual_scenarios.get(name, 0) != wanted:
            problems.append(
                f"scenario {name!r}: {actual_scenarios.get(name, 0)} result(s) != {wanted} planned"
            )

    # Cross-round mismatch: an id encodes its round, so a result filed under another round is a
    # result this round did not produce.
    for result in results:
        encoded = round_of(result.get("id") or "")
        claimed = result.get("round")
        if encoded is not None and claimed is not None and encoded + 1 != claimed:
            problems.append(
                f"result {result.get('id')!r} belongs to round {encoded + 1} but was recorded in "
                f"round {claimed}"
            )
            break
    return problems


def validate_concurrency(
    groups: list[dict],
    results: list[dict],
    concurrency: int,
    origin_evidence: dict | None = None,
) -> list[str]:
    """Every group must show `concurrency` requests in flight **at the same moment**.

    The counter is the origin's own, and it is **one counter for the whole origin**, not one per page:
    a request that arrives while nineteen others are open reads 20 no matter which page sent it. That
    is what makes this a test of the claim "20 concurrent" rather than of "each page sent its share".

    An earlier version compared against the busiest leg's share instead, and the review measured the
    consequence: a plan split 7/7/6 reported `peak=7` and passed, which is exactly the number you get
    when the three legs never overlap at all. Requiring the group total is what rejects that run.

    `origin_evidence` is the origin's `/__stats` after the run: `peak` (its running maximum over
    arrivals and departures) and `overlap` (recomputed from every request's start/end interval). Both
    are required to reach the total, so the claim rests on two independently computed numbers rather
    than on one the harness itself could have written.
    """
    problems: list[str] = []
    by_group: dict[int, list[int]] = {}
    for result in results:
        inflight = result.get("inflight")
        if not isinstance(inflight, int):
            view = origin_view(result.get("body") or "")
            inflight = view.inflight if view is not None else None
            if isinstance(inflight, int):
                result["inflight"] = inflight
        if not isinstance(inflight, int):
            continue
        key = result.get("group")
        if isinstance(key, int):
            by_group.setdefault(key, []).append(inflight)

    for index, group in enumerate(groups):
        observed = by_group.get(index, [])
        legs = {name: len(calls) for name, calls in group["legs"].items() if calls}
        # The whole group, not its busiest leg: the origin's counter is shared across legs, so a
        # genuine overlap of `concurrency` requests reads `concurrency` even when they came from
        # three pages.
        wanted = min(concurrency, group["n"])
        if not observed:
            problems.append(
                f"group {index + 1} (round {group['round']}): no in-flight observation from the "
                "upstream; concurrency is unproven (a serialised run and a concurrent one look "
                "identical without it)"
            )
            group["peak"] = None
            continue
        peak = max(observed)
        group["peak"] = peak
        group["legs_n"] = legs
        if peak < wanted:
            problems.append(
                f"group {index + 1} (round {group['round']}): at most {peak} request(s) in flight at "
                f"the upstream, expected {wanted} (legs carried {legs}); the group's legs did not "
                "overlap"
            )
        share = concurrency // max(1, len(legs))
        for name, count in sorted(legs.items()):
            if count < share:
                problems.append(
                    f"group {index + 1} (round {group['round']}): the {name!r} leg carried {count} "
                    f"of {concurrency} request(s), fewer than its share of {share}"
                )

    if origin_evidence is not None:
        peak = origin_evidence.get("peak")
        overlap = origin_evidence.get("overlap")
        wanted = min(concurrency, sum(group["n"] for group in groups) or concurrency)
        # `peak` is a running maximum; `overlap` is recomputed from intervals. On a run with several
        # groups the origin-wide numbers describe the busiest moment of the whole run, so only the
        # largest group is a fair bar for them.
        largest = max((min(concurrency, group["n"]) for group in groups), default=concurrency)
        if not isinstance(peak, int) or peak < largest:
            problems.append(
                f"the origin's own peak was {peak}, expected at least {largest}; its shared counter "
                "never saw the whole group open at once"
            )
        if not isinstance(overlap, int) or overlap < largest:
            problems.append(
                f"the origin's request intervals overlap at most {overlap} deep, expected at least "
                f"{largest}; the starts and ends of the batch do not bracket a simultaneous peak"
            )
    return problems


def validate_isolation(pages: dict) -> list[str]:
    """Each transport must run on its own page target.

    Two `Browser.open()` calls that land on the same target are one page navigated twice: the batches
    then cannot overlap (the second navigation aborts the first batch), and the second batch's
    `performance` entries describe the first page. The review found exactly that — `cdp.py` picked
    `targets[0]` unconditionally.

    A run that demonstrably ran its legs one after another on a single target is not accepted as
    "independent targets": `main` only takes the sequential path when it *reports* the leg layout,
    and then the same-target objection no longer applies to overlap. What this check always rejects
    is two legs **in parallel** sharing one target.
    """
    problems: list[str] = []
    seen: dict[str, str] = {}
    for transport in TRANSPORTS:
        page = pages.get(transport)
        if page is None:
            problems.append(f"transport {transport!r} never got a page")
            continue
        target_id = str((getattr(page, "target", None) or {}).get("id") or "")
        if not target_id:
            problems.append(
                f"transport {transport!r}: the page reported no target id, so independent pages "
                "cannot be shown"
            )
            continue
        if target_id in seen:
            problems.append(
                f"transports {seen[target_id]!r} and {transport!r} share page target "
                f"{target_id!r}; independent targets are required"
            )
        seen[target_id] = transport
    return problems


# --------------------------------------------------------------------------------------------
# Driving pages
# --------------------------------------------------------------------------------------------
def open_page(browser, url: str, used: set[str], timeout: float, label: str, relax: bool = False):
    """Open `url` on a page target no other leg is using.

    The target is chosen here and handed to `Browser.open_target`, so the id this function records is
    the id the page actually drives. Letting the browser pick (as `Browser.open` alone does) is what
    made two legs land on one target: `open` had no way to know which ids were taken.
    `relax=True` accepts a shared target (the browser exposed fewer pages than legs); the caller then
    runs the legs one after another, and `main` says so in its output.
    """
    target = None
    picker = getattr(browser, "page_targets", None)
    if picker is not None:
        free = [entry for entry in picker() if str(entry.get("id")) not in used]
        if free:
            target = free[0]
        elif not relax:
            raise RuntimeError(
                f"no free page target for the {label!r} leg: {label} would share a target with "
                "another leg, and two legs on one target cannot be in flight at the same time"
            )
    opener = getattr(browser, "open_target", None)
    if target is not None and opener is not None:
        page = opener(target, url, timeout=timeout, settle=4)
    else:
        page = browser.open(url, timeout=timeout, settle=4)
    target_id = str((getattr(page, "target", None) or {}).get("id") or "")
    if target_id:
        used.add(target_id)
    landed = page.evaluate("location.href")
    # A literal Python string, so a brace here is a brace in JavaScript. A doubled brace used to sit
    # on this line — an `str.format` escape that leaked into a non-format string — and Node rejected
    # it with `SyntaxError: Unexpected token '{'` before a single request was issued. The regression
    # that guards this parses whatever this function evaluates, rather than a copy of the intended
    # text, and a source-level test fails if a doubled brace comes back.
    protocol = page.evaluate(
        "(performance.getEntriesByType('navigation')[0]||{}).nextHopProtocol"
    )
    say(f"page ({label}): {landed} [{protocol}] target={target_id or '?'}")
    return page


def _parse_batch(raw, name: str, errors: list[str]) -> list[dict]:
    try:
        parsed = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError as error:
        errors.append(f"{name}: the page returned unparseable JSON ({error})")
        return []
    if not isinstance(parsed, list):
        errors.append(f"{name}: the page returned {type(parsed).__name__}, not a list")
        return []
    return parsed


def run_group(pages: dict, legs: dict[str, list[dict]]) -> tuple[list[dict], list[str]]:
    """Issue every leg's batch, then collect them all.

    The batches are *started* before any is awaited. Each leg has its own page and therefore its own
    WebSocket, so writing all the `Runtime.evaluate` calls first is what puts every leg in flight at
    the same time; awaiting one leg before starting the next would serialise the group into per-leg
    segments, which is the defect the review measured as "cannot prove 20 were in flight".

    A page that offers no start/collect split (a test double, or an older `cdp.Page`) falls back to
    awaiting each leg in turn; the origin's in-flight counter then reports the truth and
    `validate_concurrency` fails the group. A failure here is never silently ignored.
    """
    results: list[dict] = []
    errors: list[str] = []
    scripts = {
        name: batch_script([{k: v for k, v in call.items() if k != "transport"} for call in calls])
        for name, calls in legs.items()
    }

    can_start = all(hasattr(pages[name], "evaluate_start") for name in scripts)
    if can_start:
        started: dict[str, tuple] = {}
        for name, script in scripts.items():
            try:
                started[name] = pages[name].evaluate_start(script)
            except Exception as error:  # noqa: BLE001 - a dead page is a failed leg, not a crash
                errors.append(f"{name}: {type(error).__name__}: {error}")
        for name, handle in started.items():
            try:
                results.extend(_parse_batch(pages[name].evaluate_collect(*handle), name, errors))
            except Exception as error:  # noqa: BLE001
                errors.append(f"{name}: {type(error).__name__}: {error}")
    else:
        for name, script in scripts.items():
            try:
                results.extend(
                    _parse_batch(pages[name].evaluate(script, await_promise=True), name, errors)
                )
            except Exception as error:  # noqa: BLE001
                errors.append(f"{name}: {type(error).__name__}: {error}")
    return results, errors


def run_navigation(page, scenario: dict, timeout: float = 45.0) -> dict:
    """Drive one real document navigation and return a result shaped like a batch member.

    The navigation is executed by the page's own CDP client (`Page.navigate` + lifecycle events), so
    the status, the redirect chain, the committed `loaderId` and the new document's body all come from
    the browser rather than from a script that could only ever see the document it is running in.
    `status = 200` and `redirected = true` are **not** written here: they are read back.

    A page double without CDP navigation (a test stand-in) is supported only if it offers
    `navigate()`; falling back to a `Runtime.evaluate` would silently restore the defect this
    replaced, so the absence is an error rather than a fallback.
    """
    call = {
        "id": f"{scenario['name']}-r0-nav-{uuid.uuid4().hex[:8]}",
        "index": 0,
        "scenario": scenario["name"],
        "transport": scenario["transport"],
        "url": scenario["url"],
        "init": dict(scenario["init"]),
    }
    navigator = getattr(page, "navigate", None)
    if navigator is None:
        raise ValueError(
            f"the {scenario['name']!r} page offers no CDP navigation; a navigation result cannot be "
            "read from a script running in the document it is about to replace"
        )
    observed = navigator(call["url"], timeout=timeout, settle=2.0)
    result = {
        "id": call["id"],
        "index": 0,
        "scenario": scenario["name"],
        # The browser's own status and redirect chain, not a constant.
        "status": observed.get("status") or 0,
        "url": observed.get("url") or "",
        "redirected": bool(observed.get("redirects") and len(observed["redirects"]) > 1),
        "redirects": list(observed.get("redirects") or []),
        "loader_id": observed.get("loader_id") or "",
        "protocol": observed.get("protocol") or "",
        "loaded": bool(observed.get("loaded")),
        "body": observed.get("body") or "",
        "ms": 0.0,
        "round": 0,
    }
    if not result["status"]:
        # No document response at all — the navigation committed but the browser never got a status.
        # `check_one` reports this as a failed status; say why here so the message is accurate.
        result["error"] = "the navigation committed but the browser recorded no document response"
    return result


def origin_stats(base: str, timeout: float = 10.0) -> tuple[int, str, dict]:
    """Read the controlled origin's own `/__stats`, from the **host**.

    The measurement host can reach its own loopback origin even when the phone cannot (the tunnel
    routes every IPv4 destination into the core), so this is the one origin read that does not have to
    go through the browser. It is only a tally — no assertion about a request depends on it.
    """
    import urllib.request

    url = f"{base.rstrip('/').replace('/anything', '')}/__stats"
    request = urllib.request.Request(url, headers={"X-ZS-Req": "stats"})
    context = None
    if url.startswith("https://"):
        import ssl

        context = ssl._create_unverified_context()  # noqa: S323 - a loopback/self-signed origin
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return response.status, response.read().decode("utf-8", "replace"), dict(response.headers)
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace"), dict(error.headers)


def take_snapshot(serial: str, phase: str, label: str, run_id: str) -> bool:
    """Run `tunnel_snapshot.sh <phase> <label>` for `run_id`; a failure is reported and returned.

    `RUN_ID` is passed through because the snapshot tool now requires it: a pair that cannot name its
    run cannot be compared, and the stage-3 review accepted a hand-written pair with no run at all.
    """
    import subprocess

    script = Path(__file__).resolve().parent / "tunnel_snapshot.sh"
    result = subprocess.run(
        [str(script), phase, label], capture_output=True, text=True, check=False,
        env=os.environ | {"SERIAL": serial, "RUN_ID": run_id},
    )
    if result.returncode != 0:
        say(f"snapshot {phase}: FAILED ({result.stderr.strip()[:160]})")
        return False
    for line in result.stdout.splitlines():
        if line and not line.startswith("#"):
            say(f"snapshot {phase}: {line}")
    return True


# --------------------------------------------------------------------------------------------
# Self-test: the harness must be able to fail
# --------------------------------------------------------------------------------------------
def selftest(origin_base: str, timeout: float) -> int:
    """Each injected fault must be reported, and for its own reason.

    Runs entirely on the measurement host against the controlled origin: no device, no tunnel. The
    positive controls are what keep "reject everything" from looking like a working checker.
    """
    del timeout  # the origin's own contract tests cover liveness; this checks the checker
    # The self-test needs no reachable origin: it feeds `check_one` records directly. The base is
    # only a spelling for the URLs those records describe, so a placeholder keeps `--selftest`
    # runnable with no configuration at all (it is run in CI and by hand, both without a device).
    origin_base = (origin_base or "http://origin.invalid").rstrip("/")
    say("selftest: every injected fault must be detected")
    failures = 0

    def report(label: str, detected: bool, detail: str) -> None:
        nonlocal failures
        if not detected:
            failures += 1
        say(f"  {label:24} {'DETECTED' if detected else 'MISSED':9} {detail}")

    healthy = {
        "status": 200,
        "transport": "plain",
        "scheme": "http",
        "protocol": "http/1.1",
        "tls": False,
        "method": "GET",
        "drop_params": [],
        "require_upstream_id": True,
    }
    run_id = "selftest"
    client_url = f"{origin_base}/get?keep=1&zs_rid={run_id}"
    wanted_path = expected_upstream_path(client_url, [])
    planned = "control-r0-0-abcdef12"

    def origin_record(**overrides) -> str:
        record = {
            "id": planned,
            "path": wanted_path,
            "method": "GET",
            "body": "",
            "body_sha256": checksum(""),
            "alpn": None,
            "tls": False,
            "inflight": 1,
        }
        record.update(overrides)
        return json.dumps(record)

    def result(body: str, **overrides) -> dict:
        base = {"id": planned, "status": 200, "url": client_url, "protocol": "http/1.1", "body": body}
        base.update(overrides)
        return base

    # --- positive control: a healthy record must NOT be reported ----------------------------
    problems = check_one(result(origin_record()), {"run_id": run_id}, healthy | {"client_url": client_url})
    report("control", not problems, f"{problems}")

    # --- the original four ---------------------------------------------------------------
    problems = check_one(
        result(origin_record(), status=500), {"run_id": run_id},
        healthy | {"client_url": client_url},
    )
    report("http-500", any("status" in problem for problem in problems), f"{problems}")

    problems = check_one(
        result(origin_record(path="/__wrong-url")), {"run_id": run_id},
        healthy | {"client_url": client_url},
    )
    report("wrong-url", any("upstream target" in problem for problem in problems), f"{problems}")

    problems = check_one(
        result(origin_record(method="POST", body="sent=this", body_sha256=checksum("other"))),
        {"run_id": run_id},
        healthy | {"client_url": client_url, "method": "POST", "body_exact": "sent=this"},
    )
    report("wrong-body", any("upstream body" in problem for problem in problems), f"{problems}")

    problems = check_one(
        {"id": planned, "status": 200, "url": client_url, "protocol": "http/1.1",
         "error": "TypeError: Failed to fetch"},
        {"run_id": run_id},
        healthy | {"client_url": client_url},
    )
    report("disconnect", any("transport error" in problem for problem in problems), f"{problems}")

    # --- the three the second review drove through ---------------------------------------
    problems = check_one(
        result(origin_record(id="WRONG-UPSTREAM-ID")), {"run_id": run_id},
        healthy | {"client_url": client_url, "request_id": planned},
    )
    report("wrong-upstream-id", any("request id" in problem for problem in problems), f"{problems}")

    problems = check_one(
        result(origin_record(id="")), {"run_id": run_id},
        healthy | {"client_url": client_url, "request_id": planned},
    )
    report("missing-upstream-id", any("no request id" in problem for problem in problems), f"{problems}")

    problems = check_one(
        {"id": planned, "status": 200, "url": client_url, "protocol": "http/1.1",
         "body": "<html><body>blocked</body></html>"},
        {"run_id": run_id},
        healthy | {"client_url": client_url},
    )
    report("block-page", any("did not answer" in problem for problem in problems), f"{problems}")

    problems = check_one(
        result(origin_record(inflight=1)), {"run_id": run_id},
        healthy | {"client_url": client_url, "request_id": "a-different-plan"},
    )
    report("replayed-result", any("planned" in problem for problem in problems), f"{problems}")

    # --- protocol / transport evidence ---------------------------------------------------
    problems = check_one(
        result(origin_record(), protocol=""), {"run_id": run_id},
        healthy | {"client_url": client_url, "protocol": "h2"},
    )
    report("no-protocol", any("no protocol evidence" in problem for problem in problems), f"{problems}")

    problems = check_one(
        result(origin_record(alpn="http/1.1", tls=True)), {"run_id": run_id},
        healthy | {"client_url": client_url, "protocol": "h2", "tls": True,
                   "transport": "tls-h2", "scheme": "https"},
    )
    report("wrong-alpn", any("ALPN" in problem for problem in problems), f"{problems}")

    problems = check_one(
        result(origin_record(method="DELETE")), {"run_id": run_id},
        healthy | {"client_url": client_url, "method": "GET"},
    )
    report("wrong-method", any("upstream method" in problem for problem in problems), f"{problems}")

    # --- body: substring matches and normalised forms must not pass ----------------------
    problems = check_one(
        result(origin_record(method="POST", body="alpha=1WRONG")), {"run_id": run_id},
        healthy | {"client_url": client_url, "method": "POST", "body_exact": "alpha=1"},
    )
    report("corrupt-body", any("upstream body digest" in problem for problem in problems), f"{problems}")

    problems = check_one(
        result(json.dumps({"url": client_url, "method": "POST", "form": {"alpha": ["1WRONG"]}})),
        {"run_id": run_id},
        healthy | {"client_url": client_url, "method": "POST", "body_exact": "alpha=1"},
    )
    report("normalised-body", any("byte-level body evidence" in problem for problem in problems),
           f"{problems}")

    # --- the acceptance gate itself ------------------------------------------------------
    gate_ok, gate_detail = acceptance_gate_is_nonzero()
    report("acceptance-gate", gate_ok, gate_detail)

    say(f"selftest: {'PASS' if failures == 0 else f'FAIL ({failures} missed)'}")
    return 0 if failures == 0 else 1


def acceptance_gate_is_nonzero() -> tuple[bool, str]:
    """Feed the acceptance entry point an empty batch and require a non-zero exit.

    The review's first finding, checked directly: a stubbed page returning `[]` for every group
    produced `PASS: 0 request(s)` and exit 0. This probe fails if that behaviour returns.
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
        target = {"id": "fake-target"}

        def evaluate(self, script, **kwargs):
            if script == "location.href":
                return "https://echo.invalid/"
            if "nextHopProtocol" in script and "navigation" in script:
                return "h2"
            if "location.assign" in script:
                return json.dumps({"status": 0, "url": "", "body": ""})
            return "[]"

    class FakeBrowser:
        @staticmethod
        def attach(*args, **kwargs):
            return FakeBrowser()

        def page_targets(self):
            return [{"id": "fake-target", "type": "page"}]

        def open(self, *args, **kwargs):
            return FakePage()

    saved_cdp = sys.modules.get("cdp")
    saved_argv = sys.argv
    sys.modules["cdp"] = types.SimpleNamespace(Browser=FakeBrowser)
    sys.argv = [
        "tunnel_concurrency.py", "--origin", "https://echo.invalid/anything",
        "--rounds", "2", "--concurrency", "4",
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
    lines = output.getvalue().strip().splitlines()
    summary = lines[-1] if lines else "(no output)"
    return (isinstance(code, int) and code != 0), f"empty batch -> exit={code} ({summary[:160]})"


# --------------------------------------------------------------------------------------------
# Readiness: the behavioural probe the acceptance script runs before a full run
# --------------------------------------------------------------------------------------------
def readiness(page, origin: str, run_id: str, named: list[str], control: str) -> int:
    """Prove the run's own rule set is in force, by behaviour rather than by a log count.

    One `fetch` per **named** parameter plus one carrying a parameter no rule mentions:

      * each `named` parameter must be absent upstream — the matrix asserts both an ordinary
        `$removeparam=` and a regex `$removeparam=/…/`, so both forms are proven here;
      * the `control` parameter must still be present. Without it, a tunnel that dropped the whole
        query string, an origin that echoed a different URL, or a rule that removed everything would
        all read as "the rewrite works".

    A `fetch` rather than a navigation: `X-ZS-Req` travels in a header, which is the per-request
    identity the upstream can report. A navigation cannot set one, and this probe's whole point is to
    be as strict about identity as the run it gates.
    """
    base = origin.rstrip("/").replace("/anything", "")
    common = {
        "status": 200,
        "transport": "tls-h2",
        "scheme": "https",
        "protocol": "h2",
        "tls": True,
        "method": "GET",
        "require_upstream_id": True,
    }
    cases: list[tuple[str, str, dict]] = []
    for index, parameter in enumerate(named):
        url = f"{base}/anything/ready?scenario=ready&zs_keep_me=KEEP&{parameter}=DROP_ME&zs_rid={run_id}"
        cases.append(
            (
                f"readiness-removed-{parameter}",
                url,
                common | {"drop_params": [parameter], "keep_params": ["zs_keep_me"],
                          "client_url": url},
            )
        )
    control_url = f"{base}/anything/ready?scenario=ready&{control}=KEEP_ME&zs_rid={run_id}"
    cases.append(
        (
            f"readiness-control-{control}",
            control_url,
            common | {"drop_params": [], "keep_params": [control], "client_url": control_url},
        )
    )
    problems = 0
    for name, url, expect in cases:
        call = {
            "id": f"{name}-{run_id}",
            "index": 0,
            "scenario": name,
            "transport": "tls-h2",
            "url": url,
            "init": {"method": "GET", "headers": {"X-ZS-Req": f"{name}-{run_id}"}},
        }
        results, errors = run_group({"tls-h2": page}, {"tls-h2": [call]})
        if errors or not results:
            say(f"{name}: FAIL {'; '.join(errors) or 'the page returned no result'}")
            problems += 1
            continue
        result = results[0]
        found = check_one(result, {"run_id": run_id}, expect | {"request_id": call["id"]})
        say(
            f"{name}: {'OK' if not found else 'FAIL'} "
            f"{'; '.join(found) if found else 'upstream target as expected'}"
        )
        problems += bool(found)
    return 1 if problems else 0


# --------------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--origin",
        default="",
        help="controlled origin base (tunnel_origin.py) as the phone reaches it; required for a "
        "run unless --selftest",
    )
    parser.add_argument(
        "--http-origin",
        default="",
        help="base for the plaintext (HTTP/1.1) scenarios; defaults to --origin with the scheme flipped",
    )
    parser.add_argument(
        "--https-origin",
        default="",
        help="base for the TLS (h2) scenarios; defaults to --origin with the scheme flipped",
    )
    parser.add_argument(
        "--tls1-origin",
        default="",
        help="base for the TLS/HTTP-1.1 leg: a listener that offers http/1.1 only, so the decrypted "
        "H1 path is exercised separately from the plaintext one",
    )
    parser.add_argument("--serial", default=None,
                        help="adb serial; defaults to $SERIAL, else the only attached device")
    parser.add_argument("--browser", default="org.lineageos.jelly")
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--port", type=int, default=9333, help="local CDP forward port")
    parser.add_argument("--json", default="", help="write the full result set here")
    parser.add_argument(
        "--snapshot-label",
        default="",
        help="take before/after connection snapshots under this label, inside the run so both "
        "describe the same browser process",
    )
    parser.add_argument(
        "--no-navigation",
        action="store_true",
        help="skip the navigation controls (a batch of fetches cannot exercise the core's 302 branch)",
    )
    parser.add_argument(
        "--sequential-legs",
        default="auto",
        choices=("auto", "always", "never"),
        help="run the transports one after another with the full concurrency each (auto: only when "
        "the browser exposes fewer page targets than legs)",
    )
    parser.add_argument(
        "--readiness",
        default="",
        metavar="NAMED[,NAMED…],CONTROL",
        help="only check that the installed rule set is in force: every NAMED parameter must be "
        "removed upstream and CONTROL must survive. The last name is the control. Used by "
        "tunnel_acceptance.sh instead of counting log lines",
    )
    parser.add_argument(
        "--run-id",
        default="",
        help="this run's identifier (default: a random one). The acceptance script passes its own so "
        "the snapshots, the results file and the lock all name the same run",
    )
    parser.add_argument("--selftest", action="store_true")
    arguments = parser.parse_args()

    if arguments.selftest:
        return selftest(arguments.origin.rstrip("/"), arguments.timeout)
    # Resolved only for a real run: `--selftest` is a host-side check that needs no device.
    arguments.serial = device_serial.serial_from(arguments)
    if not arguments.origin and not (arguments.https_origin or arguments.tls1_origin):
        say("--origin (the controlled origin) is required for a run; --selftest needs none")
        return 2
    if arguments.rounds < 1 or arguments.concurrency < 1:
        say("--rounds and --concurrency must be positive")
        return 2

    cdp = load_cdp()  # late so --selftest needs no adb, and overridable (ZS_CDP_MODULE)

    origin = arguments.origin.rstrip("/")
    http_base = (arguments.http_origin or origin).rstrip("/")
    https_base = (arguments.https_origin or origin).rstrip("/")
    tls1_base = (arguments.tls1_origin or arguments.https_origin or origin).rstrip("/")
    run_id = arguments.run_id or uuid.uuid4().hex[:10]

    if arguments.readiness:
        parameters = [part.strip() for part in arguments.readiness.split(",") if part.strip()]
        if len(parameters) < 2:
            say(
                "--readiness needs at least NAMED,CONTROL (e.g. track,rxparam,zs_keep_me): every "
                "name but the last must be removed upstream, and the last must survive"
            )
            return 2
        *named, control = parameters
        browser = cdp.Browser.attach(arguments.serial, arguments.browser, port=arguments.port)
        page = open_page(browser, f"{https_base}/__id?zs_rid={run_id}", set(),
                         arguments.timeout, "readiness")
        return readiness(page, https_base, run_id, named, control)

    say(f"origin plain:  {http_base}")
    say(f"origin tls-h1: {tls1_base}")
    say(f"origin tls-h2: {https_base}")
    say(f"browser:       {arguments.browser} on {arguments.serial}")
    say(f"plan:          {arguments.rounds} round(s) x {arguments.concurrency} concurrent")

    browser = cdp.Browser.attach(arguments.serial, arguments.browser, port=arguments.port)

    used_targets: set[str] = set()
    bases = {"plain": http_base, "tls-h1": tls1_base, "tls-h2": https_base}
    available = len(getattr(browser, "page_targets", lambda: [])()) or len(TRANSPORTS)
    sequential = arguments.sequential_legs == "always" or (
        arguments.sequential_legs == "auto" and available < len(TRANSPORTS)
    )

    def park(base: str, label: str, *, shared: "object | None" = None):
        """Put a page on `base` so that leg's scenarios are same-origin with the document.

        One page per transport is required when the browser has one to spare: an `https://` document
        may not `fetch` an `http://` subresource (mixed content), and a cross-origin `fetch` on a
        different port is a CORS question rather than a filtering one. When the browser exposes fewer
        targets than legs, `shared` re-navigates the single target to *this leg's* base before the
        batch — without that, the plaintext leg would run its `fetch` calls from whatever TLS document
        the previous leg left behind, and every one of them would fail for a reason that has nothing
        to do with the tunnel.
        """
        url = f"{base}/__id?zs_rid={run_id}&probe=start"
        if shared is not None:
            # A page exposes `navigate` (real CDP and the test doubles both do). A page without it —
            # only ever a stub in the harness's own gate probe — is navigated through the browser it
            # came from when that is available, and otherwise left as it is: a shared target that
            # cannot be re-parked makes the following fetches fail on origin, which the run reports
            # rather than hides.
            navigator = getattr(shared, "navigate", None)
            if navigator is not None:
                navigator(url, timeout=arguments.timeout, settle=1.0)
            else:
                owner = getattr(shared, "browser", None)
                opener = getattr(owner, "open_target", None)
                target = getattr(shared, "target", None)
                if opener is not None and target is not None:
                    opener(target, url, timeout=arguments.timeout, settle=1.0)
            say(f"page ({label}): re-parked on {base} (single shared target)")
            return shared
        return open_page(browser, url, used_targets, arguments.timeout, label, relax=sequential)

    if sequential:
        say(
            "layout:       sequential legs — the browser exposes fewer page targets than transports, "
            "so each leg runs on its own with the full concurrency and the origin's in-flight peak "
            "is checked per leg. Each leg is re-navigated to its own origin first, so its fetches "
            "come from a same-origin document."
        )
        shared_page = park(bases[TRANSPORTS[0]], TRANSPORTS[0], shared=None)
        pages = {name: shared_page for name in TRANSPORTS}
    else:
        pages = {name: park(bases[name], name) for name in TRANSPORTS}

    scenarios = build_scenarios(origin, run_id, http_base, https_base, tls1_base)
    by_name = {scenario["name"]: scenario for scenario in scenarios}

    scope = {"run_id": run_id}
    results: list[dict] = []
    groups: list[dict] = []
    # Both snapshots are taken inside the run, around the batch, so they describe the same browser
    # process the batch used. Taken by the caller they would bracket a browser this code restarts.
    if arguments.snapshot_label:
        take_snapshot(arguments.serial, "before", arguments.snapshot_label, run_id)
    started = time.time()
    for round_index in range(arguments.rounds):
        if sequential:
            planned_groups = [
                plan_group(scenarios, arguments.concurrency, round_index, transport=transport)
                for transport in TRANSPORTS
            ]
            for group in planned_groups:
                transport = next(iter(group["legs"]))
                # Re-park the shared target on this leg's origin before its batch: the previous leg
                # left the document on a different scheme/port, and a `fetch` from there would be a
                # mixed-content or CORS failure rather than a filtering result.
                if sequential:
                    park(bases[transport], transport, shared=pages[transport])
                group_started = time.time()
                leg_results, errors = run_group(
                    {transport: pages[transport]}, {transport: group["legs"][transport]}
                )
                if errors:
                    say(f"round {round_index + 1} ({transport}): CDP failure: {'; '.join(errors)}")
                for result in leg_results:
                    result["round"] = round_index + 1
                    result["group"] = len(groups)
                results.extend(leg_results)
                groups.append(group)
                wall = (time.time() - group_started) * 1000.0
                ok = sum(
                    1 for result in leg_results
                    if result.get("status") == 200 and "error" not in result
                )
                peak = max(
                    (
                        result.get("inflight")
                        for result in leg_results
                        if isinstance(result.get("inflight"), int)
                    ),
                    default=0,
                )
                say(
                    f"round {round_index + 1} ({transport}): n={len(leg_results)} ok={ok} "
                    f"peak={peak} wall={wall:.0f} ms"
                )
            continue

        group = plan_group(scenarios, arguments.concurrency, round_index)
        group_started = time.time()
        group_results, errors = run_group(
            {transport: pages[transport] for transport in group["legs"]},
            group["legs"],
        )
        if errors:
            say(f"round {round_index + 1}: CDP failure: {'; '.join(errors)}")
        for result in group_results:
            result["round"] = round_index + 1
            result["group"] = len(groups)
        results.extend(group_results)
        groups.append(group)
        wall = (time.time() - group_started) * 1000.0
        ok = sum(
            1 for result in group_results if result.get("status") == 200 and "error" not in result
        )
        peak = max(
            (
                result.get("inflight")
                for result in group_results
                if isinstance(result.get("inflight"), int)
            ),
            default=0,
        )
        say(
            f"round {round_index + 1}: n={len(group_results)} ok={ok} peak={peak} "
            f"wall={wall:.0f} ms"
        )
    elapsed = time.time() - started
    if arguments.snapshot_label:
        take_snapshot(arguments.serial, "after", arguments.snapshot_label, run_id)

    # The origin's own concurrency numbers, read after the load stopped. Two independent figures:
    # `peak` from arrivals/departures inside the origin, `overlap` recomputed from every request's
    # interval. A run's "20 concurrent" claim rests on both, not on a number the harness computed for
    # itself. When the origin cannot answer, that is a failure, not a skip.
    origin_evidence: dict | None = None
    try:
        status, body, _ = origin_stats(https_base)
        if status == 200:
            origin_evidence = json.loads(body)
            say(
                f"origin evidence: peak={origin_evidence.get('peak')} "
                f"overlap={origin_evidence.get('overlap')} "
                f"requests={origin_evidence.get('count')}"
            )
        else:
            say(f"origin evidence: /__stats answered {status}; concurrency cannot be corroborated")
    except Exception as error:  # noqa: BLE001 - reported as a problem below, not a crash
        say(f"origin evidence: /__stats unreachable ({type(error).__name__}: {error})")

    problems: list[tuple[dict, list[str]]] = []
    structural_anchor = {"scenario": "<batch>", "index": -1, "id": "", "round": 0}
    for reason in validate_structure(
        groups, results, arguments.rounds * len(TRANSPORTS) if sequential else arguments.rounds,
        arguments.concurrency,
    ):
        problems.append((structural_anchor, [reason]))
    for reason in validate_concurrency(groups, results, arguments.concurrency, origin_evidence):
        problems.append(({"scenario": "<concurrency>", "index": -3, "id": "", "round": 0}, [reason]))
    if not sequential:
        for reason in validate_isolation(pages):
            problems.append(({"scenario": "<pages>", "index": -4, "id": "", "round": 0}, [reason]))

    for result in results:
        scenario = by_name.get(result.get("scenario"))
        if scenario is None:
            problems.append((result, [f"unknown scenario {result.get('scenario')!r}"]))
            continue
        found = check_one(result, scope, scenario["expect"])
        if found:
            problems.append((result, found))

    # ---- navigation controls -----------------------------------------------------------------
    navigation_results: list[dict] = []
    if not arguments.no_navigation:
        for scenario in (entry for entry in scenarios if entry.get("navigation")):
            page = pages[scenario["transport"]]
            try:
                result = run_navigation(page, scenario)
            except Exception as error:  # noqa: BLE001 - a dead page is a failure, not a crash
                problems.append(
                    (
                        {"scenario": scenario["name"], "index": -5, "id": "", "round": 0},
                        [f"navigation failed: {type(error).__name__}: {error}"],
                    )
                )
                continue
            navigation_results.append(result)
            found = check_one(result, scope, scenario["expect"])
            if found:
                problems.append((result, found))
            say(
                f"navigation {scenario['name']}: final={result.get('url')!r} "
                f"[{result.get('protocol')}]"
            )
    else:
        say("navigation controls: SKIPPED (--no-navigation); the 302 branch is not covered")

    totals: dict[str, Counter] = {}
    for result in results:
        counters = totals.setdefault(result.get("scenario", "?"), Counter())
        counters["n"] += 1
        if "error" in result:
            counters["err"] += 1
        elif result.get("status") != 200:
            counters[f"http_{result.get('status')}"] += 1
        else:
            counters["ok"] += 1

    say("")
    say(f"{'scenario':24}{'n':>5}{'ok':>5}{'err':>5}{'other':>7}")
    for name, counters in sorted(totals.items()):
        other = sum(value for key, value in counters.items() if key not in ("n", "ok", "err"))
        say(f"{name:24}{counters['n']:>5}{counters['ok']:>5}{counters['err']:>5}{other:>7}")

    latencies = sorted(r["ms"] for r in results if isinstance(r.get("ms"), (int, float)))
    if latencies:
        say(
            f"request latency: median {statistics.median(latencies):.0f} ms, "
            f"p95 {latencies[max(0, int(len(latencies) * 0.95) - 1)]:.0f} ms, max {latencies[-1]:.0f} ms"
        )
    if groups:
        say(
            f"in-flight peak per group: "
            f"{[group.get('peak') for group in groups]} (plan {arguments.concurrency} each); "
            f"total {elapsed:.1f} s"
        )

    protocols = Counter(
        (result.get("protocol") or "?").lower() for result in results if "error" not in result
    )
    say(f"negotiated protocols: {dict(protocols)}")
    # Every framing must appear: an all-h2 run means the plaintext and TLS/H1 legs never happened,
    # and an all-http/1.1 run means nothing was decrypted.
    for required in ("http/1.1", "h2"):
        if not protocols.get(required):
            problems.append(
                (
                    {"scenario": "<transports>", "index": -2, "id": "", "round": 0},
                    [f"no request negotiated {required}; both framings must be exercised"],
                )
            )

    for result, found in problems[:15]:
        say(
            f"  FAIL {result.get('scenario')} #{result.get('index')} (round {result.get('round')}): "
            f"{'; '.join(found)}"
        )
    if len(problems) > 15:
        say(f"  … {len(problems) - 15} more failure(s)")

    if arguments.json:
        Path(arguments.json).parent.mkdir(parents=True, exist_ok=True)
        Path(arguments.json).write_text(
            json.dumps(
                {
                    "origin_http": http_base,
                    "origin_tls1": tls1_base,
                    "origin_https": https_base,
                    "run_id": run_id,
                    "rounds": arguments.rounds,
                    "concurrency": arguments.concurrency,
                    "layout": "sequential" if sequential else "parallel",
                    # The origin's own two concurrency figures, quoted verbatim so a reader can check
                    # the "20 concurrent" claim against the upstream rather than against us.
                    "origin_peak": (origin_evidence or {}).get("peak"),
                    "origin_overlap": (origin_evidence or {}).get("overlap"),
                    "origin_requests": (origin_evidence or {}).get("count"),
                    "groups": [
                        {
                            "round": group["round"],
                            "legs": {name: len(calls) for name, calls in group["legs"].items()},
                            "n": group["n"],
                            "peak": group.get("peak"),
                        }
                        for group in groups
                    ],
                    "results": [
                        {key: value for key, value in result.items() if key != "body"}
                        for result in results
                    ],
                    "navigations": [
                        {key: value for key, value in result.items() if key != "body"}
                        for result in navigation_results
                    ],
                    "targets": {
                        name: str((getattr(page, "target", None) or {}).get("id") or "")
                        for name, page in pages.items()
                    },
                    "problems": [
                        {"result": result, "reasons": reasons} for result, reasons in problems
                    ],
                    "protocols": dict(protocols),
                    "plan_ids": [request_id for group in groups for request_id in group["ids"]],
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

    say("")
    if problems:
        request_level = sum(1 for result, _ in problems if result.get("index", -1) >= 0)
        say(
            f"FAIL: {len(problems)} problem(s) — {request_level} on individual request(s), "
            f"{len(problems) - request_level} structural"
        )
        return 1
    say(
        f"PASS: {len(results)} request(s) in {arguments.rounds} round(s) of "
        f"{arguments.concurrency}; counts and ids match the plan, both framings exercised "
        f"({dict(protocols)}), upstream in-flight peak "
        f"{[group.get('peak') for group in groups]}, every request confirmed by the controlled "
        f"origin's own record"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
