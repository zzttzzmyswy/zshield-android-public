#!/usr/bin/env python3
"""REMOVED — the host-side smoke test this file used to be reported PASS without touching the tunnel.

Why it is gone rather than fixed
--------------------------------
It drove `urllib` on the measurement **host**. Nothing in it touched the phone, the VPN, or the rule
engine, so it measured neither concurrency nor filtering and reported PASS on a run of nothing but
HTTP 500s (I2 first review, item 5; `docs/EFFECTIVENESS.md` §13.10). A later revision added a warning
and a `NOT-EVIDENCE` label, which is not enough: the command still exited 0, and a PASS-shaped exit
code is what gets quoted.

What happened at I2 stage 2 is why "keep it but warn" was rejected — a concurrency step in an
acceptance report came from a run that could not observe the thing it claimed.

Where to go instead
-------------------
`scripts/effectiveness/tunnel_concurrency.py` drives the protected browser on the phone over CDP and
requires every request to be confirmed by the controlled origin's own record (request id, method,
target, raw-body digest) — and requires the origin to have seen the requests in flight together.

    scripts/effectiveness/tunnel_acceptance.sh --rounds 5 --concurrency 20
    python3 scripts/effectiveness/tunnel_concurrency.py --selftest          # the checker can fail

This file now **refuses to run** and exits non-zero. It accepts no arguments: any invocation of the
old interface fails, so an old command line in an old report resolves to a failure that names its
replacement instead of a green run of something else. Deleting it would silently leave the old
command line as "command not found", which reads as a broken environment rather than a retired tool.
"""

from __future__ import annotations

import sys

REPLACEMENT = (
    "scripts/effectiveness/tunnel_acceptance.sh --rounds 5 --concurrency 20\n"
    "  python3 scripts/effectiveness/tunnel_acceptance.sh --help\n"
    "  python3 scripts/effectiveness/tunnel_concurrency.py --selftest"
)


def main(argv: list[str]) -> int:
    print(
        "REFUSED: concurrency_smoke.py is retired. It drove urllib on the measurement host, so it "
        "never traversed the VPN and its PASS meant nothing (I2 review item 5).\n"
        "Use the harness that drives the protected browser and checks the upstream origin's own "
        "record:\n  " + REPLACEMENT,
        file=sys.stderr,
    )
    if argv:
        print(f"\n(the arguments {argv!r} belong to the retired interface and were not run)", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
