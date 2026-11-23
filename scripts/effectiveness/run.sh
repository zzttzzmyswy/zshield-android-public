#!/usr/bin/env bash
# Run the full effectiveness measurement for one condition: the two public test pages and the 20
# reference sites.
#
# Usage:
#   scripts/effectiveness/run.sh <vpn-off|zshield-default|zshield-https> [--test-pages] [--sites] [--only <slugs>]
#
# One command per condition is the task card's requirement (§5), so this script does exactly the two
# things needed: it puts the device into the condition through `condition.sh`, then measures. Every
# step prints its command, and the JSON each step writes is what the report quotes.
#
# `--with-agrd-test-lists` installs the testcases.agrd.dev companion filter lists before the QUnit
# pages are opened. It is off by default because it changes the rule set: without it the QUnit pages
# measure "does this build speak the syntax", with it they measure "does the shipped rule set plus the
# page's own test list produce the right DOM". Both are reported, separately labelled.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

OUT="${OUT:-.effectiveness/results}"
CONDITION=""
WANT_TESTPAGES=0
WANT_SITES=0
WANT_AGRD=0
ONLY=""

while [ $# -gt 0 ]; do
    case "$1" in
        vpn-off|zshield-default|zshield-https) CONDITION="$1" ;;
        --test-pages) WANT_TESTPAGES=1 ;;
        --sites) WANT_SITES=1 ;;
        --with-agrd-test-lists) WANT_AGRD=1 ;;
        --only) shift; ONLY="${1:-}" ;;
        -h|--help)
            sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

if [ -z "$CONDITION" ]; then
    echo "usage: scripts/effectiveness/run.sh <vpn-off|zshield-default|zshield-https> [--test-pages] [--sites]" >&2
    exit 2
fi
# Neither flag given means "everything": the common case is one command per condition.
if [ "$WANT_TESTPAGES" = 0 ] && [ "$WANT_SITES" = 0 ]; then
    WANT_TESTPAGES=1
    WANT_SITES=1
fi

mkdir -p "$OUT"
STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
say() { printf '\n===== %s\n' "$*"; }

say "condition: $CONDITION"
scripts/effectiveness/condition.sh "$CONDITION" || {
    echo "could not put the device into condition '$CONDITION'" >&2
    exit 1
}

# The companion lists are installed *around the first QUnit pass only*, and a second pass is run
# without them. That is deliberate: the two passes answer different questions, and mixing them into
# one number would answer neither.
#
#   pass A (shipped rule set, no companion lists): does this build *act on* the syntax at all?
#   pass B (companion lists installed): does the rule set + that page's own test list produce the
#                                       right DOM?
#
# The 20 reference sites are measured **between** the two passes and with the lists removed, because
# they are real sites: installing the test lists would add rules written for the test fixture pages
# (`###case-1-elemhide > .test-banner`) and change what those sites measure.
if [ "$WANT_AGRD" = 1 ] && [ "$WANT_TESTPAGES" = 1 ]; then
    say "public test pages, pass A (shipped rule set, no companion lists)"
    python3 scripts/effectiveness/testpages.py --condition "$CONDITION" --out "$OUT" --suffix=_A \
        || FAILED_TESTPAGES=1
fi

if [ "$WANT_SITES" = 1 ]; then
    say "reference sites"
    # Always without the companion lists, whatever `--with-agrd-test-lists` asked for.
    scripts/effectiveness/condition.sh clear-test-lists >/dev/null 2>&1 || true
    if [ -n "$ONLY" ]; then
        python3 scripts/effectiveness/sites.py --condition "$CONDITION" --out "$OUT" --only "$ONLY" \
            || FAILED_SITES=1
    else
        python3 scripts/effectiveness/sites.py --condition "$CONDITION" --out "$OUT" || FAILED_SITES=1
    fi
fi

if [ "$WANT_AGRD" = 1 ] && [ "$WANT_TESTPAGES" = 1 ]; then
    say "installing the companion lists and re-measuring the test pages (pass B)"
    scripts/effectiveness/condition.sh apply-test-lists || exit 1
    python3 scripts/effectiveness/testpages.py --condition "$CONDITION" --out "$OUT" --suffix=_B \
        || FAILED_TESTPAGES=1
    say "clearing the companion filter lists"
    scripts/effectiveness/condition.sh clear-test-lists
elif [ "$WANT_TESTPAGES" = 1 ]; then
    say "public test pages"
    python3 scripts/effectiveness/testpages.py --condition "$CONDITION" --out "$OUT" || FAILED_TESTPAGES=1
fi

say "summary"
python3 - "$OUT" "$CONDITION" "$STARTED" <<'PY'
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
condition = sys.argv[2]
started = sys.argv[3]

def load(name):
    path = out / f"{name}-{condition}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

pages = load("testpages")
sites = load("sites")
print(f"condition:  {condition}")
print(f"started:    {started}")
if pages:
    score = (pages.get("adblockTester") or {}).get("score")
    print(f"adblock-tester: {score}/100" if score is not None else "adblock-tester: not measured")
    for key, reading in (pages.get("qunit") or {}).items():
        counts = reading.get("counts") or {}
        if reading.get("error"):
            print(f"  qunit {key:<16} ERROR: {reading['error'][:90]}")
            continue
        subscription = reading.get("subscription") or {}
        state = "list active" if subscription.get("subscribed") else "list NOT active"
        print(
            f"  qunit {key:<16} tests {counts.get('testsPassed', '?')}/{counts.get('tests', '?')} passed, "
            f"assertions {counts.get('assertionsPassed', '?')}/{counts.get('assertionsTotal', '?')} ({state})"
        )
if sites:
    total = len(sites["sites"])
    broken = [slug for slug, entry in sites["sites"].items() if entry.get("signals")]
    errored = [slug for slug, entry in sites["sites"].items() if entry.get("error")]
    print(f"sites:      {total} measured, {len(broken)} with breakage signals, {len(errored)} errored")
    for slug in broken:
        print(f"  ! {slug}: {','.join(sites['sites'][slug]['signals'])}")
PY

if [ -n "${FAILED_TESTPAGES:-}${FAILED_SITES:-}" ]; then
    echo
    echo "some measurements failed; see the output above" >&2
    exit 1
fi
