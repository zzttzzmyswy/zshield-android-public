#!/usr/bin/env bash
# One command that reproduces the I2 request-path evidence end to end.
#
# Usage:
#   LOCK_OWNER=<task-id> scripts/effectiveness/tunnel_acceptance.sh [options]
#
#   --origin URL          controlled origin base as the **phone** reaches it (required)
#   --http-origin URL     plaintext leg (defaults to --origin with the scheme flipped)
#   --https-origin URL    TLS/H2 leg    (defaults to --origin with the scheme flipped)
#   --tls1-origin URL     TLS/H1 leg    (defaults to --https-origin)
#   --rounds N            concurrency groups (default 5)
#   --concurrency N       requests in each group (default 20)
#   --issue <task-id>     the same as LOCK_OWNER, spelled as a flag
#   --skip-selftest       skip the through-the-tunnel fault self-test
#
# The order is deliberate, and every step before the first device write can fail without changing
# anything on the phone:
#
#   0. **origin and arguments** — a configuration error is answered before the device is touched.
#   1. **the lock** — taken with this transaction's own token and *held for the whole run*. A tool that
#      released it on return would leave the rest of the transaction unprotected, which is what the
#      stage-3 review found. The token is this process's, so releasing at the end cannot delete a lock
#      another run took over after expiry.
#   2. **the rules backup** — read losslessly (real XML parse, JSON with an explicit `known` flag) and
#      *required*: if it cannot be read, the script exits before installing anything. The previous
#      version printed "NOT restored" after having already replaced the rules.
#   3. **rule installation** — the ordinary rule **and** the regex rule, for the origin's actual host,
#      because the scenario matrix asserts both kinds of rewrite. `--control-param` names a parameter
#      no rule mentions, and readiness requires it to survive.
#   4. **behavioural readiness** — `tunnel_concurrency.py --readiness` proves the rule set is in force
#      by observing the upstream, not by counting log lines.
#   5. **fault self-test** — through the same tunnel, using the same rule transaction (no second rule
#      install, no fixed log count, no leaving rules behind).
#   6. **the run** — `--rounds` × `--concurrency`, every request confirmed by the origin's own record,
#      with the origin's shared in-flight counter and its recomputed interval overlap both required.
#   7. **wind-down** — a bounded poll of `tunnel_snapshot.sh check`, which refuses to conclude anything
#      from a missing observation.
#   8. **restore** — on every exit path including a signal: the rules come back (verified by
#      re-reading) and the lock is released. A failed restore makes the exit status non-zero.
#
# Signal handling: `trap` on EXIT/INT/TERM/HUP runs the same restore, so an interrupted run does not
# leave the phone with the probe's rules installed.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# shellcheck source=device-lock.sh
# `device-lock.sh` resolves `SERIAL` lazily, on the first device operation.
. scripts/effectiveness/device-lock.sh

PKG="${PKG:-top.zztweb.zshield}"
RECEIVER="$PKG/.filters.DebugCommandReceiver"
OUT="${OUT:-.effectiveness/results}"
ORIGIN=""
HTTP_ORIGIN=""
HTTPS_ORIGIN=""
TLS1_ORIGIN=""
ROUNDS=5
CONCURRENCY=20
SKIP_SELFTEST=0
#: A parameter an ordinary `$removeparam=` rule names; the matrix expects it gone on decrypted legs.
RULE_PARAM="track"
#: A parameter a **regex** rule names; also expected gone, so the matrix's regex scenarios can pass.
REGEX_PARAM="rxparam"
#: A parameter **no** rule names; the control that keeps "the whole query was dropped" from passing.
CONTROL_PARAM="zs_keep_me"

while [ $# -gt 0 ]; do
    case "$1" in
        --rounds) shift; ROUNDS="${1:-5}" ;;
        --concurrency) shift; CONCURRENCY="${1:-20}" ;;
        --origin) shift; ORIGIN="${1:-}" ;;
        --http-origin) shift; HTTP_ORIGIN="${1:-}" ;;
        --https-origin) shift; HTTPS_ORIGIN="${1:-}" ;;
        --tls1-origin) shift; TLS1_ORIGIN="${1:-}" ;;
        --fault-origin) shift; : ;;   # accepted for compatibility; the fault test uses --origin now
        --rule-param) shift; RULE_PARAM="${1:-track}" ;;
        --regex-param) shift; REGEX_PARAM="${1:-rxparam}" ;;
        --control-param) shift; CONTROL_PARAM="${1:-zs_keep_me}" ;;
        --issue) shift; LOCK_OWNER="${1:-}" ;;
        --issue=*) LOCK_OWNER="${1#--issue=}" ;;
        --skip-selftest) SKIP_SELFTEST=1 ;;
        -h|--help) sed -n '2,58p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

mkdir -p "$OUT"
FAILED=0
step() { printf '\n===== %s\n' "$*"; }
note() { printf '%s\n' "$*"; }

# ------------------------------------------------------------------------------------------------
# Restore state — defined before anything can fail, so every exit path has it
# ------------------------------------------------------------------------------------------------
RULES_BACKUP="$OUT/acceptance-rules-backup.json"
RESTORE_NEEDED=0
LOCK_HELD_BY_US=0
RESTORE_FAILED=0

restore_all() {
    local code=$?
    # One restore, whatever else fails on the way out; the trap is disarmed first so the `exit` below
    # cannot re-enter it.
    trap - EXIT INT TERM HUP
    if [ "$RESTORE_NEEDED" = 1 ]; then
        step "restore"
        if ! lock_require; then
            # This run's lease is gone (or was never taken), so the phone may now belong to another
            # task. Writing the rules back would overwrite whatever that task installed — worse than
            # reporting honestly that the original set was not put back. This is the case the previous
            # version could not see: a failed background renewal ended only the renewer, and the
            # transaction kept writing.
            RESTORE_FAILED=1
            echo "rules: THE USER RULES WERE NOT RESTORED — this run does not hold the device lock" >&2
            echo "       ($(lock_loss_reason || echo 'no lease')); no write was attempted. The backup at" >&2
            echo "       $RULES_BACKUP still holds the original set." >&2
        elif python3 scripts/effectiveness/rules_backup.py restore --from "$RULES_BACKUP" \
                --serial "$SERIAL" --package "$PKG"; then
            RESTORE_NEEDED=0
        else
            RESTORE_FAILED=1
            echo "rules: THE USER RULES COULD NOT BE RESTORED — see the message above;" >&2
            echo "       the backup at $RULES_BACKUP is what was there before this run." >&2
        fi
    fi
    if [ "$LOCK_HELD_BY_US" = 1 ]; then
        # A renewal child that survived is a leaked process nobody can attribute, so its cleanup is
        # part of the exit status rather than a line in a log.
        lock_stop_renewer || RESTORE_FAILED=1
        lock_release || true
    fi
    if [ "$RESTORE_FAILED" = 1 ] && [ "$code" = 0 ]; then
        code=1
    fi
    exit "$code"
}
trap restore_all EXIT
# Signals get their own entry so the status is explicit: a signalled run is a **failed** run, and it
# must not be reported as 0 whatever the interrupted command happened to be doing. `exit 130` reaches
# the EXIT trap once, which then does the one restore.
for _signal in INT TERM HUP; do
    # shellcheck disable=SC2064  # the trap is meant to see this process's own state
    trap "exit 130" "$_signal"
done

# ------------------------------------------------------------------------------------------------
# 0. Arguments
# ------------------------------------------------------------------------------------------------
if [ -z "$ORIGIN" ] && [ -z "$HTTPS_ORIGIN" ]; then
    cat >&2 <<'EOF'
no --origin given. This script needs the controlled origin, because only it reports the request ID,
the raw-body digest, the in-flight counter and the request intervals the assertions read:

  python3 scripts/effectiveness/tunnel_origin.py --port 18200 --https-port 18443 \
      --https1-port 18444 --cert /path/cert.pem --key /path/key.pem --hold-ms 400 \
      --ready-file .effectiveness/results/origin-ready.json

Then pass the base the **phone** reaches (see docs/TESTING.md §14.1: with the tunnel up, every IPv4
destination including the LAN is routed into the core, so a host port is not reachable — use
`adb reverse` for a local fixture or a public entry point for a real run).
EOF
    exit 2
fi
HTTPS_ORIGIN="${HTTPS_ORIGIN:-$ORIGIN}"
HTTP_ORIGIN="${HTTP_ORIGIN:-$(printf '%s' "$HTTPS_ORIGIN" | sed 's#^https://#http://#')}"
TLS1_ORIGIN="${TLS1_ORIGIN:-$HTTPS_ORIGIN}"
# The host the rules are scoped to: the TLS/H2 origin, because the rewrite assertions run there.
RULE_HOST="$(printf '%s' "$HTTPS_ORIGIN" | sed 's#^.*://##; s#/.*$##; s#:.*$##')"
if [ -z "$RULE_HOST" ]; then
    echo "cannot derive a host from --origin/--https-origin ($HTTPS_ORIGIN)" >&2
    exit 2
fi
if [ -z "$LOCK_OWNER" ]; then
    # Reading the lock is not a device write, so the state is reported before refusing: an operator
    # then learns *who* holds the phone instead of only that their own invocation was incomplete, and
    # the check is observable in the adb transcript rather than implied by an exit code.
    step "device lock"
    lock_status || true
    cat >&2 <<'EOF'
this script must be told which task owns the device lock:
  LOCK_OWNER=MYS-2817 scripts/effectiveness/tunnel_acceptance.sh --origin https://ORIGIN
  or  ... --issue MYS-2817
There is deliberately no default: a default owner reads as "mine" to every run and disables the lock.
Nothing on the device was changed.
EOF
    exit 2
fi

# ------------------------------------------------------------------------------------------------
# 1. The lock — held for the whole transaction, before any device write
# ------------------------------------------------------------------------------------------------
# This script has no device-free path: it samples connections and drives a browser. Resolve the
# serial once here, before the lock, so a missing/ambiguous device is refused with the resolver's
# explanation instead of surfacing later as `adb -s "" ...`.
ensure_serial
step "device lock"
if ! lock_take; then
    echo "not taking the device; nothing on it was changed" >&2
    exit 1
fi
LOCK_HELD_BY_US=1
lock_start_renewer

# ------------------------------------------------------------------------------------------------
# 2. Preconditions
# ------------------------------------------------------------------------------------------------
step "preconditions"
state="$(adb -s "$SERIAL" get-state 2>&1 | tr -d '\r')"
if [ "$state" != "device" ]; then
    echo "device $SERIAL is not available ($state)" >&2
    exit 1
fi
note "device:   $SERIAL ($state)"
tunnel="$(adb -s "$SERIAL" shell dumpsys connectivity 2>/dev/null | grep -c IS_VPN)"
note "tunnel:   IS_VPN x$tunnel"
if [ "$tunnel" = "0" ]; then
    echo "the tunnel is down; run: LOCK_OWNER=$LOCK_OWNER scripts/effectiveness/condition.sh zshield-https" >&2
    exit 1
fi

# ------------------------------------------------------------------------------------------------
# 3. The rules backup — REQUIRED, and taken before anything is installed
# ------------------------------------------------------------------------------------------------
# If this fails, the run stops here. That ordering is the whole point: the previous version installed
# the probe rule first and only then discovered it could not put the original back.
step "capturing the user rules (required)"
if ! python3 scripts/effectiveness/rules_backup.py capture --out "$RULES_BACKUP" \
        --serial "$SERIAL" --package "$PKG"; then
    echo "the current user rules could not be read, so this run will not replace them." >&2
    echo "nothing on the device was changed." >&2
    exit 1
fi
RESTORE_NEEDED=1

# ------------------------------------------------------------------------------------------------
# 4. Install the rules the matrix needs, then prove them by behaviour
# ------------------------------------------------------------------------------------------------
# Two rules, because the matrix asserts two kinds of rewrite:
#   ||host^$removeparam=track,all      the ordinary form   (--rule-param)
#   ||host^$removeparam=/^rxparam=/    the regex form      (--regex-param)
# and one parameter that no rule names (--control-param), which readiness requires to survive. The
# previous version installed only the ordinary rule while the matrix expected the regex removal, and
# then used the regex parameter as the "must survive" control — so the fixed matrix could not pass.
#
# `,all` because an untyped `$removeparam` matches documents only by design (docs/TESTING.md §14.7)
# and these probes are `fetch` calls. The rules travel as a file read on the device: `adb shell`
# re-parses its argument through the device's `sh`, which expands `$removeparam` to nothing.
rule_file="$OUT/acceptance-rules.txt"
mkdir -p "$OUT"
{
    printf '! installed by tunnel_acceptance.sh for %s\n' "$RULE_HOST"
    printf '||%s^$removeparam=%s,all\n' "$RULE_HOST" "$RULE_PARAM"
    printf '||%s^$removeparam=/^%s=/,all\n' "$RULE_HOST" "$REGEX_PARAM"
} >"$rule_file"

step "installing the rewrite rules and proving them by behaviour"
note "rules:"
sed 's/^/  /' "$rule_file"
note "control parameter (no rule names it, it must survive): $CONTROL_PARAM"

# Every device **write** from here on is guarded by `lock_require`: a background renewal that failed
# would otherwise be invisible to this process, and the transaction would keep writing probe rules to
# a phone another task now owns. The install itself goes through `rules_backup.py install`, whose
# device-side script reads the staged file with a sentinel — `"$(cat …)"` drops trailing newlines, and
# a rule file whose last line is empty is not the same rule file.
if ! lock_require; then
    echo "the lock is gone; not installing anything" >&2
    exit 1
fi
if ! python3 scripts/effectiveness/rules_backup.py install --from "$rule_file" \
        --serial "$SERIAL" --package "$PKG"; then
    echo "the rule broadcast did not complete" >&2
    exit 1
fi

# Readiness is retried rather than slept through: the compile is debounced and takes seconds, and a
# fixed sleep is either too short (flaky) or too long (slow) depending on the day.
readiness_ok=0
for attempt in 1 2 3 4 5 6; do
    if python3 scripts/effectiveness/tunnel_concurrency.py \
            --origin "$HTTPS_ORIGIN" --serial "$SERIAL" \
            --readiness "$RULE_PARAM,$REGEX_PARAM,$CONTROL_PARAM"; then
        readiness_ok=1
        break
    fi
    note "readiness attempt $attempt did not pass yet; waiting for the hot reload"
    sleep 8
done
if [ "$readiness_ok" != 1 ]; then
    cat >&2 <<'EOF'
the run's rule set is not in force: a named parameter was not removed upstream, or the control
parameter was lost as well. Both are checked by behaviour, so this is not a log-timing artefact —
check that HTTPS filtering is on, that the measuring browser's uid is in the decrypted set, and that
the rules' host matches the origin (`condition.sh zshield-https --issue <task>`).
EOF
    exit 1
fi
note "readiness: both named parameters are removed upstream and the control parameter survives"

# ------------------------------------------------------------------------------------------------
# 5. Fault self-test, through the same tunnel and the same rule transaction
# ------------------------------------------------------------------------------------------------
if [ "$SKIP_SELFTEST" = 0 ]; then
    step "fault self-test (each injected fault must be detected)"
    # `--no-install-rules`: the rules for this transaction are already installed and proven above.
    # The script used to install its own single rule, wait for a fixed log count, and leave the rule
    # behind; now it observes under the rules this run already established.
    if ! python3 scripts/effectiveness/tunnel_fault_selftest.py --origin "$HTTPS_ORIGIN" \
            --serial "$SERIAL" --no-install-rules --json "$OUT/tunnel-faults.json"; then
        echo "the harness failed its own fault test; a PASS below would mean nothing" >&2
        exit 1
    fi
else
    step "fault self-test: SKIPPED (--skip-selftest); the run's PASS is not backed by it"
fi

# ------------------------------------------------------------------------------------------------
# 6. The run
# ------------------------------------------------------------------------------------------------
step "concurrency run: $ROUNDS group(s) x $CONCURRENCY (with in-run snapshots)"
run_id="accept-$(date +%s)-$$"
if ! python3 scripts/effectiveness/tunnel_concurrency.py \
        --origin "$HTTPS_ORIGIN" --rounds "$ROUNDS" --concurrency "$CONCURRENCY" \
        --serial "$SERIAL" --run-id "$run_id" \
        --http-origin "$HTTP_ORIGIN" --https-origin "$HTTPS_ORIGIN" --tls1-origin "$TLS1_ORIGIN" \
        --snapshot-label "accept" \
        --json "$OUT/tunnel-concurrency.json"; then
    FAILED=1
fi

# ------------------------------------------------------------------------------------------------
# 7. Wind-down
# ------------------------------------------------------------------------------------------------
WIND_DOWN_LIMIT=45
step "waiting up to ${WIND_DOWN_LIMIT}s for the connection count to settle"
settled=0
elapsed=0
while [ "$elapsed" -lt "$WIND_DOWN_LIMIT" ]; do
    OUT="$OUT" SERIAL="$SERIAL" RUN_ID="$run_id" \
        scripts/effectiveness/tunnel_snapshot.sh settled accept >/dev/null 2>&1 || true
    if OUT="$OUT" SERIAL="$SERIAL" RUN_ID="$run_id" \
            scripts/effectiveness/tunnel_snapshot.sh check accept; then
        settled=1
        break
    fi
    sleep 5
    elapsed=$((elapsed + 5))
done
if [ "$settled" = 1 ]; then
    note "settled after ${elapsed}s"
else
    echo "did NOT settle within ${WIND_DOWN_LIMIT}s — see the delta below and the check output above" >&2
    FAILED=1
fi

step "delta"
OUT="$OUT" SERIAL="$SERIAL" RUN_ID="$run_id" \
    scripts/effectiveness/tunnel_snapshot.sh delta accept 2>/dev/null | sed 's/^/  /' || true

step "summary"
python3 - "$OUT" <<'PY'
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
concurrency = out / "tunnel-concurrency.json"
faults = out / "tunnel-faults.json"

if concurrency.exists():
    data = json.loads(concurrency.read_text(encoding="utf-8"))
    problems = data.get("problems") or []
    total = len(data.get("results") or [])
    print(f"concurrency: {total - len(problems)}/{total} passed "
          f"({data.get('rounds')} rounds x {data.get('concurrency')}, {data.get('layout')} legs)")
    print(f"protocols:   {data.get('protocols')}")
    print(f"in-flight:   {[group.get('peak') for group in data.get('groups') or []]}")
    print(f"origin:      peak={data.get('origin_peak')} overlap={data.get('origin_overlap')}")
    print(f"targets:     {data.get('targets')}")
else:
    print("concurrency: no result file")

if faults.exists():
    cases = json.loads(faults.read_text(encoding="utf-8")).get("cases") or []
    missed = [case["case"] for case in cases if not case["detected"]]
    print(f"faults:      {len(cases) - len(missed)}/{len(cases)} detected"
          + (f"; MISSED: {missed}" if missed else ""))
else:
    print("faults:      skipped")
PY

if [ "$FAILED" != 0 ]; then
    echo
    echo "ACCEPTANCE FAILED: at least one step above did not meet its condition" >&2
fi
exit "$FAILED"
