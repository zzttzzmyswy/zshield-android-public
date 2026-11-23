#!/usr/bin/env bash
# Front/settled snapshots of the resources a concurrency run consumes, so "no leak" is a measurement
# and not an assertion.
#
# Usage:
#   RUN_ID=<run> scripts/effectiveness/tunnel_snapshot.sh <before|settled|after|delta|check> [label]
#
# What is sampled, and why each one:
#
#   sockets      TCP sockets owned by the app's uid, by state, read from `/proc/net/tcp{,6}`. The
#                tunnel is a userspace stack, so every proxied connection is one of these.
#   rss_kb       RSS at the time of the snapshot, so a run that is clean but grew is still visible.
#   threads      thread count — a leak of tokio tasks each blocking a worker also lands here.
#   sockstat     the kernel's own socket totals, which catch a leak the uid filter might miss.
#
# The three facts every snapshot must carry
# -----------------------------------------
# The stage-3 review accepted a pair of hand-written snapshots with **no** `run`, no `readable`, no
# `collected`, no `ok`, a shared pid/uid, and app-owned ESTABLISHED growing 1 -> 3 — and the gate said
# "wound down". Each of those was a separate hole:
#
#   run=<id>          which run this sample belongs to. A pair from different runs is not comparable,
#                     and a snapshot that names no run cannot be shown to belong to this one, so it is
#                     refused rather than assumed.
#   at=<epoch>        when it was taken, so a stale file from an earlier run is visible as stale.
#   readable=yes|no   whether `/proc/net/tcp` could be read at all. "Could not look" and "looked and
#                     found none" are different facts; only the second can support "wound down". A
#                     read failure is encoded (`readable=no`, `sockets=UNREADABLE`) and refused; a
#                     genuine zero (`readable=yes`, `sockets=`) is a valid observation and can pass.
#   collected=k/n     how many fields the one device-side pipeline actually produced.
#   ok=yes|no         whether the sample is usable at all.
#
# What may veto `check`
# ---------------------
#   01 ESTABLISHED  must not grow at all for the **app's own uid**. The previous version gave it a +2
#                   allowance "for the browser's keep-alives", which is wrong: the app does not run
#                   the browser, and the review measured that allowance accepting a 1 -> 3 growth of
#                   app-owned sockets. Browser connections are charged to the browser's uid, not this
#                   app's, so no allowance is needed or granted here.
#   08 CLOSE_WAIT   must not grow — it is where a leaked tunnel connection sits.
#   05 FIN_WAIT2    must not grow — the review's counter-example grew it 0 -> 1000 unchecked.
#   kernel TCP      must not grow beyond the same small margin, as a second opinion on the uid filter.
#
# Snapshots are written to `.effectiveness/results/tunnel-snapshot-<label>-<phase>.txt`.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# shellcheck source=device-serial.sh
. scripts/effectiveness/device-serial.sh

PKG="${PKG:-top.zztweb.zshield}"
OUT="${OUT:-.effectiveness/results}"
PHASE="${1:-before}"
LABEL="${2:-run}"
#: The run this sample belongs to. Required: a snapshot that cannot name its run cannot be compared.
RUN_ID="${RUN_ID:-}"

d()   { adb -s "$SERIAL" "$@"; }
sh_() { adb -s "$SERIAL" shell "$@"; }

mkdir -p "$OUT"
FILE="$OUT/tunnel-snapshot-${LABEL}-${PHASE}.txt"

# One `adb shell` round trip per field would cost seconds each on a Wi-Fi link; the whole sample is
# taken by a single on-device script and shipped as text.
#
# Every field is emitted with its own marker rather than as an empty value: `sockets=` with nothing
# after it is indistinguishable from "the table was readable and empty", and that ambiguity is exactly
# what let a missing observation pass as a clean one.
sample() {
    local pid uid
    pid="$(sh_ "pidof $PKG" 2>/dev/null | tr -d '\r' | cut -d' ' -f1)"
    # `dumpsys package` reports `appId`, which is the uid the sockets are charged to. It is read
    # rather than assumed (10123 vs 10250 differ per install) and it survives the app restarting.
    uid="$(sh_ "dumpsys package $PKG 2>/dev/null | grep -oE 'appId=[0-9]+' | head -1 | cut -d= -f2" \
        | tr -d '\r')"
    printf 'pid=%s\n' "${pid:-absent}"
    printf 'uid=%s\n' "${uid:-unknown}"
    if [ -z "$pid" ] || [ -z "$uid" ]; then
        printf 'readable=no\nsockets=UNAVAILABLE\ncollected=0/5\nok=no\n'
        printf 'error=pid=%s uid=%s\n' "${pid:-absent}" "${uid:-unknown}"
        return 0
    fi
    # One device-side pipeline: the uid filter runs there, because shipping both tables costs more
    # than the numbers are worth and the Wi-Fi link is the slow part.
    sh_ "printf 'readable=%s\n' \"\$( [ -r /proc/net/tcp ] && echo yes || echo no )\"; \
         printf 'sockets=%s\n' \"\$(cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk -v u=$uid 'NR>1 && \$8==u {print \$4}' | sort | uniq -c | tr -s ' ' | tr '\n' ' ')\"; \
         printf 'rss_kb=%s\n' \"\$(grep VmRSS /proc/$pid/status 2>/dev/null | grep -oE '[0-9]+')\"; \
         printf 'threads=%s\n' \"\$(grep Threads /proc/$pid/status 2>/dev/null | grep -oE '[0-9]+')\"; \
         printf 'sockstat=%s\n' \"\$(grep -E '^TCP:' /proc/net/sockstat 2>/dev/null | tr -s ' ')\"" \
        2>/dev/null | tr -d '\r'
}

# A sample is usable only when every field it claims to report is present. The `ok=` flag is computed
# here rather than trusted from the device, so a device-side pipeline that half-fails cannot label
# itself healthy.
finalize() {
    python3 - "$1" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
values = {}
for line in path.read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    key, _, value = line.partition("=")
    values[key.strip()] = value.strip()

required = ("run", "at", "pid", "uid", "sockets", "rss_kb", "threads")
present = {key for key in required if key in values and (values[key] or key == "sockets")}
usable = len(present) == len(required)
usable = usable and values.get("pid") not in ("absent", "unknown")
usable = usable and values.get("uid") not in ("unknown",)
# `readable=no` means `/proc/net/tcp` was unreadable: `sockets=` being empty then means "we could not
# look". `sockets=UNAVAILABLE` is the explicit marker for that, and neither is a valid observation.
if values.get("readable") != "yes" or values.get("sockets") == "UNAVAILABLE":
    usable = False
collected = len(present)
values["collected"] = f"{collected}/{len(required)}"
values["ok"] = "yes" if usable else "no"
with path.open("a", encoding="utf-8") as handle:
    handle.write(f"collected={values['collected']}\n")
    handle.write(f"ok={values['ok']}\n")
    if not usable:
        handle.write("error=an observation is missing; this snapshot cannot support a conclusion\n")
print(f"collected={values['collected']} ok={values['ok']}")
PY
}

case "$PHASE" in
    before|after|settled)
        # Only the sampling phases talk to a phone; `check` reads files that already exist. Resolving
        # here, rather than at the top, keeps the device-free subcommands device-free.
        ensure_serial
        if [ -z "$RUN_ID" ]; then
            cat >&2 <<'EOF'
tunnel_snapshot.sh needs RUN_ID: a snapshot that does not name its run cannot be compared with
another one, and the stage-3 review accepted a hand-written pair with no run at all. Pass the run's
identifier (the acceptance script derives one and passes it to every phase).
EOF
            exit 2
        fi
        {
            printf '# phase=%s label=%s at=%s\n' "$PHASE" "$LABEL" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            printf '# serial=%s package=%s\n' "$SERIAL" "$PKG"
            printf 'run=%s\n' "$RUN_ID"
            printf 'at=%s\n' "$(date +%s)"
            sample
        } | tee "$FILE"
        finalize "$FILE" >/dev/null
        tail -n 2 "$FILE"
        echo "snapshot: $FILE"
        ;;
    delta)
        before="$OUT/tunnel-snapshot-${LABEL}-before.txt"
        after="$OUT/tunnel-snapshot-${LABEL}-after.txt"
        if [ ! -f "$before" ] || [ ! -f "$after" ]; then
            echo "need both $before and $after" >&2
            exit 2
        fi
        python3 - "$before" "$after" <<'PY'
import sys
from pathlib import Path

def read(path):
    values = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values

before, after = read(sys.argv[1]), read(sys.argv[2])
print(f"run        {before.get('run', '?')}")
print(f"{'metric':10} {'before':>10} {'after':>10} {'delta':>10}")
for key in ("rss_kb", "threads"):
    old, new = before.get(key, "?"), after.get(key, "?")
    try:
        delta = f"{int(new) - int(old):+d}"
    except ValueError:
        delta = "n/a"
    print(f"{key:10} {old:>10} {new:>10} {delta:>10}")
print(f"sockets    before: {before.get('sockets', '?')}")
print(f"sockets    after:  {after.get('sockets', '?')}")
print(f"sockstat   before: {before.get('sockstat', '?')}")
print(f"sockstat   after:  {after.get('sockstat', '?')}")
for side, values in (("before", before), ("after", after)):
    if values.get("ok") != "yes":
        print(f"NOTE: the {side} snapshot is not usable (ok={values.get('ok')}, "
              f"readable={values.get('readable')}, collected={values.get('collected')}); "
              "read these numbers as unverified.")
if before.get("run") != after.get("run"):
    print(f"NOTE: the snapshots name different runs ({before.get('run')} vs {after.get('run')}).")
PY
        ;;
    check)
        # Exit 0 only when the run has demonstrably wound down. This is the command the acceptance
        # script polls: its exit status is the gate, so "the connections look fine in the printout"
        # cannot be mistaken for a pass.
        #
        # Exit codes: 0 settled, 1 not settled, 2 missing/unusable input (never a pass either way).
        before="$OUT/tunnel-snapshot-${LABEL}-before.txt"
        settled=""
        for candidate in "${LABEL}-settled" "${LABEL}-settled-after" "${LABEL}-after"; do
            if [ -f "$OUT/tunnel-snapshot-${candidate}.txt" ]; then
                settled="$OUT/tunnel-snapshot-${candidate}.txt"
                break
            fi
        done
        if [ ! -f "$before" ] || [ -z "$settled" ]; then
            echo "check: missing snapshot ($before / $OUT/tunnel-snapshot-${LABEL}-settled.txt)" >&2
            exit 2
        fi
        python3 - "$before" "$settled" "${RUN_ID:-}" "${TIMESTAMP_SLACK:-600}" <<'PY2'
import re
import sys
import time
from pathlib import Path

def read(path):
    values = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values

def states(text):
    """`sockets= 6 01  8 05  1 08` -> {'01': 6, '05': 8, '08': 1}."""
    found = {}
    for count, code in re.findall(r"(\d+)\s+([0-9A-Fa-f]{2})", text or ""):
        found[code.upper()] = found.get(code.upper(), 0) + int(count)
    return found

before, settled = read(sys.argv[1]), read(sys.argv[2])
expected_run = sys.argv[3]
slack = int(sys.argv[4])

def refuse(message):
    print(f"check: {message}", file=sys.stderr)
    raise SystemExit(2)

# --- the observations themselves must be usable -------------------------------------------
#
# Usability is recomputed here from the fields this conclusion actually reads. A flag cannot outvote
# the data it describes, and the review's hand-written pair is judged by what it contains rather than
# by whether it happens to carry `ok=yes`.
# `sockets=` with nothing after it is a **valid** observation ("readable, and the table held no rows
# for this uid"); a missing key is not. The two are different facts and the check must not merge them.
for side, values in (("before", before), ("settled", settled)):
    absent = [key for key in ("run", "at", "pid", "uid", "readable", "sockets") if key not in values]
    blank = [
        key for key in ("run", "at", "pid", "uid", "readable")
        if key in values and not str(values[key]).strip()
    ]
    missing = sorted(set(absent) | set(blank))
    if missing:
        refuse(
            f"the {side} snapshot is missing {missing}; a snapshot without a run, a timestamp and a "
            "socket observation cannot support a 'wound down' conclusion"
        )
    if values.get("pid") in ("absent", "unknown") or values.get("uid") in ("unknown",):
        refuse(
            f"the {side} snapshot could not identify the process (pid={values.get('pid')}, "
            f"uid={values.get('uid')}); its socket counts describe nothing"
        )
    if values.get("readable") != "yes" or values.get("sockets") == "UNAVAILABLE":
        refuse(
            f"the {side} snapshot could not read the socket tables (readable={values.get('readable')}, "
            f"sockets={values.get('sockets')}); a read failure is not an empty table"
        )
    if values.get("ok") == "no":
        refuse(
            f"the {side} snapshot marked itself unusable (ok=no, collected={values.get('collected')}, "
            f"error={values.get('error', '-')})"
        )

# The pair must belong to **this** run. `RUN_ID` is what the acceptance script passes; when it is not
# given, the two snapshots must at least agree with each other, and the caller has opted out of the
# stronger check by not supplying one.
if expected_run and (before.get("run") != expected_run or settled.get("run") != expected_run):
    refuse(
        f"the snapshots are not this run's ({before.get('run')} / {settled.get('run')} != "
        f"{expected_run})"
    )
if before.get("run") != settled.get("run"):
    refuse(f"the snapshots belong to different runs ({before.get('run')} vs {settled.get('run')})")

# A snapshot older than the window cannot describe a run that has just finished; a stale file would
# otherwise be compared with a fresh one and read as a delta.
now = time.time()
for side, values in (("before", before), ("settled", settled)):
    try:
        age = now - int(values["at"])
    except (KeyError, ValueError):
        refuse(f"the {side} snapshot's timestamp is not an epoch second ({values.get('at')!r})")
    if age > slack:
        refuse(
            f"the {side} snapshot is {age:.0f}s old (limit {slack}s); it does not describe this run"
        )

if before.get("pid") != settled.get("pid"):
    refuse(
        f"process changed ({before.get('pid')} -> {settled.get('pid')}); the wind-down cannot be "
        "compared"
    )
if before.get("uid") != settled.get("uid"):
    refuse(f"app uid changed ({before.get('uid')} -> {settled.get('uid')}); the socket counts are "
           "no longer comparable")

before_states = states(before.get("sockets", ""))
after_states = states(settled.get("sockets", ""))

# What "wound down" means.
#
# Measured on this device (Pixel 5 / A16): after a run, the core parks a handful of sockets in
# CLOSE_WAIT and releases some of them only after ~100 s. Requiring zero within the polling window
# would fail every healthy run, so the test is **growth** against this run's own baseline — a leak
# accumulates, a slow release returns to it.
#
# No allowance is granted to the app's own counts. The browser's keep-alives are charged to the
# browser's uid, not this app's, so an ESTABLISHED growth attributed to this uid is this app's own.
# The previous version allowed +2 "for the browser", and the review measured that accepting a
# 1 -> 3 growth of app sockets.
problems = []
for state, code in (("ESTABLISHED", "01"), ("CLOSE_WAIT", "08"), ("FIN_WAIT2", "05")):
    old = before_states.get(code, 0)
    new = after_states.get(code, 0)
    if new > old:
        problems.append(f"{state} grew {old} -> {new} (limit {old})")

print(f"check: run={before.get('run')} pid={before.get('pid')} uid={before.get('uid')}")
print(f"check: before={before_states} after={after_states}")
if problems:
    for problem in problems:
        print(f"check: {problem}", file=sys.stderr)
    raise SystemExit(1)

# The kernel's own total is a second opinion: the uid filter could miss a socket the core owns under
# a different uid (an isolated process), and only this number would show it.
def sockstat_total(text):
    """`TCP: inuse 40 orphan 0 tw 5 alloc 60 mem 3` -> 40."""
    match = re.search(r"TCP:\s+inuse\s+(\d+)", text or "")
    if match:
        return int(match.group(1))
    match = re.search(r"TCP:\s+(\d+)", text or "")
    return int(match.group(1)) if match else None

old_total = sockstat_total(before.get("sockstat", ""))
new_total = sockstat_total(settled.get("sockstat", ""))
kernel_allowance = 2   # system-wide noise, not this app's connections
if old_total is not None and new_total is not None and new_total > old_total + kernel_allowance:
    print(f"check: kernel TCP inuse grew {old_total} -> {new_total}", file=sys.stderr)
    raise SystemExit(1)
print("check: wound down (no socket state grew beyond this run's baseline)")
PY2
        ;;
    *)
        echo "usage: RUN_ID=<run> $0 <before|settled|after|delta|check> [label]" >&2
        exit 2
        ;;
esac
