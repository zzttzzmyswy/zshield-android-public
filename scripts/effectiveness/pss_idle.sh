#!/usr/bin/env bash
# Idle PSS after the tunnel settles, sampled the way `docs/PERF.md` §14.6 defines it.
#
# Usage:
#   LOCK_OWNER=<task-id> scripts/effectiveness/pss_idle.sh <label> --expect-identity "<dns=… engine=… extras=…>"
#        [--samples N] [--interval S] [--out DIR] [--settle S] [--ready-line PATTERN] [--issue <task-id>]
#        [--expect-identity-from <dir>] [--expect-engine N] [--expect-rules "<block>,<network>"]
#   LOCK_OWNER=<task-id> scripts/effectiveness/pss_idle.sh <label> --diagnostic [...]
#   scripts/effectiveness/pss_idle.sh --identity <dir>          # print a directory's identity
#
# Protocol, and why each step is there:
#
#   1. the target rule content is **declared** (`--expect-identity`, or `--identity-from` to derive it
#      from the artifacts under test) and its format is validated **before any device command runs**.
#      A run without a declaration is only possible as `--diagnostic`, which cannot produce a median;
#   2. the device lock is taken with this run's own owner and **renewed** while the run lasts, so a
#      sample that takes 6 × 60 s does not let its lock expire mid-measurement;
#   3. the app is force-stopped and the tunnel restarted. Every step of that sequence is checked for
#      its **actual exit status**, and the log boundary is verified by reading the buffer back: a
#      `logcat -c` that failed leaves the previous launch's lines in place, and host wall-clock time
#      is not evidence about a device buffer;
#   4. the run waits for **this launch's own** `rules identity:` event. Every log line used as evidence
#      must carry a threadtime pid/tag it can be attributed by, and every identity field must be
#      present and well-formed; a line missing fields, or one whose pid cannot be attributed, is
#      rejected rather than believed. The last event must be a *successful* install whose content
#      identity equals the declared target (`MYS-2825`);
#   5. the app is sent to the background (`input keyevent HOME`), because the debug screen's views and
#      graphics buffers are measurement artefacts, not filtering cost;
#   6. every sample is validated **before and after** the read — same pid, same handle, same
#      generation, same target content — and the `dumpsys meminfo` answer must be a block for exactly
#      this pid and package. A process restart, a rule swap or a foreign meminfo block voids the whole
#      batch: a median over two different processes or rule sets describes neither;
#   7. the batch is validated once more immediately before the median is printed, so a change during
#      the last read cannot slip into a "successful" result;
#   8. the median is taken on the raw kB and converted once, so the printed MiB is exact. An earlier
#      round converted per sample and then averaged the converted numbers, which is how 100.2 MB and
#      99.8 MB were both stated for the same data (`docs/EFFECTIVENESS.md` §13.8).
#
# Nothing is sampled unless the process is demonstrably this launch's, idle, holding the declared rule
# content, and the same one for every sample: a PSS taken during the startup compile, from a
# replacement process, from a foreign meminfo block, or from a rule set nobody asked for is a
# measurement of something else, and reporting one as idle PSS is how a regression hides.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

SERIAL="${SERIAL:-}"
PKG="${PKG:-top.zztweb.zshield}"
LOCK_TTL="${LOCK_TTL:-7200}"      # 2 hours
LOCK_RENEW_EVERY="${LOCK_RENEW_EVERY:-1800}"  # refreshed every 30 minutes during a long run
LOCK_OWNER="${LOCK_OWNER:-}"

#: `--identity <dir>`: print the content identity of the compiled artifacts in `dir` and exit. No
#: device, no lock. This is how a caller derives the expected identity from the very artifacts the
#: run is about, with the same measure the core uses (SHA-256 of the envelope payload), instead of
#: transcribing a number from somewhere.
if [ "${1:-}" = "--identity" ] || [ "${1:-}" = "identity" ]; then
    target="${2:-}"
    if [ -z "$target" ] || [ ! -d "$target" ]; then
        echo "usage: pss_idle.sh --identity <compiled-artifact-dir>" >&2
        exit 2
    fi
    exec python3 - "$target" <<'PY'
import hashlib
import struct
import sys
from pathlib import Path

HEADER = 20
ARTIFACTS = (
    ("dns", "dns.bin", b"ZSDNS\0\0\x01"),
    ("engine", "engine.bin", b"ZSENG\0\0\x01"),
    ("extras", "extras.txt", b"ZSEXT\0\0\x01"),
)
root = Path(sys.argv[1])
fields = []
for name, filename, magic in ARTIFACTS:
    path = root / filename
    if not path.exists():
        fields.append(f"{name}=-")
        continue
    raw = path.read_bytes()
    if len(raw) < HEADER or raw[0:8] != magic:
        sys.exit(f"{path}: not a ZShield {name} artifact ({len(raw)} bytes, magic {raw[0:8]!r})")
    declared = struct.unpack("<I", raw[12:16])[0]
    payload = raw[HEADER:]
    if len(payload) != declared:
        sys.exit(f"{path}: the header declares {declared} payload bytes, the file has {len(payload)}")
    fields.append(f"{name}=sha256:{hashlib.sha256(payload).hexdigest()}:{len(payload)}")
print(" ".join(fields))
PY
fi

LABEL="${1:-run}"
shift || true
SAMPLES=6
INTERVAL=60
OUT="${OUT:-.effectiveness/results}"
SETTLE=90
#: An **extra necessary condition** (MYS-2825): when given, this exact text must appear in one of this
#: launch's own log lines, or the run refuses. It is opt-in because the old default
#: (`hot reload finished: ok=true`) is only printed when a rule *change* triggers a swap, so a cold
#: start could never satisfy it — a default that made every cold start unsatisfiable. Silence is no
#: longer silent either way: an unsatisfied pattern is a refusal, never a warning.
READY_LINE="${READY_LINE:-}"
#: The rule content this run is supposed to measure, as `dns=<token> engine=<token> extras=<token>`
#: (as printed by `--identity <dir>`). Each token is `sha256:<hex>:<bytes>`, or `-` for a component
#: that is not part of the target. **Required** for a formal run: a batch that is not tied to a
#: declared rule set cannot be acceptance evidence, and a warning is not a check.
EXPECT_IDENTITY="${EXPECT_IDENTITY:-}"
EXPECT_IDENTITY_FROM="${EXPECT_IDENTITY_FROM:-}"
#: Explicitly the *other* mode: sample without declaring a target, print no median, and say in the
#: output that the run is not acceptance evidence. It has to be asked for by name — the default must
#: never quietly degrade into it.
DIAGNOSTIC=0
#: Auxiliary checks, kept because they are cheap and catch a truncated artifact: they are **not** an
#: identity (two rule sets can share a length and a rule count — the stage-4 review's counter-example).
EXPECT_ENGINE="${EXPECT_ENGINE:-}"
EXPECT_RULES="${EXPECT_RULES:-}"

while [ $# -gt 0 ]; do
    case "$1" in
        --samples) shift; SAMPLES="${1:-6}" ;;
        --interval) shift; INTERVAL="${1:-60}" ;;
        --out) shift; OUT="${1:-.effectiveness/results}" ;;
        --settle) shift; SETTLE="${1:-90}" ;;
        --ready-line) shift; READY_LINE="${1:-}" ;;
        --expect-identity) shift; EXPECT_IDENTITY="${1:-}" ;;
        --expect-identity=*) EXPECT_IDENTITY="${1#--expect-identity=}" ;;
        --expect-identity-from) shift; EXPECT_IDENTITY_FROM="${1:-}" ;;
        --diagnostic) DIAGNOSTIC=1 ;;
        --expect-engine) shift; EXPECT_ENGINE="${1:-}" ;;
        --expect-rules) shift; EXPECT_RULES="${1:-}" ;;
        --issue) shift; LOCK_OWNER="${1:-}" ;;
        --issue=*) LOCK_OWNER="${1#--issue=}" ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

# ---- the declared target: format validated before any device command ---------------------------
# Everything below runs before the lock is taken and before `adb` is invoked, so a malformed or missing
# declaration costs nothing on the device and can never be "discovered" halfway through a run.
if [ "$DIAGNOSTIC" = 1 ]; then
    if [ -n "$EXPECT_IDENTITY" ] || [ -n "$EXPECT_IDENTITY_FROM" ]; then
        echo "--diagnostic and --expect-identity/--expect-identity-from are mutually exclusive: a" >&2
        echo "diagnostic run declares no target, so it cannot also be held to one." >&2
        exit 2
    fi
fi
if [ -n "$EXPECT_IDENTITY" ] && [ -n "$EXPECT_IDENTITY_FROM" ]; then
    echo "--expect-identity and --expect-identity-from are mutually exclusive" >&2
    exit 2
fi
if [ -n "$EXPECT_IDENTITY_FROM" ]; then
    if [ ! -d "$EXPECT_IDENTITY_FROM" ]; then
        echo "--expect-identity-from $EXPECT_IDENTITY_FROM: not a directory" >&2
        exit 2
    fi
    EXPECT_IDENTITY="$(bash "${BASH_SOURCE[0]}" --identity "$EXPECT_IDENTITY_FROM")" || {
        echo "--expect-identity-from $EXPECT_IDENTITY_FROM: could not compute an identity" >&2
        exit 2
    }
fi
if [ "$DIAGNOSTIC" != 1 ] && [ -z "$EXPECT_IDENTITY" ]; then
    cat >&2 <<'EOF'
pss_idle.sh needs the rule content this run is supposed to measure:
  --expect-identity "dns=sha256:<hex>:<bytes> engine=sha256:<hex>:<bytes> extras=sha256:<hex>:<bytes>"
  --expect-identity-from <compiledDir>     # derive it from the artifacts under test
A batch that is not tied to a declared rule set cannot be acceptance evidence. If you only want a
rough number, ask for that explicitly with --diagnostic — it prints no median and says so.
EOF
    exit 2
fi

#: The three components of the declared target, empty in diagnostic mode.
WANT_DNS=""; WANT_ENGINE=""; WANT_EXTRAS=""
if [ -n "$EXPECT_IDENTITY" ]; then
    parsed="$(python3 - "$EXPECT_IDENTITY" <<'PY'
import re
import sys

TOKEN = re.compile(r"^(?:-|sha256:[0-9a-f]{64}:[0-9]+)$")
fields = {"dns": None, "engine": None, "extras": None}
for token in sys.argv[1].split():
    if "=" not in token:
        sys.exit(f"--expect-identity: {token!r} is not <name>=<value>")
    name, value = token.split("=", 1)
    if name not in fields:
        sys.exit(f"--expect-identity: unknown component {name!r} (expected dns, engine, extras)")
    if not TOKEN.match(value):
        sys.exit(
            f"--expect-identity: {name}={value!r} is not an identity "
            f"(expected '-' or 'sha256:<64 hex>:<bytes>')"
        )
    fields[name] = value
missing = [name for name, value in fields.items() if value is None]
if missing:
    sys.exit("--expect-identity: missing component(s) " + ", ".join(sorted(missing)))
if all(value == "-" for value in fields.values()):
    sys.exit("--expect-identity: every component is '-' — that declares no rule set to measure")
print(fields["dns"], fields["engine"], fields["extras"])
PY
)" || exit 2
    read -r WANT_DNS WANT_ENGINE WANT_EXTRAS <<<"$parsed"
fi

for setting in SAMPLES INTERVAL SETTLE; do
    case "${!setting}" in
        ''|*[!0-9]*) echo "$setting must be a whole number, got '${!setting}'" >&2; exit 2 ;;
    esac
done
if [ "$SAMPLES" -lt 1 ]; then
    echo "--samples must be at least 1" >&2
    exit 2
fi

# Which phone this batch measures, resolved once (explicit `SERIAL` wins, otherwise exactly one
# attached device). Resolved *after* `--identity`, which needs no device at all. There is no default
# address: a measurement labelled with a serial it did not use is worse than a refusal.
# shellcheck source=device-serial.sh
. scripts/effectiveness/device-serial.sh
require_serial
SERIAL="$RESOLVED_SERIAL"
export SERIAL

d()   { adb -s "$SERIAL" "$@"; }
sh_() { adb -s "$SERIAL" shell "$@"; }

mkdir -p "$OUT"
FILE="$OUT/pss-${LABEL}.txt"
#: The raw device output every decision below was made from, kept next to the result so a reader can
#: re-derive it instead of trusting the summary.
RAW_DIR="$OUT/pss-${LABEL}.raw"
mkdir -p "$RAW_DIR"

log() { printf '%s\n' "$*" | tee -a "$FILE"; }
fail() { log "FAIL: $*"; exit 1; }

: >"$FILE"
log "# idle PSS — label=$LABEL at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "# serial=$SERIAL package=$PKG samples=$SAMPLES interval=${INTERVAL}s owner=${LOCK_OWNER:-unset}"
log "# raw device output for every decision: $RAW_DIR"

# ---- the device lock: one shared implementation ----------------------------------------------
# The same library `condition.sh` and `tunnel_acceptance.sh` use, so "held", "expired" and "mine" mean
# one thing across the tools. The owner is required; the token is this process's.
# shellcheck source=device-lock.sh
. scripts/effectiveness/device-lock.sh
LOCK_OWNER="${LOCK_OWNER:-}"
if [ -z "$LOCK_OWNER" ]; then
    cat >&2 <<'EOF'
pss_idle.sh needs the owner of this measurement:
  LOCK_OWNER=MYS-2817 scripts/effectiveness/pss_idle.sh idle --expect-identity-from <dir>
  or  scripts/effectiveness/pss_idle.sh idle --issue MYS-2817 --expect-identity-from <dir>
There is deliberately no default: a default owner reads as "mine" to every run and disables the lock.
EOF
    exit 1
fi
if ! lock_take; then
    log "# device lock unavailable; refusing to measure"
    exit 1
fi
lock_start_renewer

cleanup() {
    local code=$?
    # A `return` from an EXIT trap cannot change the shell's exit status — the status it was already
    # going to exit with wins — so a handler that noticed a problem and returned 1 still exited 0.
    # The final status is accumulated explicitly and passed to `exit`, and the trap is disarmed first
    # so `exit` here cannot re-enter it.
    trap - EXIT INT TERM HUP
    log "# cleanup at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    # A renewer child that survived is a leaked process nobody can attribute, so its cleanup is part
    # of the exit status rather than a line in a log.
    lock_stop_renewer || code=$(( code == 0 ? 1 : code ))
    lock_release >/dev/null 2>&1 || true
    exit "$code"
}
trap cleanup EXIT
# A signal runs the same cleanup and is non-zero: `exit 130` from the signal trap reaches the EXIT
# trap once, with the status the caller needs.
for _signal in INT TERM HUP; do
    # shellcheck disable=SC2064  # the trap is meant to see this process's own state
    trap "exit 130" "$_signal"
done

read_pid() { sh_ "pidof $PKG" 2>/dev/null | tr -d '\r' | cut -d' ' -f1; }
read_uid() {
    sh_ "dumpsys package $PKG 2>/dev/null | grep -oE 'appId=[0-9]+' | head -1 | cut -d= -f2" \
        | tr -d '\r'
}
#: The lines this run treats as possible evidence. `-v threadtime` is explicit so the pid and tag are
#: in fixed columns that can be parsed — a line that cannot be attributed is not evidence.
LOG_GREP='engine loaded in|engine started|rules reloaded|rules identity:|hot reload finished|tunnel stack up'

# ---- 1. cold start, with every step's exit status checked -------------------------------------
# The tunnel is toggled *before* the app is killed, so the toggle reaches a live receiver. Toggling a
# force-stopped app is a no-op: the broadcast has no process to run in, and the run then waits for a
# tunnel that can never come up. That is what made an earlier version report `tunnel: DOWN`.
log "## stopping the tunnel and the app"
sh_ "am broadcast -a $PKG.action.DEBUG_TOGGLE_VPN -n $PKG/.filters.DebugCommandReceiver" \
    >"$RAW_DIR/toggle-off.txt" 2>&1 || true
sleep 4

# `am force-stop` is a necessary command: if it fails, the launch below may well resume the *previous*
# process, whose log lines and whose PSS are not this run's. So its status is checked, and then the
# consequence is checked too — the package must really have no pid.
force_stop_out="$(sh_ "am force-stop $PKG" 2>&1)"; force_stop_rc=$?
printf '%s\n' "$force_stop_out" >"$RAW_DIR/force-stop.txt"
[ "$force_stop_rc" -eq 0 ] \
    || fail "am force-stop $PKG exited ${force_stop_rc}: ${force_stop_out} — the previous process may still be running, so nothing after this point describes a fresh launch"
gone=0
for _ in $(seq 1 10); do
    if [ -z "$(read_pid)" ]; then gone=1; break; fi
    sleep 1
done
[ "$gone" = 1 ] || fail "am force-stop reported success but $PKG still has a pid ($(read_pid)); refusing to measure a process this run did not start"

# The log boundary is **verified**, not assumed. `logcat -c` can fail (a busy buffer, a dropped
# transport), and a failed clear leaves the previous launch's lines in place — where a stale
# `rules identity:` line from the *same* pid would be indistinguishable from a fresh one. Host
# wall-clock time says nothing about a device buffer, so what is recorded is the result of reading the
# buffer back and finding none of this run's markers in it.
log "## establishing the log start boundary"
clear_out="$(sh_ "logcat -c" 2>&1)"; clear_rc=$?
printf '%s\n' "$clear_out" >"$RAW_DIR/logcat-clear.txt"
[ "$clear_rc" -eq 0 ] \
    || fail "logcat -c exited ${clear_rc}: ${clear_out} — the buffer still holds the previous launch's lines, so no line read afterwards can be attributed to this launch"
boundary_ok=0
for _ in $(seq 1 5); do
    leftover="$(sh_ "logcat -d -b all -v threadtime 2>/dev/null | grep -cE '$LOG_GREP'" 2>/dev/null | tr -d '\r')"
    case "$leftover" in ''|*[!0-9]*) leftover=-1 ;; esac
    if [ "$leftover" -eq 0 ]; then boundary_ok=1; break; fi
    sleep 1
done
sh_ "logcat -d -b all -v threadtime 2>/dev/null" >"$RAW_DIR/logcat-at-boundary.txt" 2>&1 || true
if [ "$boundary_ok" != 1 ]; then
    fail "logcat -c reported success but the buffer still holds ${leftover} line(s) this run would treat as evidence; a start boundary that cannot be verified is not a boundary"
fi
BOUNDARY_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "# start boundary verified at $BOUNDARY_AT: logcat -c exited 0 and the buffer then held 0 evidence lines"

# The launcher activity is `.ui.MainActivity`; `.MainActivity` does not exist, and `am start` reports
# its failure on stderr while exiting 0 — so its status *and* its text are checked.
start_output="$(sh_ "am start -W -n $PKG/.ui.MainActivity" 2>&1)"; start_rc=$?
printf '%s\n' "$start_output" >"$RAW_DIR/am-start.txt"
[ "$start_rc" -eq 0 ] || fail "am start exited ${start_rc}: ${start_output}"
if printf '%s' "$start_output" | grep -qiE "Error|does not exist"; then
    fail "could not start $PKG/.ui.MainActivity: $start_output"
fi
sleep 10
launched_pid="$(read_pid)"
[ -n "$launched_pid" ] || fail "am start reported success but $PKG has no pid; there is no process to measure"
sh_ "am broadcast -a $PKG.action.DEBUG_TOGGLE_VPN -n $PKG/.filters.DebugCommandReceiver" \
    >"$RAW_DIR/toggle-on.txt" 2>&1 || true

# ---- 2. the process this run measures --------------------------------------------------------
log "## waiting for the tunnel"
up=0
for _ in $(seq 1 45); do
    if sh_ "dumpsys connectivity" 2>/dev/null | grep -q "IS_VPN"; then
        up=1
        break
    fi
    sleep 2
done
log "tunnel: $([ "$up" = 1 ] && echo up || echo DOWN)"
[ "$up" = 1 ] || fail "the tunnel did not come up; no idle PSS to measure"

MEASURED_PID="$launched_pid"
MEASURED_UID="$(read_uid)"
if [ -z "$MEASURED_PID" ] || [ -z "$MEASURED_UID" ]; then
    fail "could not read the pid/uid of $PKG (pid=${MEASURED_PID:-absent} uid=${MEASURED_UID:-unknown})"
fi
log "# measuring pid=$MEASURED_PID uid=$MEASURED_UID"

snapshot_log() {
    sh_ "logcat -d -b all -v threadtime 2>/dev/null | grep -E '$LOG_GREP' | tail -200" 2>/dev/null \
        | tr -d '\r'
}

# Parse a log snapshot into the facts the run decides on.
#
# Attribution and completeness are both strict, because each lenient rule is a demonstrated false pass:
#
#   * a line is used only when its threadtime pid/tag can be read and the pid is **this run's**. The
#     previous revision also accepted lines with no pid column on the grounds that the buffer had been
#     cleared — but the clear is now verified instead, and a bare line is simply unattributable, so it
#     is refused (`MYS-2825` rework). Lines from other pids are counted as foreign.
#   * a `rules identity:` line names its own pid in `pid=`. A column and a payload that disagree make
#     the line contradictory; it is refused, not resolved in either direction.
#   * every field of a `rules identity:` line must be present and well-formed. `event=start ok=true`
#     on its own used to be accepted, which left generation/handle/identity as `none` while still
#     letting a run proceed.
#
# Output is `key=value` lines so the caller can act on each fact instead of re-grepping.
analyze_log() {
    # $1 = snapshot file, $2 = the pid this run measures, $3 = optional ready-line pattern
    python3 - "$1" "$2" "${3:-}" <<'PY'
import re
import sys

snapshot, measured, ready_line = sys.argv[1], int(sys.argv[2]), sys.argv[3]
THREADTIME = re.compile(
    r"^\d\d-\d\d\s+\d\d:\d\d:\d\d\.\d+\s+(\d+)\s+(\d+)\s+[VDIWEFA]\s+([^:]*):\s?(.*)$"
)
OUR_TAGS = {"ZShieldCore", "ZShield"}
IDENTITY_TOKEN = re.compile(r"^(?:-|sha256:[0-9a-f]{64}:[0-9]+)$")
IDENTITY_FIELDS = ("event", "ok", "handle", "generation", "pid", "dns", "engine", "extras")

own_events = []       # [(index, fields)] events attributed to this launch and well-formed
malformed = []        # [(index, why)] identity lines that could not be used, with the reason
failures = []         # [(index, description)] failure signals attributed to this launch
foreign = 0
unattributed = 0
ready_hits = 0
tunnel_ready = 0

for index, raw in enumerate(open(snapshot, encoding="utf-8", errors="replace")):
    line = raw.rstrip("\n").rstrip("\r")
    match = THREADTIME.match(line)
    if not match:
        # No pid column: this line cannot be attributed to a process, so it is not evidence. Counted
        # separately from foreign so a reader can see the difference in kind.
        if re.match(r"^[VDIWEFA]\s+[^:]*:", line):
            unattributed += 1
        continue
    pid, tag, message = int(match.group(1)), match.group(3).strip(), match.group(4)
    if tag not in OUR_TAGS:
        continue
    if pid != measured:
        foreign += 1
        continue

    if message.startswith("rules identity:"):
        fields = {}
        for token in message.split()[2:]:
            if "=" in token:
                key, value = token.split("=", 1)
                fields[key] = value
        missing = [name for name in IDENTITY_FIELDS if name not in fields]
        if missing:
            malformed.append((index, "missing field(s) " + ",".join(missing)))
            continue
        if fields["event"] not in ("start", "swap"):
            malformed.append((index, f"event={fields['event']!r} is not start/swap"))
            continue
        if fields["ok"] not in ("true", "false"):
            malformed.append((index, f"ok={fields['ok']!r} is not true/false"))
            continue
        if not fields["handle"].isdigit() or not fields["generation"].isdigit():
            malformed.append((index, "handle/generation are not whole numbers"))
            continue
        if int(fields["handle"]) < 1 or int(fields["generation"]) < 1:
            malformed.append((index, "handle/generation are not positive"))
            continue
        if not fields["pid"].isdigit():
            malformed.append((index, f"pid={fields['pid']!r} is not a number"))
            continue
        if int(fields["pid"]) != measured:
            # A line that names another process in its payload, whatever its column says.
            foreign += 1
            continue
        bad = [name for name in ("dns", "engine", "extras")
               if not IDENTITY_TOKEN.match(fields[name])]
        if bad:
            malformed.append((index, "malformed identity in " + ",".join(bad)))
            continue
        own_events.append((index, fields))
    elif message.startswith("hot reload finished:"):
        if "ok=false" in message:
            failures.append((index, "hot reload finished: ok=false"))
    elif "engine started" in message or "tunnel stack up" in message:
        tunnel_ready = 1
    if ready_line and ready_line in message:
        ready_hits += 1

last_success_index = -1
for index, fields in own_events:
    if fields.get("ok") == "true":
        last_success_index = index

failures_after = [entry for entry in failures if entry[0] > last_success_index]
failed_events_after = [
    (index, fields) for index, fields in own_events
    if index > last_success_index and fields.get("ok") != "true"
]
# A malformed line *after* the last good install means the engine said something this parser cannot
# read about the state it is in; that is unknown, and unknown is not a pass.
malformed_after = [entry for entry in malformed if entry[0] > last_success_index]

last = own_events[-1][1] if own_events else {}
print(f"events={len(own_events)}")
print(f"last_event={last.get('event', 'none')}")
print(f"last_ok={last.get('ok', 'unknown')}")
print(f"last_generation={last.get('generation', 'none')}")
print(f"last_handle={last.get('handle', 'none')}")
print(f"last_dns={last.get('dns', 'none')}")
print(f"last_engine={last.get('engine', 'none')}")
print(f"last_extras={last.get('extras', 'none')}")
print(f"failures_after={len(failures_after) + len(failed_events_after)}")
reason = ""
if failures_after:
    reason = failures_after[0][1]
elif failed_events_after:
    fields = failed_events_after[0][1]
    reason = f"rules identity event={fields.get('event', '?')} ok=false {fields.get('reason', '')}".strip()
print(f"failure_reason={reason.replace(' ', '_') or '-'}")
print(f"foreign={foreign}")
print(f"unattributed={unattributed}")
print(f"malformed={len(malformed)}")
print(f"malformed_after={len(malformed_after)}")
print(f"malformed_reason={(malformed_after[0][1].replace(' ', '_') if malformed_after else (malformed[0][1].replace(' ', '_') if malformed else '-'))}")
print(f"ready_hits={ready_hits}")
print(f"tunnel_ready={tunnel_ready}")
PY
}

#: Facts from the most recent analysis, read with `fact <key>`.
FACTS=""
refresh_facts() {
    local snapshot
    snapshot="$(mktemp "${TMPDIR:-/tmp}/pss-log.XXXXXX")"
    snapshot_log >"$snapshot"
    cp "$snapshot" "$RAW_DIR/last-logcat.txt" 2>/dev/null || true
    FACTS="$(analyze_log "$snapshot" "$MEASURED_PID" "$READY_LINE")"
    rm -f "$snapshot"
}
fact() {
    printf '%s\n' "$FACTS" | sed -n "s/^$1=//p" | head -1
}

log "## waiting for this launch's successful rule install"
# What "settled" has to mean (MYS-2825)
# -------------------------------------
# The previous revision settled on a conjunction of `engine loaded in`, `engine started` and a rule
# count, and let the caller pin *the artifact's byte size* as the rule-set identity on a cached start.
# The stage-4 review rejected that with a counter-example that needs no device: two rule sets of the
# same length and the same rule count have the same numbers and different rules, so neither number can
# say which rules were in force. What replaced it is an observation, not an inference: the core prints
# one `rules identity:` line per install, carrying the SHA-256 of each artifact's payload as it was
# loaded (`core/src/rules_identity.rs`).
#
# A formal run requires all of:
#
#   1. at least one **well-formed** `rules identity:` event attributed to this launch's pid;
#   2. the last such event is `ok=true` — a failed load or a failed swap leaves no successful
#      generation, so there is nothing to sample;
#   3. no failure signal and no malformed event after that one;
#   4. `engine started` / `tunnel stack up` — the tunnel can carry requests at all;
#   5. the declared target matches every component (formal run only);
#   6. when the caller passed `--ready-line`, that text appears in one of this launch's own lines.
settled=0
for _ in $(seq 1 "$SETTLE"); do
    refresh_facts
    ready_ok=1
    if [ -n "$READY_LINE" ] && [ "$(fact ready_hits)" = 0 ]; then
        ready_ok=0
    fi
    if [ "$(fact events)" -gt 0 ] && [ "$(fact last_ok)" = true ] \
        && [ "$(fact failures_after)" -eq 0 ] && [ "$(fact malformed_after)" -eq 0 ] \
        && [ "$(fact tunnel_ready)" = 1 ] && [ "$ready_ok" = 1 ]; then
        settled=1
        break
    fi
    sleep 1
done

# Every refusal names the fact that was missing, because "not settled" sends a reader to the engine and
# the tunnel when the real gap is usually one specific observation.
if [ "$settled" != 1 ]; then
    if [ -n "$READY_LINE" ] && [ "$(fact ready_hits)" = 0 ]; then
        fail "this run requires the extra readiness line '$READY_LINE' but no line from this launch printed it; refusing to sample a launch that never reached the state it was required to reach"
    fi
    if [ "$(fact events)" -eq 0 ]; then
        if [ "$(fact malformed)" -gt 0 ]; then
            fail "within ${SETTLE}s the only 'rules identity:' line(s) from pid ${MEASURED_PID} were unusable ($(fact malformed_reason)); a line whose fields cannot be read does not name a rule set, so the effective content is unknown"
        fi
        if [ "$(fact unattributed)" -gt 0 ]; then
            fail "within ${SETTLE}s no attributable 'rules identity:' event came from pid ${MEASURED_PID}; $(fact unattributed) line(s) in the buffer carried no pid column and cannot be attributed to any process"
        fi
        fail "within ${SETTLE}s no 'rules identity:' event came from the measured pid ${MEASURED_PID} ($(fact foreign) line(s) in the buffer belong to other processes, if any). A readiness line from another process says nothing about this one"
    fi
    if [ "$(fact malformed_after)" -ne 0 ]; then
        fail "an unusable 'rules identity:' line followed the last good install ($(fact malformed_reason)); the rule set in force after it is unknown"
    fi
    if [ "$(fact failures_after)" -ne 0 ]; then
        fail "the last rule install of this launch did not succeed ($(fact failure_reason)): the rule set in force is a mixture this run did not declare, so it will not be measured"
    fi
    if [ "$(fact last_ok)" != true ]; then
        fail "this launch's last rule install reported ok=$(fact last_ok); there is no successful generation to sample"
    fi
    fail "within ${SETTLE}s this launch did not report both a successful rule install and a running tunnel ('engine started' / 'tunnel stack up'); refusing to sample"
fi

PINNED_GENERATION="$(fact last_generation)"
PINNED_HANDLE="$(fact last_handle)"
PINNED_DNS="$(fact last_dns)"
PINNED_ENGINE="$(fact last_engine)"
PINNED_EXTRAS="$(fact last_extras)"
log "settled: rules identity event=$(fact last_event) ok=true handle=$PINNED_HANDLE generation=$PINNED_GENERATION"
log "settled: engine started (tunnel can carry requests)"
log "# effective rule content: dns=$PINNED_DNS engine=$PINNED_ENGINE extras=$PINNED_EXTRAS"
if [ "$(fact foreign)" -gt 0 ]; then
    log "# note: $(fact foreign) line(s) in the buffer belong to other processes and were ignored"
fi

# The declared target must be the content the live engine actually holds.
if [ "$DIAGNOSTIC" != 1 ]; then
    if [ "$PINNED_DNS" != "$WANT_DNS" ] || [ "$PINNED_ENGINE" != "$WANT_ENGINE" ] \
        || [ "$PINNED_EXTRAS" != "$WANT_EXTRAS" ]; then
        fail "the live rule content is dns=$PINNED_DNS engine=$PINNED_ENGINE extras=$PINNED_EXTRAS but this run expects dns=$WANT_DNS engine=$WANT_ENGINE extras=$WANT_EXTRAS; the measurement would describe a different rule set (a byte count or a rule count cannot tell these apart)"
    fi
    log "verified: live rule content is the declared target"
else
    log "# diagnostic mode: no target declared, so this run produces no acceptance median"
fi

# Auxiliary cross-checks. They cannot establish identity — that is the point of the lines above — but a
# truncated artifact or a differently-sized engine is worth catching before six minutes of sampling.
if [ -n "$EXPECT_ENGINE" ] && [ "$PINNED_ENGINE" != "-" ]; then
    actual_bytes="${PINNED_ENGINE##*:}"
    if [ "$actual_bytes" != "$EXPECT_ENGINE" ]; then
        fail "the live engine loaded ${actual_bytes:-unknown} B of rules but this run expects ${EXPECT_ENGINE} B; the measurement would describe a different rule set"
    fi
    log "verified (auxiliary): engine artifact is ${EXPECT_ENGINE} B"
fi
if [ -n "$EXPECT_RULES" ]; then
    snapshot_log | grep -qE 'rules reloaded:' || fail "this run expects ${EXPECT_RULES} block/network rules but the launch printed no 'rules reloaded' line, so the live rule set cannot be cross-checked from this launch"
    reload="$(snapshot_log | grep -E 'rules reloaded:' | tail -1)"
    want_block="${EXPECT_RULES%%,*}"
    want_network="${EXPECT_RULES##*,}"
    got_block="$(printf '%s' "$reload" | grep -oE 'rules reloaded: [0-9]+ block' | grep -oE '[0-9]+')"
    got_network="$(printf '%s' "$reload" | grep -oE '[0-9]+ network-only' | grep -oE '[0-9]+')"
    if [ "$got_block" != "$want_block" ] || [ "$got_network" != "$want_network" ]; then
        fail "the live engine holds ${got_block:-?} block / ${got_network:-?} network rules but this run expects ${want_block} / ${want_network}; the measurement would describe a different rule set"
    fi
    log "verified (auxiliary): live rule set is the expected ${want_block} block / ${want_network} network"
fi
sleep 10

# ---- 3. background ---------------------------------------------------------------------------
log "## sending the app to the background"
sh_ "input keyevent KEYCODE_HOME" >/dev/null 2>&1
sleep 5

# ---- 4. the state a sample must be taken in ---------------------------------------------------
#: Set by `verify_state` when it refuses, so the caller can say what changed instead of "failed".
VOID_REASON=""
# Check that this instant still describes one process running the declared rule set: same pid, same
# handle, same generation, same content, no failure after readiness. Called before and after every
# `dumpsys meminfo`, and again before the median is printed.
verify_state() {
    local where="$1" pid gen handle dns eng ext
    VOID_REASON=""
    pid="$(read_pid)"
    if [ -z "$pid" ] || [ "$pid" != "$MEASURED_PID" ]; then
        VOID_REASON="the measured process changed from ${MEASURED_PID} to ${pid:-absent} (${where})"
        return 1
    fi
    refresh_facts
    gen="$(fact last_generation)"; handle="$(fact last_handle)"
    dns="$(fact last_dns)"; eng="$(fact last_engine)"; ext="$(fact last_extras)"
    if [ "$gen" != "$PINNED_GENERATION" ] || [ "$handle" != "$PINNED_HANDLE" ]; then
        VOID_REASON="the rule generation changed from ${PINNED_GENERATION}/handle ${PINNED_HANDLE} to ${gen}/handle ${handle} (${where})"
        return 1
    fi
    if [ "$(fact malformed_after)" -ne 0 ]; then
        VOID_REASON="an unusable 'rules identity:' line appeared after the pinned install ($(fact malformed_reason), ${where})"
        return 1
    fi
    if [ "$(fact failures_after)" -ne 0 ]; then
        VOID_REASON="a rule install failed after the pinned one ($(fact failure_reason), ${where})"
        return 1
    fi
    if [ "$DIAGNOSTIC" != 1 ] \
        && { [ "$dns" != "$WANT_DNS" ] || [ "$eng" != "$WANT_ENGINE" ] || [ "$ext" != "$WANT_EXTRAS" ]; }; then
        VOID_REASON="the rule content in force is no longer the declared target (dns=$dns engine=$eng extras=$ext, ${where})"
        return 1
    fi
    return 0
}

# Parse a `dumpsys meminfo` answer, requiring it to belong to exactly the measured process.
#
# `dumpsys meminfo <pkg>` answers for the package, and an earlier revision took the first `TOTAL PSS:`
# it found without reading the block header — so a `MEMINFO in pid 9999` answer was recorded as a
# sample of pid 4242. The header is the attribution, so it is required, unique, and must agree.
parse_meminfo() {
    # $1 = raw dump file, $2 = expected pid, $3 = expected package
    python3 - "$1" "$2" "$3" <<'PY'
import re
import sys

raw = open(sys.argv[1], encoding="utf-8", errors="replace").read()
want_pid, want_package = int(sys.argv[2]), sys.argv[3]
headers = re.findall(r"\*\* MEMINFO in pid (\d+) \[([^\]]+)\] \*\*", raw)
if not headers:
    sys.exit("the answer carries no '** MEMINFO in pid N [package] **' header, so it cannot be attributed to a process")
if len(headers) != 1:
    sys.exit(f"the answer carries {len(headers)} MEMINFO headers, so it covers more than one process")
pid, package = headers[0]
if int(pid) != want_pid:
    sys.exit(f"the meminfo block is for pid {pid}, but this run measures pid {want_pid}")
# The header's bracketed label is the process name. For this app that is the package itself (it
# declares no `android:process`), but a `pkg:suffix` process would still be this app's, so both are
# accepted and anything else is refused: an unrelated block is the failure mode being excluded.
if package != want_package and not package.startswith(want_package + ":"):
    sys.exit(f"the meminfo block is for process {package!r}, which is not {want_package!r}")
totals = re.findall(r"TOTAL PSS:\s+(\d+)", raw)
if len(totals) != 1:
    sys.exit(f"the block carries {len(totals)} 'TOTAL PSS' values; exactly one is required")
if not totals[0].isdigit():
    sys.exit("the TOTAL PSS value is not a number")
java = re.search(r"Java Heap:\s+(\d+)", raw)
native = re.search(r"Native Heap:\s+(\d+)", raw)
print(totals[0], java.group(1) if java else "?", native.group(1) if native else "?")
PY
}

# ---- 5. samples ------------------------------------------------------------------------------
log "## samples (raw dumpsys kB)"
log "# index	elapsed_s	total_pss_kb	java_kb	native_kb	pid	generation	handle"
started=$(date +%s)
void() {
    # A voided batch is not a short batch: the samples either side of the change describe different
    # processes or different rule sets, and a median over them is how a regression hides. No median is
    # printed, and the reason is in the result file next to the rows that were collected.
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$(( $(date +%s) - started ))" VOID ? ? \
        "${2:-absent}" "${3:-?}" "${4:-?}" | tee -a "$FILE"
    cp "${RAW_DIR}/last-logcat.txt" "${RAW_DIR}/logcat-at-void.txt" 2>/dev/null || true
    log "# raw logcat for this decision: ${RAW_DIR}/logcat-at-void.txt"
    fail "batch voided — ${VOID_REASON}; no median is produced, because the samples are not evidence for one process and one rule set"
}

for index in $(seq 1 "$SAMPLES"); do
    if [ "$index" -gt 1 ]; then
        sleep "$INTERVAL"
        # A 6 × 60 s run must not let its own lock expire — and a renewal that is refused means the
        # phone now belongs to another task, so the remaining samples would describe a device this run
        # no longer owns. Stop rather than keep writing into somebody else's measurement.
        if ! lock_renew; then
            log "# device lock lost during the run; stopping instead of sampling a device this run no longer holds"
            fail "the device lock was lost mid-run"
        fi
    fi
    # Before the read.
    if ! verify_state "before sample ${index}"; then
        void "$index" "$(read_pid)" "$PINNED_GENERATION" "$PINNED_HANDLE"
    fi

    raw_meminfo="${RAW_DIR}/meminfo-${index}.txt"
    # The status that matters is `adb`'s, not `tr`'s — a pipeline reports only its last command — so the
    # first element of PIPESTATUS is what is checked.
    sh_ "dumpsys meminfo $MEASURED_PID" 2>"${RAW_DIR}/meminfo-${index}.stderr" \
        | tr -d '\r' >"$raw_meminfo"
    meminfo_rc="${PIPESTATUS[0]}"
    if [ "$meminfo_rc" -ne 0 ]; then
        VOID_REASON="dumpsys meminfo exited ${meminfo_rc} (sample ${index})"
        void "$index" "$MEASURED_PID" "$PINNED_GENERATION" "$PINNED_HANDLE"
    fi
    meminfo_err="${RAW_DIR}/meminfo-${index}.err"
    if ! parsed="$(parse_meminfo "$raw_meminfo" "$MEASURED_PID" "$PKG" 2>"$meminfo_err")"; then
        VOID_REASON="the meminfo answer at sample ${index} does not belong to pid ${MEASURED_PID} of ${PKG} ($(head -1 "$meminfo_err")); raw answer kept at ${raw_meminfo}"
        void "$index" "$MEASURED_PID" "$PINNED_GENERATION" "$PINNED_HANDLE"
    fi
    read -r total java_heap native_heap <<<"$parsed"

    # After the read: a swap or a restart during `dumpsys` means this number describes neither state.
    if ! verify_state "after sample ${index}"; then
        void "$index" "$(read_pid)" "$PINNED_GENERATION" "$PINNED_HANDLE"
    fi

    elapsed=$(( $(date +%s) - started ))
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$index" "$elapsed" "$total" "$java_heap" \
        "$native_heap" "$MEASURED_PID" "$PINNED_GENERATION" "$PINNED_HANDLE" | tee -a "$FILE"
done

# Every sample must be a real number from the measured process. A missing `TOTAL PSS:` line means
# `dumpsys` did not answer for the package — a dead process, a renamed package, a transport hiccup —
# and a different pid means the run outlived the process it set out to measure. Taking the median of
# the survivors would silently measure fewer than the protocol requires.
valid="$(awk -F'\t' '!/^#/ && NF>=6 && $3 ~ /^[0-9]+$/ {n++} END {print n+0}' "$FILE")"
if [ "$valid" -ne "$SAMPLES" ]; then
    fail "only ${valid} of ${SAMPLES} sample(s) carried a PSS reading from the measured process; the run is not evidence"
fi
# Every row must name the same process, generation and handle. A row that does not is a sample from a
# different state that somehow survived the per-sample checks, and averaging it in would be wrong.
inconsistent="$(awk -F'\t' -v want_pid="$MEASURED_PID" -v want_gen="$PINNED_GENERATION" \
    -v want_handle="$PINNED_HANDLE" '
    !/^#/ && NF>=8 && $3 ~ /^[0-9]+$/ && ($6 != want_pid || $7 != want_gen || $8 != want_handle) {n++}
    END {print n+0}' "$FILE")"
if [ "$inconsistent" -ne 0 ]; then
    fail "${inconsistent} sample row(s) name a pid/generation/handle other than ${MEASURED_PID}/${PINNED_GENERATION}/${PINNED_HANDLE}; the batch is not one measurement"
fi

# ---- 6. final validation, immediately before the median ---------------------------------------
# The last check is the one the previous revision was missing: it validated the state before each
# `dumpsys meminfo` and then summarised unconditionally, so a swap during the final read still printed
# a "successful" median for the old generation.
if ! verify_state "after the last sample, before the median"; then
    void "$SAMPLES" "$(read_pid)" "$PINNED_GENERATION" "$PINNED_HANDLE"
fi
log "# final check: pid=${MEASURED_PID} handle=${PINNED_HANDLE} generation=${PINNED_GENERATION} content unchanged"

# ---- summary ---------------------------------------------------------------------------------
if [ "$DIAGNOSTIC" = 1 ]; then
    python3 - "$FILE" "$LABEL" <<'PY'
import statistics
import sys
from pathlib import Path

path, label = Path(sys.argv[1]), sys.argv[2]
values = []
for line in path.read_text(encoding="utf-8").splitlines():
    if line.startswith("#") or not line.strip():
        continue
    parts = line.split("\t")
    if len(parts) >= 3 and parts[2].isdigit():
        values.append(int(parts[2]))
if not values:
    print(f"## {label}: no usable sample")
    sys.exit(1)
median = statistics.median(values)
exact = f"{int(median)}" if float(median).is_integer() else f"{median:.1f}"
print(f"## diagnostic {label}: {len(values)} sample(s) {values}")
# Deliberately **not** a `## median` line: a diagnostic run declared no target rule set, so its number
# must not be quotable as an acceptance figure by a script that looks for that line.
print(f"## diagnostic only: centre {exact} kB = {median / 1024:.9f} MiB, NOT acceptance evidence "
      f"(no target rule set was declared)")
PY
    log "# note: diagnostic mode — the summary above is marked 'diagnostic', never 'median', so a script that looks for the acceptance line will not match it."
    exit 0
fi

python3 - "$FILE" "$LABEL" <<'PY'
import statistics
import sys
from pathlib import Path

path, label = Path(sys.argv[1]), sys.argv[2]
values = []
for line in path.read_text(encoding="utf-8").splitlines():
    if line.startswith("#") or not line.strip():
        continue
    parts = line.split("\t")
    if len(parts) >= 3 and parts[2].isdigit():
        values.append(int(parts[2]))

if not values:
    print(f"## {label}: no usable sample")
    sys.exit(1)

median = statistics.median(values)
# An even sample count gives a **half-step** median (98 810.5 kB here). Printing it with `:.0f`
# rounded it to 98 811 and then divided, which is why the delivered figure (96.5 MiB) disagreed with
# the same data recomputed at full precision (96.49462890625 MiB). The median is a rational number of
# kB, so it is printed exactly, and the MiB figure is derived from it, never from a rounded kB.
print(f"## {label}: {len(values)} sample(s) {values}")
if float(median).is_integer():
    exact = f"{int(median)}"
else:
    exact = f"{median:.1f}"
print(f"## median {exact} kB = {median / 1024:.9f} MiB "
      f"(min {min(values)} kB, max {max(values)} kB)")
PY

log "# note: the median is taken on the raw kB and converted once, so the printed MiB is exact."
log "# note: every sample above came from pid=$MEASURED_PID uid=$MEASURED_UID, while rule generation"
log "#       $PINNED_GENERATION (handle $PINNED_HANDLE) was in force, after the verified start"
log "#       boundary at $BOUNDARY_AT."
log "# note: raw device output for every decision: $RAW_DIR"
