#!/usr/bin/env bash
# The device lock, as a sourced library so every tool shares one implementation.
#
# The lock other tasks already observe
# ------------------------------------
# `AGENTS.md` fixes the device lock as the **file** `/data/local/tmp/zshield-device.lock`, whose first
# line is `<issue> <ISO time>`, and other scripts in this repository (`scripts/device-test-m4a.sh`,
# `docs/TESTING.md` §11.2/§13.2) write and read exactly that. So the canonical resource is that file:
#
#     MYS-2820 2026-11-12T21:55:27Z
#
# The previous revision kept its lock in `/data/local/tmp/zshield-device.lock.d`, a directory nothing
# else knew about. The consequence was measured by the stage-3 safety probe: with a live canonical lock
# naming another issue, `lock_take` still exited 0 and the phone was used by two runs at once. A lock
# nobody else can see is not a lock. Auxiliary state (this run's token, the epoch stamps) lives in
# `…lock.state/`, and the mutual exclusion described below in `…lock.guard/`; both are additions *beside*
# the canonical file, never a replacement for it.
#
# One critical section for every read/verify/modify
# ------------------------------------------------
# Taking over an expired lock used to be "read the old stamp, then `mv` the directory away". Two
# runners could both read the same stale stamp; the loser's `mv` then removed the *winner's fresh lock*,
# and both exited 0 (also measured by the probe). Reading and modifying a shared resource is one
# decision and must be one critical section.
#
# The critical section is a `mkdir` of `…lock.guard/` — atomic on POSIX filesystems — held for the whole
# of first acquisition, stale takeover, renewal and release, and released by a `trap … 0` on the device.
# There is **no waiting**: a guard that cannot be created is an immediate refusal, because an unbounded
# wait inside a measurement script is a hang nobody can attribute. A guard left behind by a crash cannot
# be attributed to anyone, so it is reported and refused, never stolen — the operator removes it by hand
# (the refusal prints the exact path).
#
# Every device answer is explicit
# -------------------------------
# Each operation is one device-side script whose **last line is the verdict** (`TAKEN`, `HELD <meta>`,
# `RENEWED`, `RELEASED`, `NOTMINE`, `LOST`, `GUARD_BUSY`, `WRITE_FAILED`, `VERIFY_FAILED`,
# `HELD_UNKNOWN_FORMAT`, `HELD_FUTURE`, `HELD_LEGACY`). A missing or unrecognised verdict is a failure,
# never a success: a stub, a dropped connection, or a device that answered something unexpected must not
# read as "I hold the lock". `TAKEN`, `RENEWED` and `RELEASED` are only printed after the write has been
# **read back** on the device, so a failed write cannot be reported as a successful acquisition.
#
# Tokens, not just owners
# -----------------------
# The canonical line records the owner; `…lock.state/meta` also records a token unique to *this process*.
# Renew and release only act when the token matches, so a tool that holds the lock for a multi-command
# transaction cannot have it released by a command it runs inside that transaction, and a run that lost
# the lock after expiry can never delete the new holder's.
#
# Losing the lease is a fact the caller can see
# ---------------------------------------------
# A long transaction renews in the background. A renewal that fails used to end only that background
# subshell: the transaction kept writing to a phone that now belonged to somebody else. Now a failed
# renewal drops a marker file that `lock_require` reads, so every later device write in the transaction
# is refused and the caller reports "not restored" instead of overwriting another run's device.

#: Path of the canonical lock file — the one `AGENTS.md` and the other scripts use.
LOCK_PATH="${LOCK_PATH:-/data/local/tmp/zshield-device.lock}"
#: The previous revision's lock, a **directory** with a `meta` file inside. It is still honoured: a
#: run that started before this change may be holding it, and ignoring it would be the very defect
#: this rework removes ("a lock nobody else can see is not a lock"). A live one is refused; an expired
#: one is taken over. Nothing new is ever written in this format.
LOCK_LEGACY_DIR="${LOCK_LEGACY_DIR:-$LOCK_PATH.d}"
#: Auxiliary metadata (owner/issued/renewed/token) for the canonical file.
LOCK_STATE_DIR="${LOCK_STATE_DIR:-$LOCK_PATH.state}"
#: The mutual-exclusion directory: created with `mkdir`, held across one read/verify/modify decision.
LOCK_GUARD_DIR="${LOCK_GUARD_DIR:-$LOCK_PATH.guard}"
#: How long a lock stays valid without a renewal, in seconds (2 hours, per AGENTS.md).
LOCK_TTL="${LOCK_TTL:-7200}"
#: How often a long transaction renews, in seconds (30 minutes, per AGENTS.md).
LOCK_RENEW_EVERY="${LOCK_RENEW_EVERY:-1800}"
#: The owner recorded in the lock — the issue identifier. Required; there is no default, because a
#: default owner reads as "mine" to every run and disables the lock.
LOCK_OWNER="${LOCK_OWNER:-}"
#: This process's token. A caller that spans several processes (take in one, release in another) must
#: pass the same token to both — `lock_take` prints the one it used so the caller can.
LOCK_TOKEN="${LOCK_TOKEN:-$$-$RANDOM$RANDOM}"
#: Dropped by the renewer when a renewal fails; read by `lock_require`.
LOCK_LOST_FILE="${LOCK_LOST_FILE:-${TMPDIR:-/tmp}/zshield-lock-lost-$$-$RANDOM.flag}"
#: Every delay the renewer started, so the transaction can prove none was left running.
LOCK_RENEWER_PIDS_FILE="${LOCK_RENEWER_PIDS_FILE:-${TMPDIR:-/tmp}/zshield-lock-renewer-$$-$RANDOM.pids}"

#: The device this run operates on. `device-serial.sh` resolves it — an explicit `SERIAL` wins,
#: otherwise exactly one attached device — and refuses rather than guessing: the lock protects one
#: phone, and which phone that is has to be an answer, not an assumption about somebody's network.
#
# Resolution is **lazy**, on the first device operation rather than at source time: several callers
# of this library have subcommands that only read local files (`tunnel_snapshot.sh check`,
# `condition.sh status`), and demanding a device for those would make a device-free command fail
# whenever none is attached.
# shellcheck source=device-serial.sh
. "$(dirname "${BASH_SOURCE[0]}")/device-serial.sh"

lock_device() {
    ensure_serial
    adb -s "$SERIAL" shell "$@"
}

# ---------------------------------------------------------------------------------------------
# The device-side protocol
#
# The script travels **base64-encoded** and is decoded by the device's own shell:
#
#     echo <base64> | base64 -d | sh
#
# The first version passed it through `printf %q`, which is a bash-ism: for a multi-line string bash
# emits `$'...'`, and the device's `sh` (mksh/toybox) does not understand that form. It read the literal
# characters, produced no verdict, and the lock refused — correctly, since a missing verdict is not a
# lock, but the refusal was caused by the transport rather than by another run holding the phone.
# Base64 has no quoting rules at all, so there is nothing left to get wrong.
#
# The scripts themselves are bash **here-documents with `@placeholders@`** rather than interpolated
# strings. The previous revision escaped every `$` of the device script (`\$...`), which is correct only
# as long as nobody adds one `$` too few; a quoted here-document leaves the device-side `$` alone and
# makes the placeholder substitution the single place where host values enter.

_lock_prelude() {
    cat <<'DEVICE'
LOCK='@LOCK@'
LEGACY='@LEGACY@'
STATE='@STATE@'
GUARD='@GUARD@'
OWNER='@OWNER@'
TOKEN='@TOKEN@'
TTL='@TTL@'
NOW=$(date +%s)
NOWISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)
meta_field() { sed -n "s/^$1=//p" "$STATE/meta" 2>/dev/null | head -1; }
# The first line's first field, and the rest of it, without `awk`: the device's toybox has no `awk`,
# so a parser that depends on it would work on the host and fail on the phone.
canonical_line() { head -1 "$LOCK" 2>/dev/null; }
canonical_owner() { head -1 "$LOCK" 2>/dev/null | { read -r _o _rest || true; printf '%s' "$_o"; }; }
canonical_time()  { head -1 "$LOCK" 2>/dev/null | { read -r _o _rest || true; printf '%s' "$_rest"; }; }
is_uint() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }
# An `<issue> <time>` stamp as seconds since the epoch. Both spellings that exist in this repository
# and in `AGENTS.md` are accepted — ISO-8601 (`2026-11-12T21:55:27Z`, optionally with fractional
# seconds or an offset) and a bare epoch second — and nothing else. An unparseable stamp is an unknown
# format, and the caller refuses rather than guessing an age.
#
# The conversion is arithmetic rather than `date -d`, because the device's toybox `date` has no `-d`
# off GNU systems: a parser that only works on the host would make the whole expiry rule untestable on
# the phone it exists for.
to_epoch() {
    [ -n "$1" ] || return 1
    case "$1" in
        *[!0-9]*) ;;
        *) printf '%s' "$1"; return 0 ;;
    esac
    _t=$1
    case "$_t" in
        [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]*) ;;
        *) return 1 ;;
    esac
    _y=${_t%%-*}; _rest=${_t#*-}
    _mo=${_rest%%-*}; _rest=${_rest#*-}
    _d=${_rest%%T*}; _rest=${_rest#*T}
    _h=${_rest%%:*}; _rest=${_rest#*:}
    _mi=${_rest%%:*}; _rest=${_rest#*:}
    _s=${_rest%%[!0-9]*}
    case "$_y$_mo$_d$_h$_mi$_s" in *[!0-9]*|'') return 1 ;; esac
    # What follows the seconds: optional fractional part, then a zone designator. `Z`/`z`/nothing means
    # UTC; `±HH:MM` or `±HHMM` is an offset. An offset that is present but unparseable is an unknown
    # format rather than silently UTC, because reading a local-time stamp as UTC would misjudge the
    # lease by hours in either direction.
    _tail=${_rest#${_s}}
    case "$_tail" in
        .[0-9]*) _tail=${_tail#.}; _tail=${_tail#"${_tail%%[!0-9]*}"} ;;
    esac
    _off=0
    case "$_tail" in
        ''|Z|z) ;;
        [+-][0-9][0-9]:[0-9][0-9]|[+-][0-9][0-9][0-9][0-9])
            _sign=${_tail%"${_tail#?}"}
            _digits=${_tail#?}
            _digits=${_digits/:}
            [ "${#_digits}" = 4 ] || return 1
            _off=$(( 10#${_digits%??} * 3600 + 10#${_digits#??} * 60 ))
            [ "$_sign" = "-" ] && _off=$(( -_off )) ;;
        *) return 1 ;;
    esac
    # Days from the civil date (Howard Hinnant's algorithm), so no `date` is involved at all.
    # Every field is read with an explicit base: a zero-padded month, day or hour (`08`, `09`) is not
    # a valid octal literal, and a bare `$(( 08 * 60 ))` fails with "value too great for base" — which
    # would refuse a lock whose only sin is being written in January.
    _yy=$_y
    if [ "$(( 10#$_mo ))" -le 2 ]; then _yy=$(( _yy - 1 )); fi
    _era=$(( _yy / 400 ))
    _yoe=$(( _yy - _era * 400 ))
    if [ "$(( 10#$_mo ))" -gt 2 ]; then _mp=$(( 10#$_mo - 3 )); else _mp=$(( 10#$_mo + 9 )); fi
    _doy=$(( ( 153 * _mp + 2 ) / 5 + 10#$_d - 1 ))
    _doe=$(( _yoe * 365 + _yoe / 4 - _yoe / 100 + _doy ))
    _days=$(( _era * 146097 + _doe - 719468 ))
    printf '%s' $(( _days * 86400 + 10#$_h * 3600 + 10#$_mi * 60 + 10#$_s - _off ))
}
# The critical section. `mkdir` is atomic; there is deliberately no retry and no timeout.
#
# A parent directory that does not exist, or one this shell cannot write, is reported as its own
# verdict. Reporting it as `GUARD_BUSY` would blame another run for a path that could never have
# worked, and the operator would go looking for a phantom holder.
enter_guard() {
    if [ ! -d "$(dirname "$GUARD")" ] || [ ! -w "$(dirname "$GUARD")" ]; then
        echo "WRITE_FAILED path-not-writable dir=$(dirname "$GUARD")"
        return 1
    fi
    if ! mkdir "$GUARD" 2>/dev/null; then
        _since=$(cat "$GUARD/started" 2>/dev/null)
        if [ -n "$_since" ]; then
            echo "GUARD_BUSY path=$GUARD age=$(( NOW - _since ))s holder=$(cat "$GUARD/owner" 2>/dev/null)"
        else
            echo "GUARD_BUSY path=$GUARD age=unknown"
        fi
        return 1
    fi
    printf '%s\n' "$NOW" >"$GUARD/started" 2>/dev/null
    printf '%s\n' "$TOKEN" >"$GUARD/token" 2>/dev/null
    # `0` is the POSIX spelling of "on exit", so this is not a bash-ism like the `printf %q` the
    # previous transport used: the device's own `sh` (mksh/toybox) accepts it too. The guard is
    # removed only by the process that created it — a losing runner must not clear the winner's.
    trap 'if [ "$(cat "$GUARD/token" 2>/dev/null)" = "$TOKEN" ]; then rm -rf "$GUARD" 2>/dev/null; fi' 0
    return 0
}
# Write the canonical first line. `mv` of a fully written temporary file is the atomic step, so another
# reader (including one that does not know about the guard) never sees a half-written lock.
write_canonical() {
    printf '%s %s\n' "$OWNER" "$NOWISO" >"$LOCK.tmp.$$" 2>/dev/null || { rm -f "$LOCK.tmp.$$"; return 1; }
    mv "$LOCK.tmp.$$" "$LOCK" 2>/dev/null || { rm -f "$LOCK.tmp.$$"; return 1; }
}
write_meta() {
    mkdir -p "$STATE" 2>/dev/null || return 1
    printf 'owner=%s\nissued=%s\nrenewed=%s\ntoken=%s\ncanonical=%s\n' \
        "$OWNER" "$1" "$2" "$TOKEN" "$(canonical_line)" >"$STATE/meta.tmp.$$" 2>/dev/null || return 1
    mv "$STATE/meta.tmp.$$" "$STATE/meta" 2>/dev/null || return 1
}
# Read back what was written. A write that "succeeded" but is not on the device is a failed write.
verify_mine() {
    [ -f "$LOCK" ] || return 1
    [ "$(canonical_owner)" = "$OWNER" ] || return 1
    [ "$(meta_field token)" = "$TOKEN" ] || return 1
    return 0
}
# The previous revision's lock, in its **directory** form.
#
# There are two places such a lock can be, and both must be honoured rather than ignored:
#
#   `$LOCK.d`   the previous revision's default path. A run that started before this change may be
#               holding it, and ignoring it is exactly the "invisible lock" defect this rework removes.
#   `$LOCK`     a directory sitting at the canonical path. That is the same format with `LOCK_PATH`
#               overridden, which is how the stage-3 safety probe drives it — so treating it as
#               unreadable debris would refuse a lock that is perfectly well formed.
#
# Neither is ever *written*: a live one is refused, an unreadable one is refused, and only an expired
# one is retired (under the guard) before a canonical lock is taken.
#
# Two variables rather than one verdict string, because the decision has to be compared exactly
# (`expired` is a decision, not a prefix of a message) while the detail is for the operator to read.
# `LEGACY_KIND` is one of: absent / expired / held / unreadable.
LEGACY_KIND='absent'
LEGACY_DETAIL=''
LEGACY_PATH=''
legacy_meta() { sed -n "s/^$1=//p" "$LEGACY_PATH/meta" 2>/dev/null | head -1; }
check_legacy() {
    LEGACY_KIND='absent'; LEGACY_DETAIL=''; LEGACY_PATH=''
    if [ -d "$LOCK" ]; then
        LEGACY_PATH=$LOCK
    elif [ -d "$LEGACY" ]; then
        LEGACY_PATH=$LEGACY
    else
        return 0
    fi
    _lo=$(legacy_meta owner); _lr=$(legacy_meta renewed)
    if [ -z "$_lo" ] || [ -z "$_lr" ]; then
        LEGACY_KIND='unreadable'; LEGACY_DETAIL="path=$LEGACY_PATH owner=$_lo renewed=$_lr"; return 0
    fi
    case "$_lr" in
        *[!0-9]*|'') LEGACY_KIND='unreadable'; LEGACY_DETAIL="path=$LEGACY_PATH renewed=$_lr"; return 0 ;;
    esac
    _lage=$(( NOW - _lr ))
    if [ "$_lage" -le "$TTL" ]; then
        LEGACY_KIND='held'; LEGACY_DETAIL="owner=$_lo path=$LEGACY_PATH age=${_lage}s"
    else
        LEGACY_KIND='expired'; LEGACY_DETAIL="owner=$_lo path=$LEGACY_PATH age=${_lage}s"
    fi
    return 0
}
# Retire an expired directory lock. Only an expired one, only under the guard, and only by renaming it
# to `…stale.<token>` first — a `rename` is atomic, so a half-removed tree can never look live again,
# and a second runner that reaches this point after the winner finds nothing to move.
retire_legacy() {
    [ "$LEGACY_KIND" = expired ] || return 0
    if ! mv "$LEGACY_PATH" "$LEGACY_PATH.stale.$TOKEN" 2>/dev/null; then
        echo "WRITE_FAILED legacy-retire"; return 1
    fi
    rm -rf "$LEGACY_PATH.stale.$TOKEN" 2>/dev/null
    LEGACY_KIND='absent'; LEGACY_DETAIL=''
    return 0
}
DEVICE
}

_lock_take_script() {
    cat <<'DEVICE'
enter_guard || exit 0
# A live lock in the previous revision's directory form still holds the phone: a run that started
# before this change may be using it, and ignoring it is exactly the "invisible lock" defect. A live
# one is refused, an unreadable one is refused, and only an expired one is retired.
check_legacy
case "$LEGACY_KIND" in
    absent|expired) ;;
    held) echo "HELD_LEGACY $LEGACY_DETAIL"; exit 0 ;;
    *) echo "HELD_LEGACY_UNREADABLE $LEGACY_DETAIL"; exit 0 ;;
esac
# Our own metadata is the more precise record of a renewed lease, so it is used **in addition to** the
# canonical stamp, never instead of it: a lock file somebody else wrote (the AGENTS.md convention) has
# no state beside it and is judged by its own line. One that cannot be read is an unknown format and is
# refused, exactly like an unparseable canonical line.
if [ -f "$STATE/meta" ]; then
    if ! is_uint "$(meta_field renewed)" || [ -z "$(meta_field owner)" ]; then
        echo "HELD_UNKNOWN_FORMAT metadata=$STATE/meta"; exit 0
    fi
fi
if [ -f "$LOCK" ]; then
    HELD_OWNER=$(canonical_owner)
    HELD_TIME=$(canonical_time)
    if [ -z "$HELD_OWNER" ] || [ -z "$HELD_TIME" ]; then
        echo "HELD_UNKNOWN_FORMAT line=$(canonical_line)"; exit 0
    fi
    if ! ISSUED=$(to_epoch "$HELD_TIME"); then
        echo "HELD_UNKNOWN_FORMAT time=$HELD_TIME"; exit 0
    fi
    LEASE=$ISSUED
    if [ -f "$STATE/meta" ] && [ "$(meta_field owner)" = "$HELD_OWNER" ]; then
        _renewed=$(meta_field renewed)
        if [ "$_renewed" -gt "$LEASE" ]; then LEASE=$_renewed; fi
    fi
    AGE=$(( NOW - LEASE ))
    if [ "$AGE" -lt 0 ]; then
        # A stamp in the future never expires, so it would hold the phone forever. Refuse rather than
        # guess how far off the clocks are.
        echo "HELD_FUTURE owner=$HELD_OWNER skew=$(( -AGE ))s"; exit 0
    fi
    if [ "$AGE" -le "$TTL" ]; then
        echo "HELD owner=$HELD_OWNER age=${AGE}s ttl=${TTL}s"; exit 0
    fi
    # Expired. Under the guard this is a single decision, so the takeover cannot interleave with
    # another runner's read or write — which is what the previous read-then-rename did.
    retire_legacy || exit 0
    write_canonical || { echo "WRITE_FAILED canonical"; exit 0; }
    write_meta "$NOW" "$NOW" || { echo "WRITE_FAILED meta"; exit 0; }
    verify_mine || { echo "VERIFY_FAILED after-takeover"; exit 0; }
    echo "TAKEN_STALE $HELD_OWNER"; exit 0
fi
# No canonical lock file. An expired legacy directory is retired, then the lock is taken; a live one
# was already refused above.
retire_legacy || exit 0
write_canonical || { echo "WRITE_FAILED canonical"; exit 0; }
write_meta "$NOW" "$NOW" || { echo "WRITE_FAILED meta"; exit 0; }
verify_mine || { echo "VERIFY_FAILED after-take"; exit 0; }
echo TAKEN
DEVICE
}

_lock_renew_script() {
    cat <<'DEVICE'
enter_guard || exit 0
[ -f "$LOCK" ] || { echo "LOST canonical-missing"; exit 0; }
_held=$(meta_field token)
# A lock with no metadata beside it is not ours: this run always writes both, so its absence means the
# lock was replaced by somebody who does not use the state file.
if [ "$_held" != "$TOKEN" ]; then echo "NOTMINE token=$_held"; exit 0; fi
if [ "$(canonical_owner)" != "$OWNER" ] || [ "$(meta_field owner)" != "$OWNER" ]; then
    echo "LOST canonical-owner=$(canonical_owner)"; exit 0
fi
_issued=$(meta_field issued)
is_uint "$_issued" || _issued=$NOW
write_canonical || { echo "WRITE_FAILED canonical"; exit 0; }
write_meta "$_issued" "$NOW" || { echo "WRITE_FAILED meta"; exit 0; }
verify_mine || { echo "VERIFY_FAILED after-renew"; exit 0; }
[ "$(meta_field renewed)" = "$NOW" ] || { echo "VERIFY_FAILED renewed=$(meta_field renewed)"; exit 0; }
echo RENEWED
DEVICE
}

_lock_release_script() {
    cat <<'DEVICE'
enter_guard || exit 0
if [ ! -e "$LOCK" ] && [ ! -d "$STATE" ]; then echo "NOTMINE nothing-held"; exit 0; fi
_held=$(meta_field token)
if [ "$_held" != "$TOKEN" ]; then echo "NOTMINE token=$_held"; exit 0; fi
# Only a lock that still names this owner is removed: after an expiry takeover the state file can
# carry an old token while the canonical line already belongs to somebody else.
if [ -f "$LOCK" ] && [ "$(canonical_owner)" != "$OWNER" ]; then
    echo "NOTMINE canonical-owner=$(canonical_owner)"; exit 0
fi
rm -f "$LOCK" 2>/dev/null
rm -rf "$STATE" 2>/dev/null
[ -e "$LOCK" ] && { echo "WRITE_FAILED released-but-present"; exit 0; }
[ -e "$STATE" ] && { echo "WRITE_FAILED state-survived"; exit 0; }
echo RELEASED
DEVICE
}

#: Whether this run *currently* holds the lock, asked of the device — not of local state.
#:
#: A local "I have not seen a loss" is not the same fact as "the lock on the device is mine": a run
#: that has not yet taken it has no loss marker, and a `cleanup` or `restore` invocation is a fresh
#: process with an empty one. So the question goes to the canonical file and its state, under the same
#: critical section as every other read/verify/modify, and the answer is `HELD_BY_ME` or a refusal.
_lock_verify_script() {
    cat <<'DEVICE'
enter_guard || exit 0
check_legacy
case "$LEGACY_KIND" in
    held) echo "HELD_LEGACY $LEGACY_DETAIL"; exit 0 ;;
    unreadable) echo "HELD_LEGACY_UNREADABLE $LEGACY_DETAIL"; exit 0 ;;
esac
if [ ! -f "$LOCK" ]; then echo "FREE nothing-held"; exit 0; fi
_held=$(meta_field token)
if [ "$_held" != "$TOKEN" ]; then echo "NOTMINE token=$_held"; exit 0; fi
if [ "$(canonical_owner)" != "$OWNER" ] || [ "$(meta_field owner)" != "$OWNER" ]; then
    echo "NOTMINE canonical-owner=$(canonical_owner)"; exit 0
fi
_renewed=$(meta_field renewed)
is_uint "$_renewed" || { echo "NOTMINE renewed=$_renewed"; exit 0; }
AGE=$(( NOW - _renewed ))
if [ "$AGE" -gt "$TTL" ]; then echo "EXPIRED age=${AGE}s ttl=${TTL}s"; exit 0; fi
echo "HELD_BY_ME token=$TOKEN remaining=$(( TTL - AGE ))"
DEVICE
}

_lock_status_script() {
    cat <<'DEVICE'
if [ -d "$GUARD" ]; then
    _since=$(cat "$GUARD/started" 2>/dev/null)
    echo "GUARD ${_since:-unknown}"
    exit 0
fi
check_legacy
if [ ! -f "$LOCK" ]; then
    case "$LEGACY_KIND" in
        absent) echo FREE ;;
        expired) echo "FREE legacy=expired owner=$(legacy_owner)" ;;
        *) echo "HELD_LEGACY $LEGACY_DETAIL" ;;
    esac
    exit 0
fi
if [ -e "$LOCK" ] && [ ! -f "$LOCK" ]; then
    echo "UNREADABLE kind=$( [ -d "$LOCK" ] && echo directory || echo special )"; exit 0
fi
HELD_OWNER=$(canonical_owner)
HELD_TIME=$(canonical_time)
if [ -z "$HELD_OWNER" ] || [ -z "$HELD_TIME" ] || ! ISSUED=$(to_epoch "$HELD_TIME"); then
    echo "UNREADABLE line=$(canonical_line)"; exit 0
fi
LEASE=$ISSUED
_meta_owner=$(meta_field owner)
if [ "$_meta_owner" = "$HELD_OWNER" ] && is_uint "$(meta_field renewed)"; then
    _renewed=$(meta_field renewed)
    if [ "$_renewed" -gt "$LEASE" ]; then LEASE=$_renewed; fi
fi
AGE=$(( NOW - LEASE ))
echo "HELD owner=$HELD_OWNER token=$(meta_field token) remaining=$(( TTL - AGE )) age=${AGE}s"
DEVICE
}

#: Join the shared prelude and one operation's body. `$(…)` drops trailing newlines, so the two
#: here-documents would otherwise be concatenated on one line (`}enter_guard || exit 0`), which parses
#: as a malformed brace group — a real failure this composer exists to prevent.
_lock_compose() {
    _lock_prelude
    printf '\n'
    "$@"
}

#: Substitute the host-side values into one device script. A placeholder that survives means the
#: template was edited without a matching value, which is a bug rather than a device fault.
_lock_expand() {
    local script="$1"
    script="${script//@LOCK@/$LOCK_PATH}"
    script="${script//@LEGACY@/$LOCK_LEGACY_DIR}"
    script="${script//@STATE@/$LOCK_STATE_DIR}"
    script="${script//@GUARD@/$LOCK_GUARD_DIR}"
    script="${script//@OWNER@/$LOCK_OWNER}"
    script="${script//@TOKEN@/$LOCK_TOKEN}"
    script="${script//@TTL@/$LOCK_TTL}"
    case "$script" in
        *"@LOCK@"*|*"@LEGACY@"*|*"@STATE@"*|*"@GUARD@"*|*"@OWNER@"*|*"@TOKEN@"*|*"@TTL@"*)
            printf '_LOCK_TEMPLATE_ERROR'
            return 0 ;;
    esac
    printf '%s\n' "$script"
}

#: Run one device-side protocol script and return its final verdict line.
_lock_protocol() {
    local script encoded
    script="$(_lock_expand "$1")"
    case "$script" in
        _LOCK_TEMPLATE_ERROR) echo "_LOCK_TEMPLATE_ERROR"; return 0 ;;
    esac
    encoded="$(printf '%s' "$script" | base64 -w0 2>/dev/null || printf '%s' "$script" | base64 | tr -d '\n')"
    if [ -z "$encoded" ]; then
        echo "_LOCK_TRANSPORT_ERROR"
        return 0
    fi
    # The lock's path is echoed as a **comment** before the decoded script runs. It changes nothing
    # about the protocol, and it means the adb transcript — which is what an operator, a reviewer and
    # a probe read — says which resource this call is about. Without it the transcript is an opaque
    # base64 blob, and a reader cannot tell a lock call from any other `sh` call on the device.
    lock_device "echo '# $LOCK_PATH (token $LOCK_TOKEN)' >/dev/null; echo $encoded | base64 -d | sh" \
        2>/dev/null | tr -d '\r' | tail -n 1
}

#: The owner is required and is also what goes into the canonical first line, so it is validated as a
#: bare token: an owner with a space would silently shorten the `<issue> <ISO>` line every other task
#: parses, and a quote would break the device script it is embedded in.
_lock_owner_problem() {
    case "$LOCK_OWNER" in
        "") echo "LOCK_OWNER is empty"; return 0 ;;
        *[!A-Za-z0-9._-]*) echo "LOCK_OWNER contains a character that cannot go into '<issue> <time>': $LOCK_OWNER"; return 0 ;;
    esac
    case "$LOCK_TOKEN" in
        "") echo "LOCK_TOKEN is empty"; return 0 ;;
        *[!A-Za-z0-9._:-]*) echo "LOCK_TOKEN contains an unsupported character: $LOCK_TOKEN"; return 0 ;;
    esac
    return 1
}

#: Take the lock, or fail with the holder's record.
#:
#: Prints `TAKEN` / `TAKEN_STALE <previous-owner>` on success and returns 0; prints the verdict on
#: stderr and returns 1 otherwise. The caller must not touch the device before this returns 0.
lock_take() {
    if [ -z "$LOCK_OWNER" ]; then
        echo "device lock: refusing to take it without LOCK_OWNER (--issue <task>); a default owner" >&2
        echo "  reads as 'mine' to every run and disables the lock" >&2
        return 1
    fi
    local problem verdict
    if problem="$(_lock_owner_problem)"; then
        echo "device lock: refusing — $problem" >&2
        return 1
    fi
    # Keep the selected device in the owner's shell across acquisition, renewal and release.
    ensure_serial
    : >"$LOCK_LOST_FILE" 2>/dev/null || true
    verdict="$(_lock_protocol "$(_lock_compose _lock_take_script)")"
    case "$verdict" in
        TAKEN)
            echo "device lock: taken by $LOCK_OWNER ($LOCK_PATH)"
            echo "device lock: token $LOCK_TOKEN (pass LOCK_TOKEN=$LOCK_TOKEN to a later command to renew or release it)"
            return 0 ;;
        TAKEN_STALE*)
            echo "device lock: took over an expired lock from ${verdict#TAKEN_STALE } ($LOCK_PATH)"
            echo "device lock: token $LOCK_TOKEN (pass LOCK_TOKEN=$LOCK_TOKEN to a later command to renew or release it)"
            return 0 ;;
        GUARD*)
            echo "device lock: not available — ${verdict}" >&2
            echo "  ${LOCK_GUARD_DIR} is the critical section of another run, or one that crashed while" >&2
            echo "  holding it. It is never taken over automatically: confirm nobody is using the phone," >&2
            echo "  then remove it by hand — adb shell rmdir ${LOCK_GUARD_DIR} — and retry." >&2
            return 1 ;;
        HELD_LEGACY*)
            echo "device lock: not available — $verdict" >&2
            echo "  the legacy directory lock ${LOCK_LEGACY_DIR} still names a holder; it is honoured" >&2
            echo "  until it expires (${LOCK_TTL}s after its last renewal), and never overwritten." >&2
            return 1 ;;
        HELD*|WRITE_FAILED*|VERIFY_FAILED*|_LOCK_*)
            echo "device lock: not available — $verdict" >&2
            echo "  (a live lock belongs to another run; an unreadable or future-dated one is never" >&2
            echo "   overwritten; a failed write is not an acquisition)" >&2
            return 1 ;;        *)
            echo "device lock: no usable verdict from the device (${verdict:-<no output>})" >&2
            echo "  a missing answer is not a lock; refusing to touch the device" >&2
            return 1 ;;
    esac
}

#: Refresh this run's lock. Only acts when the token matches, inside the critical section.
lock_renew() {
    local verdict
    verdict="$(_lock_protocol "$(_lock_compose _lock_renew_script)")"
    case "$verdict" in
        RENEWED) echo "device lock: renewed ($LOCK_TOKEN)"; return 0 ;;
        *)
            echo "device lock: renewal refused — ${verdict:-<no output>}" >&2
            return 1 ;;
    esac
}

#: Release this run's lock. Only removes it when the token matches; a foreign lock is left alone.
#:
#: Returns 0 when this run's lock was removed or there was nothing to remove, and 1 when the lock on the
#: device belongs to someone else — the caller that believed it held the phone needs to know.
lock_release() {
    local verdict
    verdict="$(_lock_protocol "$(_lock_compose _lock_release_script)")"
    case "$verdict" in
        RELEASED) echo "device lock: released ($LOCK_TOKEN)"; return 0 ;;
        "NOTMINE nothing-held")
            echo "device lock: nothing released (no lock on the device)" >&2
            return 0 ;;
        *)
            # A run whose lock was taken over after expiry must not delete the new holder's lock; it
            # also must not report that it released one.
            echo "device lock: nothing released — ${verdict:-<no output>}" >&2
            return 1 ;;
    esac
}

#: Print the lock's state and remaining validity. Exit 2 when it cannot be read at all.
lock_status() {
    local verdict
    verdict="$(_lock_protocol "$(_lock_compose _lock_status_script)")"
    case "$verdict" in
        FREE) echo "lock:        free" ; return 0 ;;
        GUARD*)
            echo "lock:        critical section held by another run (${verdict#GUARD })"
            echo "             (a crash leaves it behind; remove it by hand after checking the phone)"
            return 2 ;;
        HELD\ *)
            local rest="${verdict#HELD }"
            echo "lock:        $rest"
            case "$rest" in
                *"remaining=-"*)
                    echo "             (expired; the next taker may claim it)" ;;
            esac
            return 0 ;;
        *)
            echo "lock:        unreadable (${verdict:-no answer})"
            return 2 ;;
    esac
}

# ---------------------------------------------------------------------------------------------
# The lease, as the rest of the transaction sees it
# ---------------------------------------------------------------------------------------------

#: Whether a background renewal has failed since this process started. Cheap: one file test, so the
#: caller can afford it before every device write.
lock_lost() {
    [ -n "$LOCK_LOST_FILE" ] && [ -s "$LOCK_LOST_FILE" ]
}

#: Why the lease was lost, or an empty string.
lock_loss_reason() {
    cat "$LOCK_LOST_FILE" 2>/dev/null | head -1
}

#: Check ownership on the device before each write. A previous success cannot authorize a
#: later write: the lease may have expired or the canonical lock may have changed owners.
lock_verify() {
    local verdict
    lock_lost && return 1
    verdict="$(_lock_protocol "$(_lock_compose _lock_verify_script)")"
    case "$verdict" in
        HELD_BY_ME*) return 0 ;;
        *)
            echo "device lock: this run does not hold $LOCK_PATH — ${verdict:-<no output>}" >&2
            return 1 ;;
    esac
}

#: Refuse to write to the device unless this run currently holds the lock.
#:
#: This is what turns "the renewer noticed" into "the transaction stopped", and what keeps a command
#: that never took the lock (`cleanup`, `restore`, a direct rule install) from writing at all.
lock_require() {
    if lock_lost; then
        echo "device lock: LOST — $(lock_loss_reason)" >&2
        echo "  this run no longer owns $LOCK_PATH; no further device writes are allowed" >&2
        return 1
    fi
    lock_verify
}

#: The renewer's process id, empty when none is running.
LOCK_RENEWER_PID=""

#: Renew in the background for the life of this process, so a long transaction keeps its lease.
#:
#: A 30-minute measurement cannot be protected by a 2-hour lock that nobody refreshes if the run
#: stalls; and a lease that is never refreshed while the run is *alive* is the other half of the same
#: bug. The renewer records every `sleep` it starts, so `lock_stop_renewer` can kill and reap the exact
#: children: killing only the subshell leaves the delay behind, asleep and invisible, which is what
#: "no leftover renewer" is about.
#:
#: `sleep` is checked for being a real delay before the loop is started. A `sleep` that returns
#: immediately (a stand-in in a test, or a broken busybox) would turn this into a spin that hammers the
#: device and keeps the wrapper's stdout pipe open. No delay, no renewer — and the caller then has a
#: plain 2-hour lease, which is the documented fallback rather than a hang.
lock_start_renewer() {
    [ -n "$LOCK_RENEWER_PID" ] && return 0
    local started ended
    started="$(date +%s)"
    sleep 1 2>/dev/null || true
    ended="$(date +%s)"
    if [ "$(( ended - started ))" -lt 1 ]; then
        echo "device lock: no real sleep available; running on the ${LOCK_TTL}s lease without a renewer" >&2
        return 0
    fi
    : >"$LOCK_RENEWER_PIDS_FILE" 2>/dev/null || true
    (
        while :; do
            # `wait` on the exact child, so the subshell sleeps rather than polling, and so the pid
            # recorded below is the only thing `lock_stop_renewer` has to kill.
            sleep "$LOCK_RENEW_EVERY" &
            child=$!
            printf '%s\n' "$child" >>"$LOCK_RENEWER_PIDS_FILE" 2>/dev/null || true
            wait "$child" 2>/dev/null || exit 0
            if ! lock_renew >/dev/null 2>&1; then
                printf 'renewal failed at %s (token %s)\n' \
                    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$LOCK_TOKEN" >"$LOCK_LOST_FILE" 2>/dev/null || true
                exit 1
            fi
        done
    ) >/dev/null 2>&1 &
    LOCK_RENEWER_PID=$!
}

#: Stop the renewer and every delay it started, and report whether anything survived.
lock_stop_renewer() {
    local pid alive waited=0 status=0
    if [ -n "$LOCK_RENEWER_PID" ]; then
        kill "$LOCK_RENEWER_PID" 2>/dev/null || true
        wait "$LOCK_RENEWER_PID" 2>/dev/null || true
        LOCK_RENEWER_PID=""
    fi
    [ -f "$LOCK_RENEWER_PIDS_FILE" ] || return 0
    while read -r pid; do
        [ -n "$pid" ] || continue
        kill "$pid" 2>/dev/null || true
    done <"$LOCK_RENEWER_PIDS_FILE"
    # Bounded confirmation: a `sleep` that ignores SIGTERM (or a pid that got reused) must be visible
    # as a leftover rather than silently assumed dead.
    while [ "$waited" -lt 100 ]; do
        alive=0
        while read -r pid; do
            [ -n "$pid" ] || continue
            kill -0 "$pid" 2>/dev/null && alive=1
        done <"$LOCK_RENEWER_PIDS_FILE"
        [ "$alive" = 0 ] && break
        sleep 0.05 2>/dev/null || sleep 1
        waited=$(( waited + 1 ))
    done
    if [ "$alive" != 0 ]; then
        echo "device lock: a renewer child survived cleanup (see $LOCK_RENEWER_PIDS_FILE)" >&2
        status=1
    fi
    rm -f "$LOCK_RENEWER_PIDS_FILE" 2>/dev/null || true
    return "$status"
}
