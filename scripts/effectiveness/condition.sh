#!/usr/bin/env bash
# Put the device into one measurement condition, or restore it afterwards.
#
# Usage:
#   LOCK_OWNER=<task-id> scripts/effectiveness/condition.sh <vpn-off|zshield-default|zshield-https>
#   LOCK_OWNER=<task-id> scripts/effectiveness/condition.sh apply-test-lists
#   scripts/effectiveness/condition.sh restore | backup | status | cleanup | renew
#
# The lock owner is required (see the device-lock section below); `--issue <task-id>` is the same
# thing spelled as a flag, which is what the acceptance script prints.
#
# Three conditions, exactly as the task card defines them:
#
#   vpn-off           protection off: this is the baseline every other number is compared against
#   zshield-default   tunnel up, default settings (HTTPS filtering OFF — no CA, no decryption)
#   zshield-https     tunnel up, HTTPS filtering ON, the app's CA installed in the user store
#
# Everything the script does is reversible through `cleanup`, and it prints what it changed so the
# transcript is the evidence. It never touches Wi-Fi (AGENTS.md: adb runs over it).
#
# `--apply-test-lists` additionally installs the testcases.agrd.dev companion filter lists through
# the app's `DEBUG_SET_RULES` broadcast seam before the test pages are opened. It is a separate flag
# because it changes the rule set: a plain condition run measures the *shipped* lists only.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# shellcheck source=device-lock.sh
# `device-lock.sh` resolves `SERIAL` lazily, on the first device operation, so a subcommand that only
# reads local state (`status`) works with no phone attached. The address is never baked into the
# repository.
. scripts/effectiveness/device-lock.sh

PKG="${PKG:-top.zztweb.zshield}"
RECEIVER="$PKG/.filters.DebugCommandReceiver"
#: Lock-screen credential used only to install a user CA (Android 11+ requires one).
#:
#: There is deliberately **no default**. A literal here would be published with the repository, would
#: become the credential every contributor's test phone ends up with, and would be printed by the
#: `install-ca` transcript and by any `adb` trace of a run. The operator supplies their own through
#: `ZSHIELD_TEST_PIN`; the value is never echoed by this script (commands that carry it are run with
#: output suppressed, and the surrounding messages name it as `$ZSHIELD_TEST_PIN` rather than a value).
PIN="${ZSHIELD_TEST_PIN:-}"
LISTS_DIR=".effectiveness/lists"

# Lazy: `status` and the `lock-*` subcommands read local state and must work with no phone attached.
d()   { ensure_serial; adb -s "$SERIAL" "$@"; }
sh_() { ensure_serial; adb -s "$SERIAL" shell "$@"; }
#: A device **write**, refused unless this run currently holds the lock.
#:
#: Two distinct failures have to be caught here, and the first is not visible from local state:
#:
#:   * another task holds the phone — the canonical lock names it. A fresh process (a `cleanup`, a
#:     `restore`, a direct rule install) has an empty loss marker, so "no loss observed" used to read
#:     as "held" and the write went through. `lock_require` now asks the **device** before each write.
#:   * this run held it and lost it — the renewer's marker, checked on every call.
#:
#: Reads keep using `sh_`: reporting on a device one no longer owns is harmless, changing it is not.
w_() {
    if ! lock_require; then
        echo "condition: refusing to write to the device — this run does not hold the lock" >&2
        return 1
    fi
    ensure_serial
    adb -s "$SERIAL" shell "$@"
}
say() { printf '\n=== %s\n' "$*"; }

#: The display's *current* size, read once and cached.
#
# The device is a Pixel 5 whose physical panel is 1080x2340, but its current override is landscape
# 1920x1080 (`wm size` reports `Physical size: 1080x2340` / `Override size: 1080x1920`, and the
# rotation puts 1920 on the x axis). Hard-coded swipe coordinates written against the portrait panel
# therefore land off-screen, and a vertical swipe that starts within ~30 px of the bottom edge is
# claimed by Android's gesture navigation and sends the app to the launcher — which is exactly how an
# earlier version of this script "lost" the debug screen mid-run. Every gesture below is derived from
# these numbers instead.
SCREEN_W=""
SCREEN_H=""
screen_size() {
    if [ -n "$SCREEN_W" ] && [ -n "$SCREEN_H" ]; then
        return 0
    fi
    local size
    size="$(sh_ "wm size" 2>/dev/null | grep -oE 'Override size: [0-9]+x[0-9]+|Physical size: [0-9]+x[0-9]+' \
        | tail -1 | grep -oE '[0-9]+x[0-9]+')"
    if [ -z "$size" ]; then
        size="1080x1920"
    fi
    local w="${size%x*}" h="${size#*x}"
    # `wm size` reports the panel in its natural orientation; `dumpsys window displays` `cur=` is the
    # rotated one. The rotation is what the input coordinates use.
    local cur
    cur="$(sh_ "dumpsys window displays" 2>/dev/null | grep -oE 'cur=[0-9]+x[0-9]+' | head -1 | cut -d= -f2)"
    if [ -n "$cur" ]; then
        w="${cur%x*}"
        h="${cur#*x}"
    fi
    SCREEN_W="$w"
    SCREEN_H="$h"
}

#: Swipe from `$2` to `$3` along the vertical axis at the horizontal centre, by `$1` percent of the
#: screen height per step, `$4` steps. Stays inside a safe band: 10%–85% of the height, which keeps
#: clear of the status bar and of the gesture-navigation strip at the bottom.
swipe_vertical() {
    local from_pct="$1" to_pct="$2" duration="${3:-300}"
    screen_size
    local x=$(( SCREEN_W / 2 ))
    local y1=$(( SCREEN_H * from_pct / 100 ))
    local y2=$(( SCREEN_H * to_pct / 100 ))
    w_ "input swipe $x $y1 $x $y2 $duration" >/dev/null 2>&1
}

# ---------------------------------------------------------------------------------------------
# Device lock — one implementation, shared with the measurement scripts
#
# The take/renew/release logic lives in `device-lock.sh` and is sourced below, so `condition.sh` and
# `tunnel_acceptance.sh` cannot drift apart on what "held", "expired" and "mine" mean. The rules it
# implements, and what each one exists to stop:
#
#   * **the owner is required** — `LOCK_OWNER` (or `--issue`). The previous version defaulted to
#     `MYS-2738`, a task that finished on 11-10, so every run wrote a lock naming a dead issue *and*
#     treated that dead name as "mine", defeating the lock entirely.
#   * **a directory, not a file** — `mkdir` is atomic; `[ -f ] && echo >` is two steps two runners can
#     both win. See `device-lock.sh`.
#   * **a token, not just an owner** — release and renew only act when *this process's* token is in the
#     lock, so a tool that holds the lock across a whole transaction cannot have it released by the
#     command it runs inside that transaction.
#   * **expiry with an atomic takeover** — an expired lock is claimed by renaming it, which exactly one
#     caller can win; two runners racing an expired lock therefore still yield one holder.
#   * **only my lock is released** — a cleanup that deletes someone else's lock is how two runs end up
#     on one device.
# ---------------------------------------------------------------------------------------------
LOCK_OWNER="${LOCK_OWNER:-}"
#: Set when this process actually took the lock, so the exit trap releases only what it holds.
LOCK_HELD=0

#: Refuse early, with a message that says how to supply the owner.
require_lock_owner() {
    if [ -z "$LOCK_OWNER" ]; then
        cat >&2 <<'EOF'
this script must be told which task owns the device lock.
  LOCK_OWNER=MYS-2817 scripts/effectiveness/condition.sh zshield-https
  or  scripts/effectiveness/condition.sh zshield-https --issue MYS-2817
The owner is recorded in the lock so a parallel task can see who holds the phone; there is
deliberately no default, because a default owner is indistinguishable from "this is mine" and
disables the lock.
EOF
        return 1
    fi
}

#: Take the lock and remember that this process holds it.
take_lock() { lock_take && LOCK_HELD=1; }

#: Release it again (trap-safe; a no-op when this process never took it).
release_lock() {
    [ "$LOCK_HELD" = 1 ] || return 0
    lock_release || true
    LOCK_HELD=0
}

# ---------------------------------------------------------------------------------------------
# State probes
# ---------------------------------------------------------------------------------------------
tunnel_up() {
    sh_ "dumpsys connectivity" 2>/dev/null | grep -q "IS_VPN"
}

protection_state() {
    local dump
    dump="$(sh_ "dumpsys activity services $PKG" 2>/dev/null)"
    # The dump always starts with an "ACTIVITY MANAGER SERVICES" banner, so the absence of the
    # package's own service record is what means "stopped" — printed either as "(nothing)" or
    # "No services found" depending on the platform version.
    if [ -z "$dump" ] \
        || printf '%s' "$dump" | grep -qE "\(nothing\)|No services found" \
        || ! printf '%s' "$dump" | grep -q "ServiceRecord"; then
        echo "stopped"
    elif printf '%s' "$dump" | grep -q "isForeground=true"; then
        echo "running"
    else
        echo "starting"
    fi
}

wait_tunnel() {
    local want="$1" timeout="${2:-90}" waited=0
    while [ "$waited" -lt "$timeout" ]; do
        if [ "$want" = "up" ]; then
            tunnel_up && return 0
        else
            tunnel_up || return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done
    echo "tunnel did NOT reach $want within ${timeout}s" >&2
    return 1
}

# The core prints the live HTTPS state on every start and policy change:
#   I ZShield : https filtering: true (ca installed true, 2 uids, user hosts 0)
# That single line answers all three questions at once (on/off, CA installed, how many app uids are
# decrypted), and unlike the debug screen it does not depend on the ScrollView's scroll position or
# on `uiautomator` seeing a Compose-rendered label.
# `logcat -s <tag>` is not usable over `adb shell` here: the device's `logcat` treats the tag
# filters differently per platform build and returned nothing at all.
#
# The grep runs **on the device**, not on the host. The whole `logcat -d -b all` buffer is ~34 000
# lines; pulling it across the measurement link costs ~100 s per 1 000 lines (measured on the Pixel 5
# over Wi-Fi: a 1 000-line prefix took 1 m 40 s), while the same pipeline executed by the device's own
# `sh` returns in ~2 s. Every caller needs one line or one fingerprint out of that buffer, so shipping
# the buffer is pure loss — and slow enough that `status` used to take minutes.
log_grep() {
    local pattern="$1"
    local quoted
    quoted="$(printf '%q' "$pattern")"
    # `-E` is the device grep's extended mode; the pattern is already an ERE. `%q` above keeps the
    # pattern one argument through `adb shell`'s own re-parse.
    sh_ "logcat -d -b all 2>/dev/null | grep -E $quoted" 2>/dev/null | tr -d '\r'
}

# Both tags matter and they are spelled differently in the dump: the Kotlin side logs under
# `ZShield` (printed as `I ZShield : …`, note the space before the colon) and the core under
# `ZShieldCore` (`I ZShieldCore: …`). Anchoring on `ZShield` alone would match both but also
# `ZShieldTileService` and friends, so the two exact forms are what is matched.
ZW_TAGS="ZShield :|ZShieldCore:"

https_state_line() {
    local line
    line="$(log_grep "$ZW_TAGS" \
        | grep -oE "https filtering: (true|false) \(ca installed (true|false), [0-9]+ uids" \
        | tail -1)"
    if [ -n "$line" ]; then
        printf '%s\n' "$line"
        return 0
    fi
    # The log ring buffer wraps (and a device reboot clears it), so the line may simply be gone even
    # though the tunnel is up. Restarting the tunnel re-emits it, which makes this probe reliable
    # without needing a privileged read of the app's settings file (the release build is not
    # debuggable, so `run-as` is refused).
    if tunnel_up; then
        toggle_vpn; wait_tunnel down 60 >/dev/null 2>&1
        toggle_vpn; wait_tunnel up 90 >/dev/null 2>&1
        log_grep "$ZW_TAGS" \
            | grep -oE "https filtering: (true|false) \(ca installed (true|false), [0-9]+ uids" \
            | tail -1
    fi
}

#: Cached probe result, so one `status` call does not restart the tunnel twice.
_HTTPS_STATE_CACHE=""
_HTTPS_STATE_READ=0
https_state() {
    if [ "$_HTTPS_STATE_READ" = "1" ]; then
        printf '%s\n' "$_HTTPS_STATE_CACHE"
        return 0
    fi
    _HTTPS_STATE_CACHE="$(https_state_line)"
    _HTTPS_STATE_READ=1
    printf '%s\n' "$_HTTPS_STATE_CACHE"
}

#: Drop the cached probe. Every action that changes the tunnel or the setting calls this, otherwise
#: a script that both toggles and re-reads would report the state from before its own change.
forget_https_state() {
    _HTTPS_STATE_CACHE=""
    _HTTPS_STATE_READ=0
}

https_filtering_on() {
    https_state | grep -q "^https filtering: true"
}

# The CA's install state and fingerprint.
#
# Two sources, each for what it is good at:
#
# 1. **install state** — the core's `https filtering: <on/off> (ca installed <true/false>, <n> uids, …)`
#    line while a tunnel is up, because that is the *policy* fact the tunnel acts on and it costs one
#    ~2 s on-device grep. It only exists while the tunnel runs, which is why
#    `condition_zshield_https` starts the tunnel **before** asking; an earlier version asked first and
#    refused to start on a device whose CA *was* installed.
# 2. **fingerprint, and the install state when no tunnel is up** — the debug screen, whose line is
#    `根证书：指纹 7670780d… ｜ 到期 2036-11-10 ｜ 已安装：是`, rendered from
#    `CertManager.refreshInstalled`, which walks the whole user CA store. `docs/TESTING.md` §9.6 names
#    that as the authoritative answer because the Settings list has been seen to go stale.
#
# The screen read is a `uiautomator` dump — ~10 s each — so it happens at most once per process and
# only when a caller actually needs a screen-only field.
CA_UI_DUMP=""
CA_UI_READ=0
debug_screen_dump() {
    w_ "am start -n $PKG/.debug.DebugActivity" >/dev/null 2>&1
    sleep 2
    CA_UI_DUMP=""
    local attempt
    for attempt in 1 2 3; do
        w_ "rm -f /sdcard/zs-ui.xml" >/dev/null 2>&1
        w_ "uiautomator dump /sdcard/zs-ui.xml" >/dev/null 2>&1
        CA_UI_DUMP="$(sh_ "cat /sdcard/zs-ui.xml" 2>/dev/null | tr -d '\r')"
        printf '%s' "$CA_UI_DUMP" | grep -q '根证书：' && break
        # The active tab is the one whose label is *not* pushed forward — `开启 HTTPS 过滤` means the
        # tunnel is up, and the CA block sits above it. Either way the block is below the first
        # screenful at 1080x1920, so one downward swipe per attempt is what reveals it. The swipe stays
        # inside 30–80 % of the height: a gesture ending near the bottom edge is claimed by Android's
        # gesture navigation and sends the app to the launcher.
        swipe_vertical 80 30 400
        sleep 1
    done
    CA_UI_READ=1
}

#: Read the debug screen at most once per process; `status` asks for two fields and should pay for one
#: dump.
ca_refresh() {
    [ "$CA_UI_READ" = "1" ] || debug_screen_dump
}

ca_ui_field() {
    ca_refresh
    # `$1` is one of `指纹`, `已安装`; the value is what follows the label, either after a `：` or a
    # space. `｜` is U+FF5C, so the split is `sed`, not `tr` — `tr` works on bytes and mangles a
    # multibyte separator.
    printf '%s' "$CA_UI_DUMP" \
        | grep -oE '根证书：[^"]*' | head -1 \
        | sed 's/｜/\n/g' | grep -F "$1" | head -1 \
        | sed "s/.*$1[：: ]*//" | tr -d ' '
}

ca_installed() {
    if tunnel_up; then
        https_state | grep -q "ca installed true"
    else
        [ "$(ca_ui_field 已安装)" = "是" ]
    fi
}

#: The first 8 hex digits of the CA's SHA-256, the form every other tool on this project prints.
#:
#: Only the debug screen has it. It is not on the core's policy line, and the generation log entry
#: (`root CA generated: …`) is gone from the ring buffer once the app has been running for a while, so
#: the screen is the only reliable source — which is why this is the one field worth a dump.
ca_fingerprint() {
    ca_ui_field 指纹 | sed 's/…$//'
}

# ---------------------------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------------------------
# The browser whose traffic the HTTPS condition must decrypt.
#
# `org.lineageos.jelly` is the only client on this device that both trusts a user-installed CA and
# negotiates h2 (docs/TESTING.md §9.4b), so it is the browser every measurement uses. It is **not**
# in the shipped `assets/https/browsers.txt`, which is why the condition adds its uid through the
# app's documented `DEBUG_HTTPS_UIDS` seam — the same seam the M3a device test used, and the reason
# it exists. Without it the core reports `AppNotSelected` for every connection and decrypts nothing,
# which would make the "HTTPS filtering on" column identical to the "default" one.
MEASURE_BROWSER="${MEASURE_BROWSER:-org.lineageos.jelly}"

select_measure_browser_uid() {
    local uid
    uid="$(sh_ "dumpsys package $MEASURE_BROWSER | grep -oE 'appId=[0-9]+'" | head -1 | cut -d= -f2 | tr -d '\r')"
    if [ -z "$uid" ]; then
        echo "cannot read the uid of $MEASURE_BROWSER" >&2
        return 1
    fi
    say "selecting $MEASURE_BROWSER (uid $uid) for decryption"
    w_ "am broadcast -a $PKG.action.DEBUG_HTTPS_UIDS -n $RECEIVER --es uids $uid" >/dev/null
    # A fresh tunnel picks the uid set up from its config; a running one hot-reloads the policy, but
    # the auto-bypass table may still hold the host from a passthrough attempt, so it is cleared too.
    w_ "am broadcast -a $PKG.action.DEBUG_CLEAR_BYPASS -n $RECEIVER" >/dev/null
    sleep 2
    echo "  selected; bypass table cleared"
}

toggle_vpn() {
    w_ "am broadcast -a $PKG.action.DEBUG_TOGGLE_VPN -n $RECEIVER" >/dev/null
    forget_https_state
}

stop_vpn() {
    if tunnel_up; then
        say "stopping protection"
        toggle_vpn
        wait_tunnel down 60 || return 1
        echo "tunnel down"
    else
        echo "tunnel already down"
    fi
    # The app must not be left holding a foreground service either: a stopped tunnel with a live
    # service would keep renewing its state when the next scenario starts.
    local state
    state="$(protection_state)"
    echo "service state: $state"
}

start_vpn() {
    if ! tunnel_up; then
        say "starting protection"
        toggle_vpn
        wait_tunnel up 90 || return 1
        echo "tunnel up"
    else
        echo "tunnel already up"
    fi
}

# Toggling HTTPS filtering needs a UI tap: it is a setting the user owns, and there is no broadcast
# seam for it (by design — a shell-accessible switch that turns decryption on would be a security
# hole). The tap goes through the debug screen's own button, found by its label, so it exercises the
# same path the settings page does. The result is then confirmed from the core's log line rather than
# from the button's label, because the label only reflects the *setting*, not whether the policy
# actually reached the running tunnel.
set_https_filtering() {
    local want="$1"
    local current
    current="$(https_filtering_on && echo on || echo off)"
    echo "HTTPS filtering currently: $current (want $want)"
    if [ "$current" = "$want" ]; then
        return 0
    fi

    w_ "am start -n $PKG/.debug.DebugActivity" >/dev/null 2>&1
    sleep 2
    # The button sits below the fold on the device's current 1080x1920 override: a dump taken right
    # after the activity starts reports only the top of the ScrollView, so the label is simply absent.
    # Scrolling to the bottom and dumping again is what makes this deterministic — a fixed number of
    # swipes would depend on the display override another task may have set.
    local xml="" attempt
    for attempt in 1 2 3; do
        w_ "rm -f /sdcard/zs-ui.xml" >/dev/null 2>&1
        w_ "uiautomator dump /sdcard/zs-ui.xml" >/dev/null 2>&1
        xml="$(sh_ "cat /sdcard/zs-ui.xml" 2>/dev/null)"
        printf '%s' "$xml" | grep -qE 'text="(开启|关闭) HTTPS 过滤"' && break
        echo "  HTTPS filtering button not on screen yet; scrolling (attempt $attempt)"
        swipe_vertical 80 30 400
        sleep 1
    done
    local label
    label="$(printf '%s' "$xml" | grep -oE 'text="(开启|关闭) HTTPS 过滤"' | head -1 \
        | sed 's/text="//;s/"$//')"
    if [ -z "$label" ]; then
        echo "cannot find the HTTPS filtering button on the debug screen" >&2
        return 1
    fi
    local bounds
    bounds="$(printf '%s' "$xml" \
        | grep -oE "text=\"$label\"[^>]*bounds=\"\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]\"" \
        | grep -oE 'bounds="\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]"' | head -1 \
        | grep -oE '[0-9]+' | paste -sd' ')"
    if [ -z "$bounds" ]; then
        echo "cannot locate the HTTPS filtering button's bounds" >&2
        return 1
    fi
    # shellcheck disable=SC2086
    set -- $bounds
    echo "  tapping '$label' at $(( ($1 + $3) / 2 )),$(( ($2 + $4) / 2 ))"
    w_ "input tap $(( ($1 + $3) / 2 )) $(( ($2 + $4) / 2 ))"
    sleep 5
    forget_https_state

    # With no tunnel running there is no policy line to read, so the setting itself is the answer.
    if ! tunnel_up; then
        echo "  no tunnel running; the setting is applied when one starts"
        return 0
    fi
    local now
    now="$(https_filtering_on && echo on || echo off)"
    echo "HTTPS filtering now: $now ($(https_state))"
    [ "$now" = "$want" ]
}

#: One place that answers "do we have a credential to work with".
#:
#: A missing value is a refusal, not a fallback: guessing a credential on someone's phone is worse
#: than not installing the CA, and `locksettings set-pin <guess>` would replace whatever the operator
#: actually has.
require_test_pin() {
    case "$PIN" in
        *[!0-9]*) echo "ZSHIELD_TEST_PIN must contain only digits" >&2; return 1 ;;
        ?*) return 0 ;;
    esac
    cat >&2 <<'EOF'
condition.sh: this command needs a lock-screen credential, and none was supplied.

Android 11+ will not install a user CA without one. Pass your own through the environment:

    ZSHIELD_TEST_PIN=<your own test credential> LOCK_OWNER=<task> \
        scripts/effectiveness/condition.sh install-ca

There is no default and nothing was changed on the device. Use a credential you are willing to set
and clear on a test phone — not one that matters anywhere else.
EOF
    return 1
}

#: Device output is suppressed rather than relayed: `locksettings` echoes the argument it was given,
#: so `2>&1 | sed ...` would print the credential into the run transcript and every saved log.
set_pin() {
    require_test_pin || return 1
    say "setting a lock-screen credential (Android 11+ requires one to install a user CA)"
    if ! w_ "locksettings set-pin $PIN" >/dev/null 2>&1; then
        echo "  setting the credential failed; nothing else was changed" >&2
        return 1
    fi
    echo "  credential set"
}

clear_pin() {
    require_test_pin || return 1
    say "clearing the lock-screen credential"
    if ! w_ "locksettings clear --old $PIN" >/dev/null 2>&1; then
        echo "  clearing the credential failed" >&2
        return 1
    fi
    echo "  credential cleared"
}

install_test_lists() {
    say "installing the testcases.agrd.dev companion filter lists as user rules"
    local combined=".effectiveness/results/agrd-test-lists.txt"
    mkdir -p .effectiveness/results
    : >"$combined"
    local base="https://testcases.agrd.dev"
    while IFS=$'\t' read -r key path; do
        [ -n "$key" ] || continue
        local url="$base/$path" body
        body="$(curl -sS --max-time 30 "$url" 2>/dev/null)"
        if [ -z "$body" ]; then
            echo "  MISSING  $key ($url)" >&2
            continue
        fi
        {
            printf '! === %s (%s)\n' "$key" "$url"
            printf '%s\n' "$body"
        } >>"$combined"
        echo "  appended $key ($(printf '%s' "$body" | wc -l) lines)"
    done <<'PAGES'
element-hiding	Filters/element-hiding-rules/test-element-hiding-rules.txt
generichide	Filters/generichide-rules/generichide-rules.txt
css-rules	Filters/css-rules/css-rules.txt
extended-css	Filters/extended-css-rules/test-extended-css-rules.txt
scriptlets	Filters/scriptlet-rules/test-scriptlet-rules.txt
important	Filters/important-rules/test-important-rules.txt
badfilter	Filters/badfilter-rules/test-badfilter-rules.txt
network-rules	Filters/network-rules/test-network-rules.txt
redirect	Filters/redirect-rules/test-redirect-rules.txt
csp	Filters/csp-rules/test-csp-rules.txt
removeparam	Filters/removeparam-rules/test-removeparam-rules.txt
removeheader	Filters/removeheader-rules/test-removeheader-rules.txt
advanced-domain	Filters/advanced-domain-modifier/test-advanced-domain-modifier.txt
subdocument	Filters/subdocument-rules/test-subdocument-rules.txt
PAGES
    local rules
    rules="$(cat "$combined")"
    echo "  total $(printf '%s' "$rules" | wc -l) lines"
    # The install goes through `rules_backup.py install`, which is the **same** code the restore uses.
    #
    # `adb shell` runs its argument through the device's own `sh`, which re-parses `|`, `*`, `(`, `)`
    # and `'` — and filter rules are full of them (`$domain=a|b`, `*$script`, `##.a:style(width: 1px)`).
    # An earlier version passed the blob inline and the device shell mangled it into "inaccessible or
    # not found" for exactly those lines, silently installing a *different* rule set. Pushing the file
    # and reading it on the device with `"$(cat …)"` keeps every byte except the trailing newlines;
    # `rules_backup.py` closes that last gap with a sentinel, and having one implementation means the
    # install and the restore cannot disagree about what "the same bytes" means.
    if ! python3 "$(dirname "${BASH_SOURCE[0]}")/rules_backup.py" install --from "$combined" \
            --serial "$SERIAL" --package "$PKG"; then
        echo "  the rule broadcast did not complete" >&2
        return 1
    fi
    sleep 10
    echo "  broadcast sent; waiting for the hot reload"
    return 0
}

clear_test_lists() {
    say "clearing the user rules"
    # Clearing is the one install whose text is known to be empty, so it needs no file: an empty `--es`
    # value is unambiguous, and `rules_backup.py install` would only add a round trip. It still goes
    # through `w_`, so a lost lease refuses it like any other write.
    w_ "am broadcast -a $PKG.action.DEBUG_SET_RULES -n $RECEIVER --es rules ''" >/dev/null || return 1
    sleep 5
}

export_ca() {
    say "exporting the app's CA to Downloads"
    w_ "am start -n $PKG/.debug.DebugActivity" >/dev/null 2>&1
    sleep 2
    # The button is below the fold; the same retry-with-scroll loop the CA line uses applies.
    local bounds="" attempt
    for attempt in 1 2 3 4 5; do
        w_ "rm -f /sdcard/zs-ui.xml" >/dev/null 2>&1
        w_ "uiautomator dump /sdcard/zs-ui.xml" >/dev/null 2>&1
        bounds="$(sh_ "cat /sdcard/zs-ui.xml" 2>/dev/null \
            | grep -oE 'text="导出证书到「下载」"[^>]*bounds="\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]"' \
            | grep -oE 'bounds="\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]"' | grep -oE '[0-9]+' | paste -sd' ')"
        [ -n "$bounds" ] && break
        swipe_vertical 80 30 400
        sleep 1
    done
    if [ -z "$bounds" ]; then
        echo "  export button not found; is the CA generated?" >&2
        return 1
    fi
    # shellcheck disable=SC2086
    set -- $bounds
    w_ "input tap $(( ($1 + $3) / 2 )) $(( ($2 + $4) / 2 ))"
    sleep 3
    sh_ "ls /sdcard/Download/ | grep ZShield-CA" 2>&1 | sed 's/^/  /'
}

# ---------------------------------------------------------------------------------------------
# Backing up and restoring the state a condition changes
#
# Every condition run changes things the user owns: the `$removeparam` rules a caller installs, the
# HTTPS-filtering switch, whether the tunnel is up. The stage-2 review found rule changes left
# installed after a run, which means the next measurement started from someone else's rule set and
# nobody could tell. So a run takes a backup first and restores it on the way out — including when it
# fails, which is what the `trap` in `main` is for.
#
# What can and cannot be read back:
#
#   * the **user rules** are app-private (`files/…`, release build, `run-as` refused). The only
#     readable copy is the debug screen's 「自定义规则：…」 line, which is what `backup` parses. When
#     that line cannot be read the backup records `rules=unavailable` and `restore` refuses to touch
#     the rules rather than clearing a set it never saw — clearing would be the destructive guess.
#   * the **tunnel and HTTPS filtering** state are probed directly (`tunnel_up`, `https_state`).
# ---------------------------------------------------------------------------------------------
BACKUP_DIR="${OUT:-.effectiveness/results}"
BACKUP_LABEL="${LOCK_OWNER:-unowned}"
#: Where `rules_backup.py` writes the captured rule set for this label.
RULES_BACKUP="$BACKUP_DIR/rules-${BACKUP_LABEL}.json"
backup_file() { printf '%s/condition-backup-%s.txt' "$BACKUP_DIR" "$BACKUP_LABEL"; }

backup_state() {
    mkdir -p "$BACKUP_DIR"
    local file; file="$(backup_file)"
    local tunnel https rules_ok=0
    # The rules come from `rules_backup.py`, which reads the **rules editor's** text field: that is the
    # only surface that carries the raw text, so empty, whitespace-only and a set that literally is
    # `（空）` stay distinct and trailing newlines survive. The diagnostics screen cannot do that, which
    # is why it is no longer the source.
    #
    # A failed or ambiguous read makes the whole backup fail — non-zero, and recorded as unreadable in
    # the file so a later `restore` refuses too. It used to be recorded as `known: false` and then the
    # caller carried on with `|| true`: `apply-test-lists` overwrote the user's rules and exited 0
    # while saying "user rules NOT restored". An unreadable original is a reason to stop *before* any
    # write, not a note to attach to the overwrite.
    # `python3 … | sed …` returns **sed's** status, so a failed capture read as success. The capture
    # runs on its own, its output is indented afterwards, and its status is the one that decides.
    local capture_out
    if capture_out="$(python3 "$(dirname "${BASH_SOURCE[0]}")/rules_backup.py" capture \
            --out "$RULES_BACKUP" --serial "$SERIAL" --package "$PKG" 2>&1)"; then
        printf '%s\n' "$capture_out" | sed 's/^/  /'
        rules_ok=1
        cp "$RULES_BACKUP" "$file.rules.json" 2>/dev/null || rules_ok=0
    else
        printf '%s\n' "$capture_out" | sed 's/^/  /' >&2
    fi
    if [ "$rules_ok" = 0 ]; then
        printf '{"known": false}\n' >"$file.rules.json"
        # Stop here, before probing the tunnel or the HTTPS switch. Those probes are not side-effect
        # free — `https_state` restarts the tunnel to re-emit its log line when the ring buffer has
        # wrapped — and a run that has already decided not to touch the device must not touch it while
        # recording why. The other fields are marked unknown rather than guessed.
        printf 'rules_backup=%s\nrules_known=0\ntunnel=unknown\nhttps=unknown\nlabel=%s\nat=%s\n' \
            "$file.rules.json" "$BACKUP_LABEL" "$(date -Iseconds)" >"$file"
        echo "backup: $file (rules UNAVAILABLE — the original rule set could not be read)" >&2
        echo "$file" >&2
        return 1
    fi
    tunnel="$(tunnel_up && echo up || echo down)"
    https="$(https_filtering_on && echo on || echo off)"
    printf 'rules_backup=%s\nrules_known=1\ntunnel=%s\nhttps=%s\nlabel=%s\nat=%s\n' \
        "$file.rules.json" "$tunnel" "$https" "$BACKUP_LABEL" "$(date -Iseconds)" >"$file"
    echo "backup: $file (rules captured, tunnel $tunnel, https $https)"
    echo "$file"
    return 0
}

restore_state() {
    local file; file="$(backup_file)"
    RESTORE_FAILED=0
    if [ ! -f "$file" ]; then
        echo "restore: no backup at $file; nothing is changed (a restore without a backup would be a guess)" >&2
        return 0
    fi
    say "restoring the state recorded in $file"
    local rules_json tunnel https
    rules_json="$(sed -n 's/^rules_backup=//p' "$file" | head -1)"
    tunnel="$(sed -n 's/^tunnel=//p' "$file" | head -1)"
    https="$(sed -n 's/^https=//p' "$file" | head -1)"

    # Rules first, through `rules_backup.py`: it verifies the restore by **re-reading** the editor,
    # comparing the exact text (trailing newlines and all), so "restored" is an observation rather than
    # a hope. A backup it recorded as unreadable is refused there too, which is the case that must
    # never clear a rule set this run never saw.
    if ! lock_require; then
        # No write at all: either the lease is gone (the phone may belong to another task now, so
        # restoring would overwrite whatever that task installed) or this process never held it.
        echo "  user rules NOT restored — this run does not hold the device lock;" >&2
        echo "  $rules_json still holds the original set, and no device write was attempted." >&2
        RESTORE_FAILED=1
    elif [ -n "$rules_json" ] && [ -f "$rules_json" ]; then
        if python3 "$(dirname "${BASH_SOURCE[0]}")/rules_backup.py" restore --from "$rules_json" \
                --serial "$SERIAL" --package "$PKG"; then
            echo "  user rules restored and verified"
        else
            echo "  user rules NOT restored — see the message above; $rules_json is what was there" >&2
            RESTORE_FAILED=1
        fi
    else
        echo "  user rules NOT restored: no backup file was recorded, and clearing a set this run"
        echo "  never saw would be the destructive guess." >&2
        RESTORE_FAILED=1
    fi

    if [ "$https" = "on" ]; then set_https_filtering on >/dev/null 2>&1 || true; else set_https_filtering off >/dev/null 2>&1 || true; fi
    if [ "$tunnel" = "up" ]; then start_vpn >/dev/null 2>&1 || true; else stop_vpn >/dev/null 2>&1 || true; fi
    echo "  tunnel:    $(tunnel_up && echo up || echo down) (backup said ${tunnel:-unknown})"
    echo "  https:     $(https_filtering_on && echo on || echo off) (backup said ${https:-unknown})"
    return "$RESTORE_FAILED"
}

#: Installed by `main` once a backup exists, so an error exit restores as well as a clean one.
#:
#:   RESTORE_ON_EXIT=error  restore only when the command failed (a condition is *meant* to leave
#:                          the device in a new state; an error must not leave a half-applied one);
#:   RESTORE_ON_EXIT=always restore whatever happened (rule installation is instrumentation, and the
#:                          stage-2 review found a probe rule left installed after a run).
RESTORE_ON_EXIT=""
LAST_STATUS=0
#: Set when this process actually took the lock, so the exit trap releases only what it holds. A
#: `cleanup` run that never took the lock must not even attempt a release: it has no owner, and the
#: attempt would be a delete of somebody else's file dressed up as bookkeeping.
LOCK_HELD=0
#: Set by `lock-take`, whose whole point is to leave the lock behind for the commands that follow.
LOCK_KEEP=0
#: Guards against the trap re-entering itself: `exit` from inside an EXIT trap runs the trap again.
EXITING=0

#: The one exit path. **Ends the process.**
#:
#: `return` from an EXIT trap does not change the shell's exit status — the status the shell was
#: already going to exit with wins. So a handler that noticed "the rules were not restored" or "the
#: renewer could not be reaped" and merely `return 1`-ed still exited 0, which is how a failed restore
#: could look like success. The final status is therefore accumulated explicitly and passed to `exit`.
on_exit() {
    local code=$?
    [ "$EXITING" = 1 ] && return 0
    EXITING=1
    # Nothing else may fire while this runs, so a trapped signal cannot re-enter it.
    trap - EXIT INT TERM HUP
    LAST_STATUS="$code"
    if [ "$RESTORE_ON_EXIT" = "always" ] || { [ "$RESTORE_ON_EXIT" = "error" ] && [ "$code" != "0" ]; }; then
        RESTORE_ON_EXIT=""   # one restore, whatever else fails on the way out
        # A restore that could not put the rules back makes the exit non-zero, even when the command
        # itself "succeeded": the user's rule set is the thing that must not be lost silently.
        restore_state || code=1
    fi
    lock_stop_renewer || code=$(( code == 0 ? 1 : code ))
    if [ "$LOCK_HELD" = "1" ] && [ "$LOCK_KEEP" != "1" ]; then
        lock_release || true
    fi
    LAST_STATUS="$code"
    exit "$code"
}
trap on_exit EXIT
# A signal must run the same restore path as a clean exit, and must be **non-zero**. `exit` from the
# signal trap makes the EXIT trap compute the final status, so `on_exit` runs exactly once (guarded by
# `EXITING`) and the process reports the failure rather than whatever the interrupted command left.
for _signal in INT TERM HUP; do
    # shellcheck disable=SC2064  # the trap is meant to see this process's own state
    trap "exit 130" "$_signal"
done

# ---------------------------------------------------------------------------------------------
# Conditions
# ---------------------------------------------------------------------------------------------
condition_vpn_off() {
    say "condition: vpn-off"
    set_https_filtering off || true
    stop_vpn
    echo
    echo "tunnel:   $(tunnel_up && echo up || echo down)"
    echo "https:    $(https_filtering_on && echo on || echo off)"
}

condition_zshield_default() {
    say "condition: zshield-default (tunnel up, HTTPS filtering off)"
    set_https_filtering off || true
    start_vpn
    echo
    echo "tunnel:   $(tunnel_up && echo up || echo down)"
    echo "https:    $(https_filtering_on && echo on || echo off)"
}

condition_zshield_https() {
    say "condition: zshield-https (tunnel up, HTTPS filtering on + CA installed)"
    # The tunnel is started **before** the CA is checked: the authoritative answer to "is the CA
    # installed" is the core's `https filtering: … (ca installed …)` line, and the core only prints it
    # while it is running.
    start_vpn
    if ! ca_installed; then
        echo "the app's CA is not installed; this condition needs it." >&2
        echo "run: scripts/effectiveness/condition.sh install-ca" >&2
        return 1
    fi
    set_https_filtering on || return 1
    # A policy change only takes effect for new connections, so the tunnel is rebuilt; the uid set is
    # re-applied after the restart because the fresh tunnel reads its config from the settings file,
    # which the debug seam does not write.
    stop_vpn
    start_vpn
    select_measure_browser_uid || return 1
    echo
    echo "tunnel:   $(tunnel_up && echo up || echo down)"
    echo "https:    $(https_filtering_on && echo on || echo off)"
    echo "ca:       $(ca_fingerprint)"
    echo "state:    $(https_state)"
}

cleanup() {
    say "cleanup"
    # Cleanup writes to the device, so it needs the device. It used to take nothing and check nothing:
    # with a live canonical lock naming another task, it still broadcast `DEBUG_SET_RULES ''`,
    # force-stopped the app and exited 0. Taking the lock here means the whole teardown is one owned
    # transaction; a live lock belonging to somebody else is refused before the first write.
    if ! take_lock; then
        echo "not cleaning up: the device is not this run's to change" >&2
        return 1
    fi
    local status=0
    set_https_filtering off || status=1
    stop_vpn || status=1
    # The rule set is **not** cleared here. `cleanup` used to send `DEBUG_SET_RULES ''`, which is the
    # destructive guess: it deletes whatever rules are installed, including a set this run restored (or
    # a set it never saw). What this run changed is put back from its own backup, and nothing else.
    if [ -f "$(backup_file)" ]; then
        restore_state || status=1
    else
        echo "  user rules: left as they are (this run recorded no backup to put back)"
    fi
    w_ "am force-stop $PKG" >/dev/null 2>&1 || status=1
    echo "  app force-stopped"
    # The lock is released by the exit trap, and only when it is this run's. Doing it twice is
    # harmless; doing it unconditionally (as the previous version did) could delete another task's
    # lock, which is how two runs end up sharing the device.
    echo
    echo "NOT done automatically (they need on-device UI, see docs/TESTING.md §9.5):"
    echo "  - remove the ZShield CA from Settings → Security → Encryption & credentials →"
    echo "    Trusted credentials → User tab"
    echo "  - clear the lock screen PIN if one was set for the install"
    return "$status"
}

usage() {
    cat >&2 <<'EOF'
usage: [LOCK_OWNER=<task-id>] scripts/effectiveness/condition.sh <command> [--issue <task-id>]
                                                                      [--renew <seconds>]

The device lock needs an owner. Pass it as LOCK_OWNER or --issue; there is no default, because a
default owner reads as "mine" to every run and disables the lock. A lock older than LOCK_TTL
(default 7200 s) is stale and may be taken over; `renew` refreshes this run's stamp, which a long
measurement does every LOCK_RENEW (default 1800 s).

commands:
  vpn-off             protection off (baseline)
  zshield-default     tunnel up, HTTPS filtering off
  zshield-https       tunnel up, HTTPS filtering on (requires the CA installed)
  install-ca          set the lock-screen credential (ZSHIELD_TEST_PIN), export the CA,
                      and open the credentials settings page
  apply-test-lists    install the testcases.agrd.dev companion filter lists (restored on exit)
  clear-test-lists    remove the user rules
  backup              record the user rules and the tunnel/HTTPS state to a restore file
  restore             put back what `backup` recorded (refuses to touch rules it could not read)
  lock-take           take the device lock and leave it held for the commands that follow
  lock-release        release this run's lock (a foreign lock is never removed)
  renew               refresh this run's lock stamp (for a long measurement)
  status              print what the device is currently doing, including the lock's validity
  cleanup             stop everything; releases the lock only if this run owns it

A condition command backs the state up first and restores it if it fails, so a failed run cannot
leave a half-applied configuration behind.
EOF
}

status() {
    echo "serial:      $SERIAL"
    echo "tunnel:      $(tunnel_up && echo up || echo down)"
    echo "service:     $(protection_state)"
    echo "https:       $(https_filtering_on && echo on || echo off)"
    echo "ca:          $(ca_fingerprint)"
    # The lock is reported with its remaining validity, and it is the *only* answer to "may I use
    # this device": the tunnel being up says nothing about whether another task holds the phone,
    # which is the inference the stage-2 review had to correct.
    echo "lock:        $(lock_status)"
    echo "lock screen: $(sh_ "dumpsys window | grep -c mDreamingLockscreen=true" | tr -d '\r') (1 = locked)"
    echo
    echo "note: a lock held by another task means the device is not yours to use, whatever the tunnel"
    echo "      state says; an expired lock may be taken over by the next run."
}

main() {
    # `--issue <task-id>` is the other spelling of `LOCK_OWNER`; the flag is what the acceptance
    # script prints, so an operator copying a command always carries the owner with it.
    local command="" arg issue=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --issue) shift; issue="${1:-}" ;;
            --issue=*) issue="${1#--issue=}" ;;
            --renew) shift 2>/dev/null; LOCK_RENEW="${1:-$LOCK_RENEW}" ;;
            --renew=*) LOCK_RENEW="${1#--renew=}" ;;
            -h|--help) usage; exit 0 ;;
            *) [ -z "$command" ] && command="$1" || { echo "unexpected argument: $1" >&2; exit 2; } ;;
        esac
        shift
    done
    if [ -n "$issue" ]; then
        LOCK_OWNER="$issue"
    fi
    case "$command" in
        vpn-off|zshield-default|zshield-https)
            take_lock || exit 1
            # The backup is a **precondition**, not a note: `|| true` here is what let a failed capture
            # be followed by a write. Nothing is changed on the device when it fails, and the exit is
            # non-zero so the caller cannot mistake the run for a clean one.
            if ! backup_state; then
                echo "the current user rules could not be read, so this command will not change them." >&2
                echo "nothing on the device was changed." >&2
                exit 1
            fi
            RESTORE_ON_EXIT=error
            "condition_${command//-/_}" ;;
        install-ca)
            require_test_pin || exit 1
            take_lock || exit 1
            # Refused before the CA is exported when no credential was supplied: exporting a CA that
            # cannot be installed would leave the device holding a certificate nobody can trust.
            if ! set_pin; then
                exit 1
            fi
            export_ca || exit 1
            say "opening Settings → trusted credentials for the install"
            w_ "am start -a android.settings.SECURITY_SETTINGS" >/dev/null 2>&1
            echo "install it by hand: 安全与隐私 → 更多安全与隐私 → 加密与凭据 → 安装证书 → CA 证书 →"
            echo "  「仍然安装」→ 输入你设置的锁屏凭据（\$ZSHIELD_TEST_PIN）→ 选择 /sdcard/Download/ZShield-CA-*.crt → Select"
            echo "then verify with: scripts/effectiveness/condition.sh status" ;;
        apply-test-lists)
            take_lock || exit 1
            # Same precondition, and here it matters most: this command *is* a rule overwrite, so an
            # unreadable original means the overwrite would be unrecoverable. It used to proceed and
            # exit 0 while reporting "user rules NOT restored".
            if ! backup_state; then
                echo "the current user rules could not be read, so this run will not replace them." >&2
                echo "nothing on the device was changed." >&2
                exit 1
            fi
            RESTORE_ON_EXIT=always
            install_test_lists ;;
        clear-test-lists)
            take_lock || exit 1
            clear_test_lists ;;
        restore)
            # `restore` writes, so it needs the lock like every other write. Without it, a run with no
            # token at all could overwrite whoever holds the phone — and `restore_state` reports that
            # as a failure rather than pretending it restored anything.
            take_lock || exit 1
            restore_state || exit 1 ;;
        backup)
            backup_state ;;
        # `lock-take` / `lock-release` exist because the lock must outlive the process that takes it:
        # a measurement runs as several commands (condition, harness, snapshot poll), and a lock that
        # was released at the end of the first one would leave the device unguarded for the rest.
        lock-take)
            LOCK_KEEP=1
            take_lock || exit 1 ;;
        lock-release)
            # `lock_release` only acts when this process's token is in the lock, so this cannot delete
            # a lock another run took over. `LOCK_HELD=1` here would be wrong: this process did not
            # take it, and the release must still be attempted because the *token* is what authorises
            # it — for `lock-take` followed by `lock-release` the token matches by construction.
            lock_release ;;
        renew|renew-lock)
            lock_renew || exit 1 ;;
        status) status ;;
        cleanup) cleanup ;;
        *) usage ; exit 2 ;;
    esac
}

main "$@"
