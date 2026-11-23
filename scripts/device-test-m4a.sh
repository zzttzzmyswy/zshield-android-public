#!/usr/bin/env bash
# M4a device test driver (docs/TESTING.md §11).
#
# Runs the DESIGN §7 scenarios that can be produced without severing the Wi-Fi adb link, and writes
# one evidence file per scenario under $OUT. Every step prints the command it ran, so the transcript
# is the report.
#
# Usage: scripts/device-test-m4a.sh <scenario...>
#   scenarios: install intent doze bucket kill boot-upgrade boot-no-alwayson network tile energy cleanup
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# The device is resolved once, centrally: an explicit `SERIAL` wins, otherwise exactly one attached
# device, otherwise a refusal. No default address belongs in a repository.
# shellcheck source=effectiveness/device-serial.sh
. scripts/effectiveness/device-serial.sh
require_serial
SERIAL="$RESOLVED_SERIAL"
export SERIAL

PKG=top.zztweb.zshield
# The APK is the one `scripts/build.sh release` just produced for the current `version.properties`,
# so this driver cannot silently install a version from three releases ago.
VERSION_NAME="$(grep -E '^versionName=' version.properties | head -1 | cut -d= -f2 | tr -d '[:space:]')"
APK="${APK:-dist/zshield-${VERSION_NAME}-release.apk}"
OUT="${OUT:-/tmp/m4a-evidence}"
LOCK=/data/local/tmp/zshield-device.lock
RECEIVER="$PKG/.filters.DebugCommandReceiver"
SUICIDE="$PKG/.vpn.RecoveryTestReceiver"

mkdir -p "$OUT"

d() { adb -s "$SERIAL" "$@"; }
sh_() { adb -s "$SERIAL" shell "$@"; }
say() { printf '\n=== %s\n' "$*"; }
# Every scenario writes a transcript; `run` echoes the command and appends its output.
run() {
    printf '\n$ adb shell %s\n' "$*" >>"$LOG"
    adb -s "$SERIAL" shell "$*" 2>&1 | tee -a "$LOG"
}
# The logcat buffer holds everything since the device booted, so a scenario's evidence is filtered
# to the lines that mention our own tags. `-T` (since-time) is not portable across the platform's
# `logcat` builds, so the scenario start time is compared as a string instead.
LOG_SINCE=""
mark_log_start() {
    adb -s "$SERIAL" logcat -c
    LOG_SINCE="$(adb -s "$SERIAL" shell date +%H:%M:%S | tr -d '\r')"
}
logcat_since_clear() {
    adb -s "$SERIAL" logcat -d -b all 2>/dev/null \
        | grep -E "ZShield : |Established by $PKG|Scheduling restart|Start proc .*$PKG|am_proc_died.*$PKG|am_foreground_service_(start|stop).*$PKG|restore after" \
        | awk -v since="$LOG_SINCE" '
            { t = $2 }
            # Keep the line when its HH:MM:SS is at or after the mark; a plain string compare works
            # within one hour, which is all a scenario needs.
            since == "" || t >= since
        ' | tail -60
}

lock_owner() { sh_ "cat $LOCK 2>/dev/null" | tr -d '\r'; }
lock_take() {
    local owner
    owner="$(lock_owner)"
    if [ -n "$owner" ] && [ "${owner%% *}" != "MYS-2729" ]; then
        echo "device is locked by: $owner" >&2
        return 1
    fi
    sh_ "echo 'MYS-2729 $(date -Iseconds)' > $LOCK"
}
lock_release() { sh_ "rm -f $LOCK"; }

# adb here runs over Wi-Fi, so a reboot drops the transport. `persist.adb.tcp.port=5555` makes adbd
# listen again once the device is up, but the host has to reconnect explicitly — `wait-for-device`
# alone would wait for a transport that never comes back on its own.
wait_after_reboot() {
    local waited=0
    sleep 20
    while [ "$waited" -lt 300 ]; do
        adb connect "$SERIAL" >/dev/null 2>&1
        if adb -s "$SERIAL" shell true >/dev/null 2>&1; then
            echo "device back after $((waited + 20))s"
            # The boot broadcast fires during boot; give the app a moment to be started by it.
            sleep 30
            return 0
        fi
        sleep 10
        waited=$((waited + 10))
    done
    echo "device did NOT come back within $((waited + 20))s"
    return 1
}

toggle_on() {
    sh_ "am broadcast -a $PKG.action.DEBUG_TOGGLE_VPN -n $RECEIVER" >/dev/null
}

wait_tunnel() {
    local timeout="${1:-60}" waited=0
    while [ "$waited" -lt "$timeout" ]; do
        if sh_ "dumpsys connectivity" 2>/dev/null | grep -q "IS_VPN"; then
            echo "tunnel up after ${waited}s"
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done
    echo "tunnel did NOT come up within ${timeout}s"
    return 1
}

blocked_now() {
    # A blocked name is answered with 127.0.0.1 by the core's default ZERO_IP response.
    sh_ "ping -c 1 -W 2 doubleclick.net" 2>&1 | head -2
}

# ---------------------------------------------------------------------------------------------
scenario_install() {
    LOG="$OUT/00-install.log"; : >"$LOG"
    say "install $APK"
    d install -r "$APK" 2>&1 | tee -a "$LOG"
    run "dumpsys package $PKG | grep -E 'versionName|lastUpdateTime'"
    run "dumpsys jobscheduler | grep -c $PKG/.vpn.KeepAliveJobService"
}

scenario_intent() {
    LOG="$OUT/01-intent.log"; : >"$LOG"
    say "user turns protection on: intent recorded, tunnel up"
    mark_log_start
    toggle_on
    wait_tunnel 90
    logcat_since_clear | tail -20 | tee -a "$LOG"
    run "ping -c 1 -W 2 doubleclick.net"

    say "user turns protection off: intent cleared, no recovery afterwards"
    mark_log_start
    toggle_on   # toggles off
    sleep 3
    run "dumpsys activity services $PKG"
    sh_ "am broadcast -a $PKG.action.DEBUG_KEEPALIVE_CHECK -n $SUICIDE" >/dev/null 2>&1 || true
    logcat_since_clear | tail -20 | tee -a "$LOG"
}

scenario_kill() {
    LOG="$OUT/03-kill.log"; : >"$LOG"
    say "make sure the tunnel is up and the intent is on"
    if ! sh_ "dumpsys connectivity" | grep -q IS_VPN; then toggle_on; wait_tunnel 90; fi
    run "pidof $PKG"

    say "SIGKILL the process, then time the recovery"
    mark_log_start
    local t0 t1
    t0=$(date +%s%3N)
    sh_ "am broadcast -a $PKG.action.DEBUG_SUICIDE -n $SUICIDE" >/dev/null
    local waited=0
    while [ "$waited" -lt 120 ]; do
        if sh_ "dumpsys connectivity" 2>/dev/null | grep -q "IS_VPN" \
            && sh_ "dumpsys activity services $PKG" 2>/dev/null | grep -q "isForeground=true"; then
            break
        fi
        sleep 1
        waited=$((waited + 1))
    done
    t1=$(date +%s%3N)
    echo "recovery took $((t1 - t0)) ms (polling granularity 1 s)" | tee -a "$LOG"
    logcat_since_clear | tee -a "$LOG"
    run "dumpsys activity services $PKG | grep -E 'isForeground|startRequested|restartCount'"
    blocked_now | tee -a "$LOG"
}

scenario_bucket() {
    LOG="$OUT/02-bucket.log"; : >"$LOG"
    say "restricted standby bucket: service stays, tunnel keeps filtering"
    if ! sh_ "dumpsys connectivity" | grep -q IS_VPN; then toggle_on; wait_tunnel 90; fi
    run "am set-standby-bucket $PKG restricted"
    run "am get-standby-bucket $PKG"
    sleep 5
    run "dumpsys activity services $PKG | grep -E 'isForeground|startRequested'"
    blocked_now | tee -a "$LOG"
    run "am set-standby-bucket $PKG active"
}

scenario_doze() {
    LOG="$OUT/01-doze.log"; : >"$LOG"
    local minutes="${DOZE_MINUTES:-30}"
    say "force-idle, wait ${minutes} min, then check filtering"
    if ! sh_ "dumpsys connectivity" | grep -q IS_VPN; then toggle_on; wait_tunnel 90; fi
    blocked_now | tee -a "$LOG"
    run "dumpsys battery unplug"
    run "dumpsys deviceidle force-idle"
    run "dumpsys deviceidle get deep"
    local elapsed=0
    while [ "$elapsed" -lt $((minutes * 60)) ]; do
        sleep 60
        elapsed=$((elapsed + 60))
        # The lock is refreshed every 30 minutes during a long run (AGENTS.md).
        if [ $((elapsed % 1800)) -eq 0 ]; then lock_take; fi
        echo "  ${elapsed}s / $((minutes * 60))s idle" | tee -a "$LOG"
    done
    run "dumpsys deviceidle get deep"
    run "dumpsys activity services $PKG | grep -E 'isForeground'"
    blocked_now | tee -a "$LOG"
    run "dumpsys deviceidle unforce"
    run "dumpsys battery reset"
}

scenario_network() {
    LOG="$OUT/06-network.log"; : >"$LOG"
    say "network change that does not sever adb: same AP, forced re-association"
    if ! sh_ "dumpsys connectivity" | grep -q IS_VPN; then toggle_on; wait_tunnel 90; fi
    blocked_now | tee -a "$LOG"
    run "cmd wifi status"
    # `cmd wifi reassociate` drops and re-establishes the same SSID; adb-over-Wi-Fi survives it.
    run "cmd wifi reassociate"
    sleep 15
    run "cmd wifi status"
    wait_tunnel 90 | tee -a "$LOG"
    blocked_now | tee -a "$LOG"
    logcat_since_clear | tail -20 | tee -a "$LOG"
}

scenario_upgrade() {
    LOG="$OUT/05-upgrade.log"; : >"$LOG"
    say "in-place upgrade: MY_PACKAGE_REPLACED restores the tunnel"
    if ! sh_ "dumpsys connectivity" | grep -q IS_VPN; then toggle_on; wait_tunnel 90; fi
    mark_log_start
    d install -r "$APK" 2>&1 | tee -a "$LOG"
    sleep 20
    logcat_since_clear | tee -a "$LOG"
    run "dumpsys activity services $PKG | grep -E 'isForeground|startRequested'"
    blocked_now | tee -a "$LOG"
}

scenario_boot_no_alwayson() {
    LOG="$OUT/04a-boot-no-alwayson.log"; : >"$LOG"
    say "always-on OFF: BOOT_COMPLETED restores the tunnel"
    run "settings get secure always_on_vpn_app"
    if ! sh_ "dumpsys connectivity" | grep -q IS_VPN; then toggle_on; wait_tunnel 90; fi
    mark_log_start
    say "rebooting"
    d reboot 2>&1 | tee -a "$LOG"
    wait_after_reboot | tee -a "$LOG"
    logcat_since_clear | tee -a "$LOG"
    run "dumpsys activity services $PKG | grep -E 'isForeground|startRequested'"
    blocked_now | tee -a "$LOG"
}

scenario_boot_alwayson() {
    LOG="$OUT/04b-boot-alwayson.log"; : >"$LOG"
    say "always-on ON: the system brings the tunnel up; the app steps aside"
    run "settings put secure always_on_vpn_app $PKG"
    run "settings put secure always_on_vpn_lockdown 0"
    run "settings get secure always_on_vpn_app"
    if ! sh_ "dumpsys connectivity" | grep -q IS_VPN; then toggle_on; wait_tunnel 90; fi
    mark_log_start
    d reboot 2>&1 | tee -a "$LOG"
    wait_after_reboot | tee -a "$LOG"
    logcat_since_clear | tee -a "$LOG"
    run "dumpsys activity services $PKG | grep -E 'isForeground|startRequested'"
    blocked_now | tee -a "$LOG"
    run "settings delete secure always_on_vpn_app"
}

scenario_tile() {
    LOG="$OUT/07-tile.log"; : >"$LOG"
    say "tile is registered, and the service it drives responds"
    run "cmd statusbar expand-settings"
    sleep 2
    run "dumpsys qs"
    run "cmd statusbar collapse"
    say "component check"
    run "dumpsys package $PKG | grep -c ZShieldTileService"
}

scenario_energy() {
    LOG="$OUT/08-energy.log"; : >"$LOG"
    local minutes="${ENERGY_MINUTES:-60}"
    say "screen-off soak for ${minutes} min, then batterystats for $PKG"
    if ! sh_ "dumpsys connectivity" | grep -q IS_VPN; then toggle_on; wait_tunnel 90; fi
    run "dumpsys batterystats --reset"
    run "input keyevent KEYCODE_SLEEP"
    local elapsed=0
    while [ "$elapsed" -lt $((minutes * 60)) ]; do
        sleep 60
        elapsed=$((elapsed + 60))
        if [ $((elapsed % 1800)) -eq 0 ]; then lock_take; fi
        echo "  ${elapsed}s / $((minutes * 60))s asleep" | tee -a "$LOG"
    done
    run "input keyevent KEYCODE_WAKEUP"
    d shell "dumpsys batterystats $PKG" >"$OUT/08-energy-batterystats.txt" 2>&1
    grep -E "Wake lock|wake|CPU|Estimated power" "$OUT/08-energy-batterystats.txt" | head -40 | tee -a "$LOG"
    run "dumpsys activity services $PKG | grep -E 'isForeground'"
}

scenario_cleanup() {
    LOG="$OUT/09-cleanup.log"; : >"$LOG"
    say "restore device state"
    run "dumpsys deviceidle unforce"
    run "dumpsys battery reset"
    run "am set-standby-bucket $PKG active"
    run "settings delete secure always_on_vpn_app"
    lock_release
    echo "lock released" | tee -a "$LOG"
}

# ---------------------------------------------------------------------------------------------
main() {
    local scenarios=("$@")
    [ ${#scenarios[@]} -gt 0 ] || scenarios=(install intent kill bucket upgrade network tile boot-no-alwayson boot-alwayson doze energy cleanup)

    lock_take || exit 1
    for name in "${scenarios[@]}"; do
        case "$name" in
            install) scenario_install ;;
            intent) scenario_intent ;;
            kill) scenario_kill ;;
            bucket) scenario_bucket ;;
            doze) scenario_doze ;;
            upgrade) scenario_upgrade ;;
            network) scenario_network ;;
            boot-no-alwayson) scenario_boot_no_alwayson ;;
            boot-alwayson) scenario_boot_alwayson ;;
            tile) scenario_tile ;;
            energy) scenario_energy ;;
            cleanup) scenario_cleanup ;;
            *) echo "unknown scenario: $name" >&2 ;;
        esac
    done
    say "evidence in $OUT"
}

main "$@"
