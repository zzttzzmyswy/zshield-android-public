#!/usr/bin/env bash
# Which device the measurement tools talk to — resolved in exactly one place.
#
# The tools used to carry one machine's Wi-Fi adb address as a default. That is a value from the
# author's network, not from this project: on any other host it either fails or, worse, points at a
# different phone. So the serial is resolved here, once, and every caller sources this file:
#
#   1. an explicit `SERIAL` in the environment wins (`adb -s <serial>` semantics);
#   2. otherwise `adb devices` must report **exactly one** usable device, which is then used;
#   3. zero devices, an unauthorized/offline device, or several devices is a refusal with the exact
#      reason. Guessing is how a run measures — or rewrites the rules of — the wrong phone.
#
# Results travel in globals, not on stdout, because every caller would otherwise have to wrap the call
# in `$(…)` — a subshell, in which the diagnosis this library exists to produce is immediately lost.
# `RESOLVED_SERIAL` holds the answer on success; `SERIAL_PROBLEM` holds the one-line reason on failure.
#
# Nothing here opens a network connection: the check is `adb devices`, which talks to the local adb
# server. It is only reached when `SERIAL` is unset, so a script driven by an explicit serial never
# pays for it.

#: The serial that was resolved. Meaningful only after `resolve_serial` returned 0.
RESOLVED_SERIAL=""
#: Why the resolution failed, in one line. Meaningful only after `resolve_serial` returned non-zero.
SERIAL_PROBLEM=""

#: Resolve the serial into `RESOLVED_SERIAL`. Returns 0 on success, 1 with `SERIAL_PROBLEM` set.
resolve_serial() {
    RESOLVED_SERIAL=""
    SERIAL_PROBLEM=""
    if [ -n "${SERIAL:-}" ]; then
        RESOLVED_SERIAL="$SERIAL"
        return 0
    fi

    if ! command -v adb >/dev/null 2>&1; then
        SERIAL_PROBLEM="SERIAL 未设置，且 PATH 里没有 adb，无法自动选择设备"
        return 1
    fi

    local listing
    if ! listing="$(adb devices 2>&1)"; then
        SERIAL_PROBLEM="SERIAL 未设置，且 \`adb devices\` 失败：${listing//$'\n'/ }"
        return 1
    fi

    # `adb devices` prints a header line, then `<serial>\t<state>` per transport, plus the adb
    # daemon's own chatter (`* daemon not running; …`) on the same stream. Neither of the first two
    # is a transport. Transports in any state other than `device` cannot be measured, but their
    # *presence* still makes the choice ambiguous: an unauthorized phone may become usable a second
    # later, and silently measuring the other one would be a measurement nobody asked for.
    local -a all=() ready=()
    local serial state rest line stripped
    while IFS= read -r line; do
        stripped="${line#"${line%%[![:space:]]*}"}"
        case "$stripped" in
            ''|'List of devices'*|'*'*) continue ;;
        esac
        read -r serial state rest <<<"$stripped"
        all+=("$serial")
        [ "$state" = "device" ] && ready+=("$serial")
    done <<<"$listing"

    if [ "${#ready[@]}" -eq 1 ] && [ "${#all[@]}" -eq 1 ]; then
        RESOLVED_SERIAL="${ready[0]}"
        return 0
    fi
    if [ "${#all[@]}" -eq 0 ]; then
        SERIAL_PROBLEM="SERIAL 未设置，且 \`adb devices\` 没有列出任何设备"
        return 1
    fi
    if [ "${#ready[@]}" -eq 0 ]; then
        SERIAL_PROBLEM="SERIAL 未设置，唯一的设备不在 device 状态（可能是 unauthorized/offline）：${all[*]}"
        return 1
    fi
    SERIAL_PROBLEM="SERIAL 未设置，连接了多个设备（${all[*]}），请显式指定，例如 SERIAL=${ready[0]}"
    return 1
}

#: Resolve once and export `SERIAL`, for callers that cannot know in advance whether the subcommand
#: they were invoked with needs a device. Idempotent: after the first call `SERIAL` is set and this
#: returns immediately.
#:
#:     d() { ensure_serial; adb -s "$SERIAL" "$@"; }
ensure_serial() {
    [ -n "${SERIAL:-}" ] && return 0
    require_serial
    SERIAL="$RESOLVED_SERIAL"
    export SERIAL
}
#:
#: Call it **directly**, never as `SERIAL="$(require_serial)"`: a command substitution runs in a
#: subshell, so the `exit 2` below would end only that subshell and the caller would carry on with an
#: empty serial — precisely the silent wrong-device behaviour this file exists to prevent. Callers do:
#:
#:     require_serial
#:     SERIAL="$RESOLVED_SERIAL"
require_serial() {
    if resolve_serial; then
        return 0
    fi
    cat >&2 <<EOF

!!! 无法确定要操作的设备
    ${SERIAL_PROBLEM}

显式指定设备后再运行：

    SERIAL=<adb 序列号> $0 ...

序列号用 \`adb devices\` 查看；USB 连接是一串字母数字，Wi-Fi 调试是 <IP>:<端口>。
不提供默认值是有意的：默认值在本机之外要么失效，要么指向另一台设备。
EOF
    exit 2
}
