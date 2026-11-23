#!/usr/bin/env bash
# Hold the canonical device lock while a host-side command runs, then release it.
#
# Why this exists as a separate file
# ----------------------------------
# `memory_profile.py` prepares the phone before it samples: it installs the declared APK, selects the
# rule set, and cold-starts once to confirm the identity. Those are **device writes**. In the first
# delivery they ran before any lock was taken, so a run could install an APK or toggle lists on a
# phone another task owned — the exact failure the canonical lock exists to prevent, and the stage-3
# safety probe already demonstrated with a foreign lock in place.
#
# `pss_idle.sh` takes the lock itself, and it cannot be modified (it is an accepted script). So the
# preparation phase takes the lock on its own and hands it back before each sampler starts; the
# sampler then takes it again for its batch. Between the two there is a gap, and that gap is why the
# *identity* check is re-run inside the sampler's own batch: the sampler verifies the rule content it
# actually measured, so a takeover in the gap cannot produce a number attributed to the wrong content.
#
# The wrapper is deliberately a shell script sourced through the shared library rather than a
# re-implementation: "held", "mine" and "expired" must mean one thing across every tool.
#
# Usage:
#   hold-device-lock.sh <owner> <token> take
#   hold-device-lock.sh <owner> <token> release
#   hold-device-lock.sh <owner> <token> status
#
# Exit status: 0 on the expected verdict, 1 otherwise, 2 on a usage error. The verdict is printed on
# stdout so the caller decides on text, not on an exit code alone.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

if [ $# -ne 3 ]; then
    echo "usage: hold-device-lock.sh <owner> <token> take|release|status" >&2
    exit 2
fi

LOCK_OWNER="$1"
LOCK_TOKEN="$2"
ACTION="$3"
export LOCK_OWNER LOCK_TOKEN
#: The token has to be the same string for take and release, so it is passed in rather than
#: generated here: a token made in this process would never match the one the take used, and
#: `lock_release` would correctly refuse to remove a lock it does not own.
# `device-lock.sh` resolves and exports `SERIAL` through `device-serial.sh`, so nothing here needs a
# default address.
# shellcheck source=device-lock.sh
. scripts/effectiveness/device-lock.sh

case "$ACTION" in
    take)
        if lock_take; then
            echo TAKEN
            exit 0
        fi
        echo REFUSED
        exit 1 ;;
    release)
        if lock_release; then
            echo RELEASED
            exit 0
        fi
        echo NOT_RELEASED
        exit 1 ;;
    status)
        lock_status
        exit $? ;;
    *)
        echo "unknown action: $ACTION" >&2
        exit 2 ;;
esac
