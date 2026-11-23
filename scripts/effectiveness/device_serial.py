#!/usr/bin/env python3
"""Which device to talk to — resolved in one place, for every Python tool under `scripts/effectiveness/`.

The tools used to carry one machine's Wi-Fi adb address as their default. That address belongs to the
author's network, not to this project: elsewhere it fails, and in the worst case it names a different
phone that happens to be reachable. So the serial is resolved here instead:

1. an explicit `SERIAL` in the environment, or an explicit `--serial`, wins;
2. otherwise `adb devices` must report **exactly one** usable transport;
3. zero devices, an unauthorized/offline device, or several devices is a refusal naming the reason.

Guessing is not an option here: these tools change rules, install builds and take measurements, so
"some device" is how a run ends up measuring — or overwriting — something nobody asked it to touch.

The failure is raised as `DeviceChoiceError` so a caller can turn it into a non-zero exit rather than
a traceback, and the message says exactly how to fix it.

`device-serial.sh` next to this file implements the same rules for the shell tools; the two exist
because a shell script cannot import Python and a Python tool should not shell out to parse a shell
function. `scripts/effectiveness/tests/test_device_serial.py` holds both to the same contract.
"""

from __future__ import annotations

import os
import subprocess

#: Environment variable that names the device. Same name the shell tools use.
SERIAL_ENV = "SERIAL"


class DeviceChoiceError(RuntimeError):
    """The device to operate on could not be determined, and guessing is not acceptable."""


def _adb_devices_output() -> str:
    try:
        completed = subprocess.run(
            ["adb", "devices"], capture_output=True, text=True, timeout=30
        )
    except FileNotFoundError as error:
        raise DeviceChoiceError(
            f"{SERIAL_ENV} is not set and `adb` is not on PATH, so no device can be selected"
        ) from error
    except subprocess.TimeoutExpired as error:
        raise DeviceChoiceError(
            f"{SERIAL_ENV} is not set and `adb devices` timed out; is the adb server healthy?"
        ) from error
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip().replace("\n", " ")
        raise DeviceChoiceError(f"{SERIAL_ENV} is not set and `adb devices` failed: {detail}")
    return completed.stdout


def parse_adb_devices(output: str) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Split `adb devices` output into (all transports, usable ones), each as (serial, state).

    Everything that is not a header line is a transport, whatever its state: an `unauthorized` phone
    is still a device the operator attached, so its presence makes the choice ambiguous even though it
    cannot be used yet.
    """
    all_transports: list[tuple[str, str]] = []
    usable: list[tuple[str, str]] = []
    for line in output.splitlines():
        stripped = line.strip()
        # `adb devices` prefixes its table with a header and prints the daemon's own chatter (e.g.
        # "* daemon not running; starting now at tcp:5037") on the same stream. Neither is a transport.
        if not stripped or stripped.startswith("List of devices") or stripped.startswith("*"):
            continue
        fields = stripped.split()
        serial, state = fields[0], (fields[1] if len(fields) > 1 else "")
        all_transports.append((serial, state))
        if state == "device":
            usable.append((serial, state))
    return all_transports, usable


def resolve_serial(explicit: str | None = None) -> str:
    """Return the serial to use, or raise `DeviceChoiceError` explaining why there is none."""
    if explicit:
        return explicit
    from_env = os.environ.get(SERIAL_ENV, "").strip()
    if from_env:
        return from_env

    all_transports, usable = parse_adb_devices(_adb_devices_output())
    if len(usable) == 1 and len(all_transports) == 1:
        return usable[0][0]
    if not all_transports:
        raise DeviceChoiceError(
            f"{SERIAL_ENV} is not set and `adb devices` lists no device. Connect the phone (or run "
            f"`adb connect <ip>:<port>` for Wi-Fi debugging), then retry."
        )
    listed = ", ".join(f"{serial} ({state})" for serial, state in all_transports)
    if not usable:
        raise DeviceChoiceError(
            f"{SERIAL_ENV} is not set and the only attached device is not usable: {listed}. "
            f"Accept the debugging authorization on the phone, or set {SERIAL_ENV} explicitly."
        )
    raise DeviceChoiceError(
        f"{SERIAL_ENV} is not set and {len(usable)} devices are attached: {listed}. "
        f"Set {SERIAL_ENV}=<serial> to choose one — these tools install builds and rewrite rules, so "
        f"picking one for you is not safe."
    )


def add_serial_argument(parser, *, help_text: str = "adb serial; defaults to $SERIAL, else the only attached device") -> None:
    """Give an argument parser the `--serial` flag with this module's resolution rules.

    The default is deliberately not a serial: `None` means "resolve at run time", so `--help` never
    advertises one machine's address and a missing device is a clear refusal at use, not a stale value.
    """
    parser.add_argument(
        "--serial",
        default=None,
        help=f"{help_text} (env: {SERIAL_ENV})",
    )


def serial_from(arguments) -> str:
    """Resolve the serial for a parsed argument namespace and exit cleanly on failure."""
    try:
        return resolve_serial(getattr(arguments, "serial", None))
    except DeviceChoiceError as error:
        raise SystemExit(f"error: {error}") from error
