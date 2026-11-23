#!/usr/bin/env python3
"""Which device the tools pick: the contract, checked without a device.

`device_serial.py` (Python) and `device-serial.sh` (shell) implement the same resolution rules for
their respective callers. Their shared promise is narrow and safety-relevant, which is exactly why it
is tested here rather than trusted:

* an explicit serial is used as given;
* with no explicit serial, exactly one attached and usable device is adopted;
* zero devices, only-unusable devices, and several devices are all refusals — never a guess.

The shell side runs against a stub `adb` on `PATH`, so no real device and no real adb server is
involved. A regression here is silent in the worst way: the tools would go back to measuring whichever
phone happened to answer, which is how a run ends up rewriting the wrong device's rules.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent
REPO = SCRIPTS.parents[1]
SHELL_LIBRARY = SCRIPTS / "device-serial.sh"

SPEC = importlib.util.spec_from_file_location("device_serial", SCRIPTS / "device_serial.py")
device_serial = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules["device_serial"] = device_serial
SPEC.loader.exec_module(device_serial)


ONE_DEVICE = "List of devices attached\nABC123\tdevice\n\n"
TWO_DEVICES = "List of devices attached\nABC123\tdevice\nDEF456\tdevice\n\n"
NO_DEVICES = "List of devices attached\n\n"
UNAUTHORIZED = "List of devices attached\nABC123\tunauthorized\n\n"
ONE_OFFLINE_ONE_READY = "List of devices attached\nABC123\toffline\nDEF456\tdevice\n\n"
DAEMON_CHATTER = (
    "* daemon not running; starting now at tcp:5037\n"
    "* daemon started successfully\n"
    "List of devices attached\n"
    "192.0.2.10:5555\tdevice\n\n"
)


class ParsingTest(unittest.TestCase):
    """`adb devices` output, including the parts that are not transports."""

    def test_header_and_daemon_chatter_are_not_transports(self) -> None:
        all_transports, usable = device_serial.parse_adb_devices(DAEMON_CHATTER)
        self.assertEqual(all_transports, [("192.0.2.10:5555", "device")])
        self.assertEqual(usable, [("192.0.2.10:5555", "device")])

    def test_an_unusable_transport_is_still_counted(self) -> None:
        # It cannot be measured, but the operator attached it: that makes the choice ambiguous.
        all_transports, usable = device_serial.parse_adb_devices(UNAUTHORIZED)
        self.assertEqual(all_transports, [("ABC123", "unauthorized")])
        self.assertEqual(usable, [])

    def test_empty_listing_has_no_transport(self) -> None:
        self.assertEqual(device_serial.parse_adb_devices(NO_DEVICES), ([], []))


class PythonResolutionTest(unittest.TestCase):
    """`resolve_serial` against a stub adb, with the environment under this test's control."""

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory(prefix="zs-serial-")
        self.dir = Path(self._temp.name)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        self.adb = self.bin / "adb"
        self.adb.write_text(
            "#!/usr/bin/env bash\n"
            'if [ "$1" = "devices" ]; then printf "%s" "$STUB_DEVICES"; exit "${STUB_RC:-0}"; fi\n'
            "exit 0\n",
            encoding="utf-8",
        )
        self.adb.chmod(0o755)
        self._saved_env = {key: os.environ.get(key) for key in ("PATH", "SERIAL")}
        os.environ["PATH"] = f"{self.bin}{os.pathsep}{os.environ.get('PATH', '')}"

    def tearDown(self) -> None:
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self._temp.cleanup()

    def stub(self, listing: str, returncode: int = 0) -> None:
        os.environ["STUB_DEVICES"] = listing
        os.environ["STUB_RC"] = str(returncode)

    def test_an_explicit_serial_wins_without_asking_adb(self) -> None:
        os.environ.pop("SERIAL", None)
        # A listing that would be refused proves no adb call was needed.
        self.stub(TWO_DEVICES)
        self.assertEqual(device_serial.resolve_serial("explicit:1"), "explicit:1")

    def test_the_environment_variable_is_used_when_the_flag_is_absent(self) -> None:
        os.environ["SERIAL"] = "from-env:2"
        self.stub(TWO_DEVICES)
        self.assertEqual(device_serial.resolve_serial(None), "from-env:2")

    def test_a_single_attached_device_is_adopted(self) -> None:
        os.environ.pop("SERIAL", None)
        self.stub(ONE_DEVICE)
        self.assertEqual(device_serial.resolve_serial(None), "ABC123")

    def test_no_device_is_a_refusal(self) -> None:
        os.environ.pop("SERIAL", None)
        self.stub(NO_DEVICES)
        with self.assertRaises(device_serial.DeviceChoiceError) as caught:
            device_serial.resolve_serial(None)
        self.assertIn("no device", str(caught.exception))

    def test_an_unusable_only_device_is_a_refusal(self) -> None:
        os.environ.pop("SERIAL", None)
        self.stub(UNAUTHORIZED)
        with self.assertRaises(device_serial.DeviceChoiceError) as caught:
            device_serial.resolve_serial(None)
        self.assertIn("not usable", str(caught.exception))

    def test_several_devices_are_a_refusal_naming_them(self) -> None:
        os.environ.pop("SERIAL", None)
        self.stub(TWO_DEVICES)
        with self.assertRaises(device_serial.DeviceChoiceError) as caught:
            device_serial.resolve_serial(None)
        message = str(caught.exception)
        self.assertIn("ABC123", message)
        self.assertIn("DEF456", message)
        self.assertIn("SERIAL", message)

    def test_a_failing_adb_is_a_refusal(self) -> None:
        os.environ.pop("SERIAL", None)
        self.stub("", returncode=1)
        with self.assertRaises(device_serial.DeviceChoiceError) as caught:
            device_serial.resolve_serial(None)
        self.assertIn("failed", str(caught.exception))

    def test_a_missing_adb_is_a_refusal(self) -> None:
        os.environ.pop("SERIAL", None)
        os.environ["PATH"] = str(self.dir / "empty")
        with self.assertRaises(device_serial.DeviceChoiceError) as caught:
            device_serial.resolve_serial(None)
        self.assertIn("not on PATH", str(caught.exception))


class ShellResolutionTest(unittest.TestCase):
    """`device-serial.sh` must reach the same verdicts as the Python side."""

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory(prefix="zs-serial-sh-")
        self.dir = Path(self._temp.name)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        self.adb = self.bin / "adb"
        self.adb.write_text(
            "#!/usr/bin/env bash\n"
            'if [ "$1" = "devices" ]; then printf "%s" "$STUB_DEVICES"; exit "${STUB_RC:-0}"; fi\n'
            "exit 0\n",
            encoding="utf-8",
        )
        self.adb.chmod(0o755)

    def tearDown(self) -> None:
        self._temp.cleanup()

    def run_require(self, listing: str, *, serial: str | None = None,
                    returncode: int = 0) -> subprocess.CompletedProcess:
        """Source the library, call `require_serial` the way the tools do, and echo what it left.

        The `SERIAL="$RESOLVED_SERIAL"` line is not decoration: `require_serial` is called directly,
        not inside `$(…)`, because a subshell would swallow its `exit 2`. The echo prints the serial
        the caller would then have — the value the tools actually pass to `adb -s`.
        """
        env = {
            key: value for key, value in os.environ.items()
            if key not in ("SERIAL", "STUB_DEVICES", "STUB_RC")
        }
        env["PATH"] = f"{self.bin}{os.pathsep}{env.get('PATH', '')}"
        env["STUB_DEVICES"] = listing
        env["STUB_RC"] = str(returncode)
        if serial is not None:
            env["SERIAL"] = serial
        return subprocess.run(
            ["bash", "-c",
             f'. "{SHELL_LIBRARY}"; require_serial; SERIAL="$RESOLVED_SERIAL"; printf "%s" "$SERIAL"'],
            env=env, capture_output=True, text=True, timeout=30,
        )

    def test_an_explicit_serial_is_echoed(self) -> None:
        result = self.run_require(TWO_DEVICES, serial="explicit:1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "explicit:1")

    def test_lock_owner_keeps_the_discovered_device(self) -> None:
        env = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}",
                   STUB_DEVICES=ONE_DEVICE, STUB_RC="0", LOCK_OWNER="unit-test",
                   LOCK_LOST_FILE=str(self.dir / "lost"))
        env.pop("SERIAL", None)
        result = subprocess.run(
            ["bash", "-c", """
                source "$1"
                lock_device() { printf '%s\\n' TAKEN; }
                lock_take >/dev/null || exit 1
                printf '%s' "${SERIAL:-}"
            """, "bash", str(SCRIPTS / "device-lock.sh")],
            env=env, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "ABC123")

    def test_a_single_attached_device_is_adopted(self) -> None:
        result = self.run_require(ONE_DEVICE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "ABC123")

    def test_no_device_is_refused_with_instructions(self) -> None:
        result = self.run_require(NO_DEVICES)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SERIAL", result.stderr)
        self.assertIn("adb devices", result.stderr)

    def test_an_unusable_only_device_is_refused(self) -> None:
        result = self.run_require(UNAUTHORIZED)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unauthorized", result.stderr)

    def test_several_devices_are_refused(self) -> None:
        result = self.run_require(TWO_DEVICES)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ABC123", result.stderr)
        self.assertIn("DEF456", result.stderr)

    def test_an_offline_transport_beside_a_ready_one_is_still_ambiguous(self) -> None:
        # The offline phone may come back; picking the other one silently would be a guess.
        result = self.run_require(ONE_OFFLINE_ONE_READY)
        self.assertNotEqual(result.returncode, 0)

    def test_a_failing_adb_is_refused(self) -> None:
        result = self.run_require("", returncode=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("adb devices", result.stderr)

    def test_resolve_serial_reports_the_problem_without_exiting(self) -> None:
        """`resolve_serial` is the non-fatal form: a caller may want to decide for itself."""
        env = {
            key: value for key, value in os.environ.items()
            if key not in ("SERIAL", "STUB_DEVICES", "STUB_RC")
        }
        env["PATH"] = f"{self.bin}{os.pathsep}{env.get('PATH', '')}"
        env["STUB_DEVICES"] = TWO_DEVICES
        env["STUB_RC"] = "0"
        result = subprocess.run(
            ["bash", "-c", f'. "{SHELL_LIBRARY}"; resolve_serial >/dev/null; echo "rc=$?"; echo "$SERIAL_PROBLEM"'],
            env=env, capture_output=True, text=True, timeout=30,
        )
        lines = result.stdout.strip().splitlines()
        self.assertEqual(lines[0], "rc=1")
        self.assertIn("多个设备", lines[1])

    def test_a_command_substitution_would_swallow_the_refusal(self) -> None:
        """The trap this library's calling convention exists for, pinned so it cannot come back.

        `SERIAL="$(require_serial)"` runs in a subshell: its `exit 2` ends only that subshell, the
        assignment stores an empty string, and a caller without `set -e` walks on to `adb -s ""`. Both
        forms are run here so the difference is measured rather than asserted from memory: the
        documented form stops the script, the substitution form does not.
        """
        env = {
            key: value for key, value in os.environ.items()
            if key not in ("SERIAL", "STUB_DEVICES", "STUB_RC")
        }
        env["PATH"] = f"{self.bin}{os.pathsep}{env.get('PATH', '')}"
        env["STUB_DEVICES"] = NO_DEVICES
        env["STUB_RC"] = "0"

        documented = subprocess.run(
            ["bash", "-c",
             f'. "{SHELL_LIBRARY}"; require_serial; SERIAL="$RESOLVED_SERIAL"; echo "reached"'],
            env=env, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(documented.returncode, 2)
        self.assertNotIn("reached", documented.stdout)

        substitution = subprocess.run(
            ["bash", "-c", f'. "{SHELL_LIBRARY}"; SERIAL="$(require_serial)"; echo "reached [$SERIAL]"'],
            env=env, capture_output=True, text=True, timeout=30,
        )
        # Documenting the trap, not endorsing it: this form really does continue with an empty serial.
        self.assertEqual(substitution.returncode, 0)
        self.assertIn("reached []", substitution.stdout)


class RepositoryCarriesNoSerialTest(unittest.TestCase):
    """The point of all of the above: no machine's device address is in the tracked files."""

    def test_no_tracked_file_contains_a_private_device_address(self) -> None:
        tracked = subprocess.run(
            ["git", "ls-files"], cwd=str(REPO), capture_output=True, text=True, timeout=60
        )
        if tracked.returncode != 0:
            self.skipTest("not a git checkout; the scan needs `git ls-files`")
        offenders: list[str] = []
        for relative in tracked.stdout.splitlines():
            path = REPO / relative
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except (OSError, IsADirectoryError):
                continue
            # RFC 5737 / 3849 documentation ranges and the loopback are expected; a *specific*
            # Wi-Fi adb address is what must not come back.
            for line_number, line in enumerate(text.splitlines(), start=1):
                if _looks_like_a_private_device_address(line):
                    offenders.append(f"{relative}:{line_number}")
        self.assertEqual(offenders, [], "device addresses must not be committed: " + ", ".join(offenders))


def _looks_like_a_private_device_address(line: str) -> bool:
    """A `<private IPv4>:<port>` used as an adb serial.

    Deliberately narrow: it flags private-range addresses that appear as an adb target, which is the
    shape a hand-written serial takes. Documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
    `203.0.113.0/24`) are synthetic and allowed — tests use them on purpose.
    """
    import re

    pattern = re.compile(r"(?:-s\s+|SERIAL=|serial=)(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})")
    for match in pattern.finditer(line):
        address = match.group(1)
        octets = [int(part) for part in address.split(".")]
        if octets[0] == 127 or octets[0] == 0:
            continue
        if octets[0] == 192 and octets[1] == 0 and octets[2] == 2:
            continue
        if octets[0] == 198 and octets[1] == 51 and octets[2] == 100:
            continue
        if octets[0] == 203 and octets[1] == 0 and octets[2] == 113:
            continue
        if octets[0] == 10 or (octets[0] == 192 and octets[1] == 168) \
                or (octets[0] == 172 and 16 <= octets[1] <= 31):
            return True
    return False


if __name__ == "__main__":
    unittest.main()
