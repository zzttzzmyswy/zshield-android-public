"""The `condition.sh` / `pss_idle.sh` entry points as programs: what they may write, and what they exit.

The stage-3 safety probe tested two layers below this one — `rules_backup.py` as a module and the lock
library as sourced functions. Both were correct and both were bypassed, because the callers did three
things the lower layers cannot see:

1. **A failed backup did not stop the run.** `backup_state` recorded `known: false`, the caller wrote
   `|| true`, and `apply-test-lists` went on to overwrite the user's rules and exit 0 while printing
   "user rules NOT restored". The reviewer's `condition-failed_backup_install-before.log` is that run.
2. **`cleanup` and `restore` never took the lock.** They are fresh processes, so their local loss
   marker was empty, and `w_`'s `lock_require` read "no loss observed" as "held". With a live canonical
   lock naming another task, `cleanup` still broadcast `DEBUG_SET_RULES`, force-stopped the app and
   exited 0 (`condition-no_lock_cleanup-before.log`).
3. **`return` from an EXIT trap cannot set the exit status.** The status the shell was already going to
   exit with wins, so a handler that noticed "not restored" or "renewer survived" still exited 0.

Every case here runs the real `condition.sh` as a subprocess against a stub `adb` that keeps the device
state in files, so "did it write" and "what did it exit with" are observations rather than inferences.
No adb, no Pixel, no `curl` (the test-list download is stubbed to a fixed body).
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import harness_fixtures as fixtures  # noqa: E402

SCRIPTS = fixtures.SCRIPTS
CONDITION = SCRIPTS / "condition.sh"
PROBE = Path(__file__).resolve().parent / "review" / "review_device_condition.py"

#: What the device already has before a run, deliberately awkward (entity, quote, `$`, a backslash).
ORIGINAL_RULES = (
    "! original set\n"
    "||kept.example^$removeparam=utm_source,all\n"
    '##.ad-banner > a[href^="https://track.example/?a=1&b=2"]\n'
    "||multi\\path.example^\n"
    "\n"
)


class ConditionDevice:
    """A stub device for `condition.sh`: the lock, the rules editor, the tunnel probes, the log.

    The rules surface is the **editor's** text field, the only one that carries the raw text. The
    backup path therefore navigates 首页 → 过滤器 → 自定义规则 the way the real app must be navigated,
    and `am start` resets that walk (as re-launching the app does).
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.bin = root / "bin"
        self.bin.mkdir(parents=True, exist_ok=True)
        self.log = root / "adb-log"
        self.rules = root / "user-rules"
        self.rules.write_text(ORIGINAL_RULES, encoding="utf-8")
        self.lock = root / "zshield-device.lock"
        self.state = Path(str(self.lock) + ".state")
        self.guard = Path(str(self.lock) + ".guard")
        self.capture_fails = False
        self.taps = root / "taps"
        self.vpn = root / "vpn-up"
        self.vpn.write_text("1", encoding="utf-8")
        self._write_stub()
        self._write_helpers()

    # -- the stub `adb` ---------------------------------------------------------------------------
    def _write_stub(self) -> None:
        """The stub `adb`. A **plain** string with `@@ROOT@@`, not an f-string.

        The body is Python that contains shell that contains braces; an f-string would mean doubling
        every `{` by hand, and one missed brace is a fixture that fails for a reason unrelated to the
        test. One placeholder substitution has nothing to get wrong.
        """
        body = """\
#!/usr/bin/env python3
import base64, json, os, re, subprocess, sys
from pathlib import Path
from xml.sax.saxutils import escape

root = Path("@@ROOT@@")
rules = root / "user-rules"
with open(root / "adb-log", "a") as handle:
    handle.write(json.dumps(sys.argv[1:]) + "\\n")

args = sys.argv[1:]
if "-s" in args:
    index = args.index("-s")
    del args[index:index + 2]
verb = args[0] if args else ""
rest = args[1:]
if verb == "get-state":
    print("device"); sys.exit(0)
if verb == "push":
    if len(rest) >= 2:
        Path(root / "pushed.txt").write_bytes(Path(rest[0]).read_bytes())
    sys.exit(0)
if verb != "shell":
    sys.exit(0)
command = " ".join(rest)

# The lock protocol and the rule install both arrive base64-encoded, so the body is the real
# device-side code with only the paths redirected.
if "base64 -d" in command:
    match = re.search(r"echo ([A-Za-z0-9+/=]+) \\| base64", command)
    script = base64.b64decode(match.group(1)).decode() if match else ""
    for suffix in (".d", ".state", ".guard"):
        script = script.replace("/data/local/tmp/zshield-device.lock" + suffix,
                                "@@LOCK@@" + suffix)
    script = script.replace("/data/local/tmp/zshield-device.lock", "@@LOCK@@")
    script = script.replace("/data/local/tmp/zs-restore-rules.txt", str(root / "pushed.txt"))
    script = script.replace("am broadcast", "zs_broadcast")
    header = (
        "zs_broadcast() {\\n"
        "  while [ $# -gt 0 ]; do case \\"$1\\" in --es) shift 2; V=$1 ;; esac; shift; done\\n"
        # The **second** install (the restore) loses trailing newlines, exactly as `"$(cat …)"` does
        # on the device. That is the loss the byte-for-byte re-read exists to catch, and the only way
        # to make a restore fail after a successful install without touching the tool under test.
        "  if [ \\"$CORRUPT_RESTORE\\" = 1 ] && [ -f \\"$RULESFILE.corrupt-after\\" ]; then\\n"
        "    V=$(printf '%s' \\"$V\\")\\n"
        "  fi\\n"
        "  printf %s \\"$V\\" > \\"$RULESFILE\\"\\n"
        "  touch \\"$RULESFILE.corrupt-after\\"\\n"
        "  echo \\"Broadcast completed: result=0\\"\\n"
        "}\\n"
    )
    completed = subprocess.run(["sh", "-c", header + script],
                               env=dict(os.environ, RULESFILE=str(rules),
                                        CORRUPT_RESTORE=os.environ.get("CORRUPT_RESTORE", "0")))
    raise SystemExit(completed.returncode)

if command.startswith("input tap"):
    taps = root / "taps"
    phase = int(taps.read_text() or 0) if taps.exists() else 0
    taps.write_text(str(phase + 1)); sys.exit(0)
if command.startswith("am start"):
    # Launching the app returns it to its first screen, so the three-phase walk restarts.
    (root / "taps").write_text("0")
    sys.exit(0)
if command.startswith("rm -f"):
    sys.exit(0)
if "uiautomator dump" in command:
    print("UI hierchary dumped to: /sdcard/zs-ui.xml"); sys.exit(0)
if "zs-ui.xml" in command and "cat" in command:
    taps = root / "taps"
    phase = int(taps.read_text() or 0) if taps.exists() else 0
    if phase < 2:
        print('<hierarchy><node text="\u8fc7\u6ee4\u5668" bounds="[270,1700][540,1800]" />'
              '<node text="\u81ea\u5b9a\u4e49\u89c4\u5219" bounds="[0,300][1080,400]" /></hierarchy>')
    else:
        value = (escape(rules.read_text(encoding="utf-8"))
                 .replace(chr(34), "&quot;").replace(chr(10), "&#10;")
                 .replace(chr(9), "&#9;").replace(chr(13), "&#13;"))
        print('<hierarchy><node class="android.widget.EditText" text="' + value
              + '" bounds="[0,420][1080,1400]" /></hierarchy>')
    sys.exit(0)
if "DEBUG_TOGGLE_VPN" in command:
    flag = root / "vpn-up"
    if flag.exists():
        flag.unlink()
    else:
        flag.write_text("1")
    print("Broadcast completed: result=0"); sys.exit(0)
if "dumpsys connectivity" in command:
    if (root / "vpn-up").exists():
        print("IS_VPN")
    else:
        print("no VPN")
    sys.exit(0)
if "wm size" in command:
    print("Physical size: 1080x1920"); sys.exit(0)
if "dumpsys window displays" in command:
    print("cur=1080x1920"); sys.exit(0)
sys.exit(0)
"""
        body = body.replace("@@ROOT@@", str(self.root)).replace("@@LOCK@@", str(self.lock))
        path = self.bin / "adb"
        path.write_text(body, encoding="utf-8")
        path.chmod(0o755)

    def _write_helpers(self) -> None:
        """`sleep` and `curl` doubles: the download is a fixed body, the delays are real but short."""
        # A real delay: the library refuses to start a renewer when `sleep` returns instantly, and a
        # shortened one keeps the tests quick without changing that decision.
        sleep = self.bin / "sleep"
        sleep.write_text(
            f"#!{sys.executable}\nimport sys, time\ntime.sleep(min(float(sys.argv[1]), 0.05))\n",
            encoding="utf-8",
        )
        sleep.chmod(0o755)
        curl = self.bin / "curl"
        curl.write_text("#!/bin/sh\nprintf '||probe.example^\\n'\n", encoding="utf-8")
        curl.chmod(0o755)
        # `python3` is the real interpreter, except that a `capture` invocation fails — the reviewer's
        # own technique for "the rules cannot be read right now".
        python = self.bin / "python3"
        python.write_text(
            f"#!{sys.executable}\n"
            "import os, sys\n"
            "if 'capture' in sys.argv and os.environ.get('FAIL_CAPTURE') == '1':\n"
            "    print('rules: capture FAILED — the rules editor was not reached')\n"
            "    raise SystemExit(2)\n"
            f"os.execv({sys.executable!r}, [{sys.executable!r}, *sys.argv[1:]])\n",
            encoding="utf-8",
        )
        python.chmod(0o755)

    # -- inspection -------------------------------------------------------------------------------
    def calls(self) -> list[list[str]]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines() if line.strip()]

    def commands(self) -> str:
        return "\n".join(" ".join(call) for call in self.calls())

    def decoded_bodies(self) -> list[str]:
        """Every base64 protocol body the device was asked to run, decoded."""
        bodies = []
        for call in self.calls():
            match = re.search(r"echo ([A-Za-z0-9+/=]+) \| base64", " ".join(call))
            if match:
                bodies.append(base64.b64decode(match.group(1)).decode("utf-8", "replace"))
        return bodies

    def rule_writes(self) -> int:
        """How many times the app was asked to install rules — literal or inside a protocol body."""
        direct = self.commands().count("DEBUG_SET_RULES")
        nested = sum(body.count("DEBUG_SET_RULES") for body in self.decoded_bodies())
        return direct + nested

    def device_writes(self) -> int:
        """How many mutating calls reached the device at all (`input`, `am`, `locksettings`, `rm`)."""
        writes = 0
        for call in self.calls():
            text = " ".join(call)
            if any(word in text for word in ("input tap", "input swipe", "am broadcast",
                                             "am start", "am force-stop", "locksettings")):
                writes += 1
        writes += sum(
            body.count("am broadcast") + body.count("am force-stop")
            for body in self.decoded_bodies()
        )
        return writes

    def rules_text(self) -> str:
        return self.rules.read_text(encoding="utf-8")

    def seed_lock(self, owner: str, *, ago: float = 0.0, token: str = "someone-else") -> None:
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - ago))
        self.lock.write_text(f"{owner} {stamp}\n", encoding="utf-8")
        self.state.mkdir(exist_ok=True)
        (self.state / "meta").write_text(
            f"owner={owner}\nissued={int(time.time() - ago)}\n"
            f"renewed={int(time.time() - ago)}\ntoken={token}\n",
            encoding="utf-8",
        )

    def env(self, *, owner: str | None = None, **extra) -> dict:
        env = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "SERIAL": "stub",
            "LOCK_PATH": str(self.lock),
            "OUT": str(self.root / "out"),
            "TMPDIR": str(self.root),
        }
        for key in ("LOCK_STATE_DIR", "LOCK_GUARD_DIR", "LOCK_LEGACY_DIR", "LOCK_TOKEN",
                    "LOCK_LOST_FILE", "LOCK_RENEWER_PIDS_FILE", "FAIL_CAPTURE"):
            env.pop(key, None)
        if owner is not None:
            env["LOCK_OWNER"] = owner
        env.update(extra)
        return env

    def run(self, command: str, *, owner: str | None = "MYS-2820", timeout: float = 120.0,
            **extra) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(CONDITION), command], env=self.env(owner=owner, **extra),
            capture_output=True, text=True, timeout=timeout, cwd=str(fixtures.REPO),
        )


class ConditionEntryCase(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory(prefix="zs-condition-")
        self.dir = Path(self._temp.name)
        self.device = ConditionDevice(self.dir / "device")

    def tearDown(self) -> None:
        self._temp.cleanup()


class FailedBackupStopsTheRunTest(ConditionEntryCase):
    """A capture that fails is a precondition, not a note attached to the overwrite."""

    def test_apply_test_lists_writes_nothing_and_exits_non_zero(self) -> None:
        """The reviewer's first case, at the entry point it actually failed at.

        Before: `attempted_rule_write=True, original_preserved=False, exit=0`, with "user rules NOT
        restored" in the same output — a run that lost the user's rules and reported success.
        """
        before = self.device.rules.read_bytes()
        result = self.device.run("apply-test-lists", FAIL_CAPTURE="1")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.device.rules.read_bytes(), before,
                         "the run replaced rules it could not back up")
        self.assertEqual(self.device.rule_writes(), 0,
                         "the run asked the app to install rules after a failed backup")
        # And it says why, without the contradictory "restored/NOT restored" pair after a write.
        combined = result.stdout + result.stderr
        self.assertIn("could not be read", combined, combined)
        self.assertIn("nothing on the device was changed", combined, combined)

    def test_a_condition_command_writes_nothing_and_exits_non_zero(self) -> None:
        # `vpn-off` changes the HTTPS switch and the tunnel; both are device writes, and both must be
        # withheld when the original state could not be recorded.
        result = self.device.run("vpn-off", FAIL_CAPTURE="1")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.device.device_writes(), 0,
                         "a condition command changed the device after a failed backup")
        self.assertIn("nothing on the device was changed", result.stdout + result.stderr)

    def test_a_good_backup_still_lets_apply_test_lists_run_and_restore(self) -> None:
        """The positive control: the same command with a readable backup does install and restore."""
        before = self.device.rules.read_bytes()
        result = self.device.run("apply-test-lists")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertGreaterEqual(self.device.rule_writes(), 2,
                                "the probe rules were never installed, so restore was not exercised")
        self.assertEqual(self.device.rules.read_bytes(), before,
                         "the original rule set was not put back")
        self.assertIn("user rules restored and verified", result.stdout)

    def test_a_capture_that_reports_failure_but_exits_zero_is_still_a_failure(self) -> None:
        """The failure is taken from the capture's status, not from a message it prints.

        `python3 … capture | sed …` used to make the *pipeline's* status `sed`'s, so a capture that
        failed still read as success. This drives a capture that prints a failure line and exits 0 —
        the shape that pipeline mistake turned every failure into — and requires the run to notice by
        the recorded state rather than by the text.
        """
        result = self.device.run("apply-test-lists", FAIL_CAPTURE="1")
        recorded = (self.dir / "device" / "out" / "condition-backup-MYS-2820.txt")
        self.assertTrue(recorded.exists(), list((self.dir / "device" / "out").iterdir()))
        fields = dict(
            line.split("=", 1)
            for line in recorded.read_text(encoding="utf-8").splitlines() if "=" in line
        )
        self.assertEqual(fields.get("rules_known"), "0",
                         "the backup file did not record that the rules were unreadable")
        self.assertNotEqual(result.returncode, 0)


class CleanupNeedsTheLockTest(ConditionEntryCase):
    """`cleanup` writes to the device, so it needs the device — not merely an empty loss marker."""

    def test_cleanup_refuses_a_live_lock_held_by_another_task(self) -> None:
        """The reviewer's second case: `cleanup` with a live canonical lock wrote and exited 0."""
        self.device.seed_lock("OTHER-ACTIVE")
        before = self.device.rules.read_bytes()
        result = self.device.run("cleanup", owner="review-condition")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.device.rule_writes(), 0, "cleanup installed or cleared rules anyway")
        self.assertEqual(self.device.device_writes(), 0,
                         "cleanup wrote to a device another task holds")
        self.assertEqual(self.device.rules.read_bytes(), before)
        self.assertIn("the device is not this run's", result.stdout + result.stderr)
        # And the other task's lock is exactly as it was.
        self.assertTrue(self.device.lock.read_text().startswith("OTHER-ACTIVE"))

    def test_cleanup_does_not_clear_the_user_rules(self) -> None:
        """It used to broadcast `DEBUG_SET_RULES ''`, which deletes a set it never saw."""
        result = self.device.run("cleanup")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.device.rules_text(), ORIGINAL_RULES,
                         "cleanup cleared the user's rules")
        self.assertIn("left as they are", result.stdout)

    def test_cleanup_puts_back_what_this_run_changed(self) -> None:
        """When the run has a backup, cleanup restores it — its own changes, nothing else."""
        backup = self.device.root / "out" / "condition-backup-MYS-2820.txt"
        backup.parent.mkdir(parents=True, exist_ok=True)
        record = backup.with_suffix(".txt.rules.json")
        import hashlib

        record.write_text(json.dumps({
            "captured_at": time.time(), "serial": "stub", "package": "top.zztweb.zshield",
            "known": True, "source": "editor", "rules": ORIGINAL_RULES,
            "rules_len": len(ORIGINAL_RULES), "rules_bytes": len(ORIGINAL_RULES.encode()),
            "rules_lines": ORIGINAL_RULES.count("\n"),
            "trailing_newlines": len(ORIGINAL_RULES) - len(ORIGINAL_RULES.rstrip("\n")),
            "sha256": hashlib.sha256(ORIGINAL_RULES.encode()).hexdigest(),
        }), encoding="utf-8")
        backup.write_text(
            f"rules_backup={record}\nrules_known=1\ntunnel=down\nhttps=off\n"
            f"label=MYS-2820\nat={int(time.time())}\n",
            encoding="utf-8",
        )
        # The device drifts away from the backup, as a measurement run would leave it.
        self.device.rules.write_text("||probe.example^\n", encoding="utf-8")
        result = self.device.run("cleanup")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.device.rules_text(), ORIGINAL_RULES,
                         "cleanup did not restore this run's own changes")

    def test_restore_needs_the_lock_too(self) -> None:
        """`restore` writes, so it takes the lock like every other write."""
        self.device.seed_lock("OTHER-ACTIVE")
        result = self.device.run("restore")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.device.rule_writes(), 0)
        self.assertIn("HELD owner=OTHER-ACTIVE", result.stdout + result.stderr)

    def test_status_still_reads_a_device_it_does_not_hold(self) -> None:
        """The control: reading is not writing, so `status` must still work under a foreign lock."""
        self.device.seed_lock("OTHER-ACTIVE")
        result = self.device.run("status")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("OTHER-ACTIVE", result.stdout + result.stderr)
        self.assertEqual(self.device.device_writes(), 0)


class ExitStatusTest(ConditionEntryCase):
    """The status is the process's, not a value a trap happened to return."""

    def test_a_failed_restore_makes_the_run_non_zero(self) -> None:
        """`return 1` from an EXIT trap cannot set the exit status; a restore failure must.

        The run's own install succeeds; the *restore* at the end then loses the trailing newlines, so
        the tool's byte-for-byte re-read reports a MISMATCH. The command body itself did everything it
        set out to do, and the process must still exit non-zero — the user's rules are not what they
        were, and that is the fact the exit status has to carry.
        """
        result = self.device.run("apply-test-lists", CORRUPT_RESTORE="1")
        combined = result.stdout + result.stderr
        self.assertIn("MISMATCH", combined, combined)
        self.assertIn("NOT restored", combined, combined)
        self.assertNotEqual(result.returncode, 0,
                            "a failed restore exited 0:\n" + combined)

    def test_a_return_from_an_exit_trap_is_not_an_exit_status(self) -> None:
        """The reviewer's minimal construct, and the shape this repository now uses instead.

        Without the second half this test would only restate the bug; with it, the fix is pinned: an
        explicit `exit "$accumulated"` from a disarmed trap *does* set the status.
        """
        broken = subprocess.run(
            ["bash", "-c",
             'on_exit() { local code=$?; code=1; return "$code"; }; trap on_exit EXIT; true'],
            capture_output=True,
        )
        self.assertEqual(broken.returncode, 0,
                         "the premise changed: `return` from an EXIT trap now sets the status")
        fixed = subprocess.run(
            ["bash", "-c",
             'on_exit() { local code=$?; trap - EXIT; code=1; exit "$code"; }; trap on_exit EXIT; true'],
            capture_output=True,
        )
        self.assertEqual(fixed.returncode, 1, "an explicit `exit` from the trap did not set the status")

    def test_the_scripts_do_not_return_from_a_trap(self) -> None:
        """A structural check on the two scripts that had this construct."""
        for name in ("condition.sh", "pss_idle.sh"):
            source = (SCRIPTS / name).read_text(encoding="utf-8")
            handler = _trap_handler_body(source, "on_exit" if name == "condition.sh" else "cleanup")
            self.assertTrue(handler, f"{name}: the exit handler was not found")
            self.assertNotIn("return \"$code\"", handler,
                             f"{name}: the exit handler still returns instead of exiting")
            self.assertIn("exit \"$code\"", handler,
                          f"{name}: the exit handler does not end the process with its status")


def _trap_handler_body(source: str, function: str) -> str:
    """The body of `function`, up to the first line that is a lone `}`."""
    match = re.search(rf"^{function}\(\) \{{", source, re.MULTILINE)
    if not match:
        return ""
    rest = source[match.end():]
    end = re.search(r"^\}$", rest, re.MULTILINE)
    return rest[: end.start()] if end else ""


class SignalExitTest(ConditionEntryCase):
    """A signalled run is a failed run, and it restores what it changed."""

    def test_sigterm_is_non_zero_and_leaves_no_probe_rules(self) -> None:
        """Both halves: the rules are put back **and** the status says the run did not finish."""
        process = subprocess.Popen(
            ["bash", str(CONDITION), "apply-test-lists"],
            env=self.device.env(owner="MYS-2820"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(fixtures.REPO),
        )
        try:
            deadline = time.time() + 60
            while time.time() < deadline:
                if self.device.rules_text() != ORIGINAL_RULES:
                    break
                if process.poll() is not None:
                    break
                time.sleep(0.05)
            self.assertNotEqual(self.device.rules_text(), ORIGINAL_RULES,
                                "the probe rules were never installed, so the restore was not exercised")
            process.send_signal(15)  # SIGTERM
            stdout, stderr = process.communicate(timeout=180)
        finally:
            if process.poll() is None:  # pragma: no cover - the run ignored the signal
                process.kill()
                stdout, stderr = process.communicate()
        self.assertNotEqual(process.returncode, 0,
                            "a signalled run exited 0:\n" + stdout + stderr)
        self.assertEqual(self.device.rules_text(), ORIGINAL_RULES,
                         "a signalled run left the probe rules installed")


class ReviewerProbeTest(unittest.TestCase):
    """The attachment from the review, unmodified, against this tree."""

    def test_the_attachment_is_byte_identical(self) -> None:
        attached = Path(__file__).resolve().parent / "review" / "review_device_condition.py"
        self.assertEqual(attached.read_bytes(), PROBE.read_bytes())
        before = (Path(__file__).resolve().parent / "review"
                  / "condition-probes-before.log").read_bytes()
        # The "before" log is what this round is measured against.
        self.assertIn(b"failed_backup_install: exit=0; attempted_rule_write=True; "
                      b"original_preserved=False", before)
        self.assertIn(b"no_lock_cleanup: exit=0; attempted_rule_write=True", before)

    def test_the_probe_reports_no_bypass(self) -> None:
        run_dir = Path(tempfile.mkdtemp(prefix="zs-devcond-"))
        try:
            tree = run_dir / "zshield-android"
            (tree / "scripts").mkdir(parents=True)
            shutil.copytree(
                SCRIPTS, tree / "scripts" / "effectiveness",
                ignore=shutil.ignore_patterns("__pycache__", ".effectiveness"),
            )
            target = run_dir / PROBE.name
            shutil.copy(PROBE, target)
            result = subprocess.run(
                [sys.executable, str(target)], capture_output=True, text=True, timeout=300,
                cwd=str(run_dir),
                env={**os.environ,
                     "PYTHONPATH": os.pathsep.join([
                         str(tree / "scripts" / "effectiveness"),
                         str(tree / "scripts" / "effectiveness" / "tests"),
                     ])},
            )
            output = result.stdout + result.stderr
            # Both entry-point cases must now refuse before writing.
            self.assertIn("no_lock_cleanup: exit=1; attempted_rule_write=False; original_preserved=True",
                          output, output)
            self.assertIn("failed_backup_install: exit=1; attempted_rule_write=False; "
                          "original_preserved=True", output, output)
            # The probe's third line is a standalone construct, not this repository's code; the shape
            # it tests is pinned by `ExitStatusTest` above, and it still reports 0 here because the
            # probe's own snippet is the *broken* one (that is what it is demonstrating).
            self.assertIn("exit_trap_return_failure: process_exit=0", output, output)
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)


class LockScreenCredentialIsNotInTheTreeTest(unittest.TestCase):
    """The lock-screen credential must be operator-supplied, never a literal in the repository.

    Round 1 shipped a hard-coded value. That value then (a) became the credential every contributor's
    test phone would be set to, (b) was printed by the `install-ca` transcript, and (c) was relayed by
    `locksettings`, which echoes its argument — so any saved run log carried it too.

    These are source-level assertions on purpose: there is no device here, and the property to protect
    is "the repository does not contain a usable credential", which is checkable without one.
    """

    CONDITION = SCRIPTS / "condition.sh"
    SEARCHED = (
        CONDITION,
        SCRIPTS / "pss_idle.sh",
        SCRIPTS / "tunnel_acceptance.sh",
        SCRIPTS / "tunnel_snapshot.sh",
        SCRIPTS.parent / "device-test-m4a.sh",
        SCRIPTS.parents[1] / "docs/TESTING.md",
        SCRIPTS.parents[1] / "docs/RELEASE_NOTES_0.1.4.md",
        SCRIPTS.parents[1] / "CONTRIBUTING.md",
        SCRIPTS.parents[1] / "README.md",
    )
    LITERAL_CREDENTIAL = re.compile(
        r"""(?:\bPIN\s*=\s*|\blocksettings\s+(?:set-pin|clear\s+--old)\s+)["']?[0-9]+\b"""
    )

    def test_no_file_carries_a_literal_lock_screen_credential(self) -> None:
        # Positive control exercises the literal check without storing a device credential.
        self.assertRegex("locksettings set-pin " + "9" * 4, self.LITERAL_CREDENTIAL)
        for path in self.SEARCHED:
            with self.subTest(path=path.name):
                self.assertTrue(path.is_file(), path.name)
                found = self.LITERAL_CREDENTIAL.search(path.read_text(encoding="utf-8"))
                self.assertFalse(bool(found), f"literal lock-screen credential in {path.name}")

    def test_the_script_reads_the_credential_from_the_environment(self) -> None:
        text = self.CONDITION.read_text(encoding="utf-8")
        self.assertIn("ZSHIELD_TEST_PIN", text,
                      "the credential must come from the environment")

    def test_the_credential_is_not_relayed_from_device_output(self) -> None:
        """`locksettings` echoes its argument, so the output must be suppressed, not piped onward."""
        text = self.CONDITION.read_text(encoding="utf-8")
        for line in text.splitlines():
            if "locksettings" not in line or line.lstrip().startswith("#"):
                continue
            if "set-pin" not in line and "clear --old" not in line:
                continue
            self.assertIn("/dev/null", line,
                          f"this line can echo the credential into the transcript: {line.strip()}")

    def test_a_missing_credential_refuses_before_touching_the_device(self) -> None:
        """No `ZSHIELD_TEST_PIN` -> install-ca stops with an explanation and changes nothing."""
        device = ConditionDevice(Path(tempfile.mkdtemp(prefix="zs-pin-", dir=self._temp_dir())))
        env = device.env(owner="MYS-3034")
        env.pop("ZSHIELD_TEST_PIN", None)
        for value in (None, "invalid-test-value"):
            with self.subTest(value=value):
                if value is not None:
                    env["ZSHIELD_TEST_PIN"] = value
                result = subprocess.run(
                    ["bash", str(self.CONDITION), "install-ca"], env=env, capture_output=True,
                    text=True, timeout=120,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("ZSHIELD_TEST_PIN", result.stderr)
                self.assertFalse(device.calls(), "invalid input reached adb")

    def _temp_dir(self) -> str:
        if not hasattr(self, "_td"):
            self._td = tempfile.TemporaryDirectory(prefix="zs-pinroot-")
            self.addCleanup(self._td.cleanup)
        return self._td.name


if __name__ == "__main__":
    unittest.main()
