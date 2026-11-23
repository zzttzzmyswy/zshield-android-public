"""The device transaction: lock exclusivity and lossless user-rule restoration (MYS-2820).

Two defects the stage-3 safety probe measured, and what each test here pins down:

1. **The lock was invisible to everyone else.** It lived in `…lock.d`, so the canonical file `AGENTS.md`
   and the other scripts use could name a live task and `lock_take` would still exit 0. Now the canonical
   file *is* the lock; the auxiliary state and the critical section are additions beside it.

2. **Stale takeover was read-then-rename, not one decision.** Both contenders read the same stale stamp
   and both exited 0 — the loser's rename removed the winner's fresh lock. Now every read/verify/modify
   runs inside one `mkdir` critical section, entered without waiting: a guard that cannot be created is
   an immediate refusal.

3. **A literal `（空）` rule set was backed up as the empty string.** The diagnostics screen renders
   `userRules.ifBlank { "（空）" }`, and the previous reader mapped the marker to `""` with
   `known: true`; the "restore" then deleted the user's rules. The editor's text field carries the raw
   text, so empty / whitespace-only / the literal marker are three distinct observations, and this file
   requires each of them to survive a round trip — or the capture to fail with zero writes.

Every device interaction here is a stub `adb` that runs the base64 protocol body with the host `sh`
against a temporary directory. No adb, no Pixel.
"""

from __future__ import annotations

import base64
import json
import os
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
LIB = SCRIPTS / "device-lock.sh"
RULES_BACKUP = SCRIPTS / "rules_backup.py"

#: A rule set that is awkward on purpose: an XML entity, a quote, a `$` that a device shell would
#: expand, a backslash, a multi-byte character and **three trailing newlines** (which `$(cat …)` eats).
AWKWARD_RULES = (
    "! original set & <kept>\n"
    "||kept.example^$removeparam=utm_source,all\n"
    '##.ad-banner > a[href^="https://track.example/?a=1&b=2"]\n'
    "||multi.example^$removeparam=one\n"
    "||multi\\path.example^\n"
    "示例.example##.广告\n"
    "\n"
    "\n"
)


# ------------------------------------------------------------------------------------------------
# A stub device: `adb shell` runs the protocol body locally, with the lock paths redirected
# ------------------------------------------------------------------------------------------------

STUB_ADB = '''#!{python}
"""A stub `adb`: runs a base64 protocol body with the host `sh`, in a redirected directory.

The lock protocol travels as `echo <base64> | base64 -d | sh`; the body is decoded and its canonical
paths are rewritten into {lock!r} before `sh` runs it, so `mkdir`/`mv`/`sed`/`date` behave exactly as
they do on the device and the *script's* decisions are what the test exercises.
"""
import base64, json, os, re, subprocess, sys
from pathlib import Path

root = Path({root!r})
with open(root / "adb-calls.log", "a") as handle:
    handle.write(json.dumps(sys.argv[1:]) + "\\n")

args = sys.argv[1:]
if "-s" in args:
    index = args.index("-s")
    del args[index:index + 2]
verb = args[0] if args else ""
rest = args[1:]
if verb == "get-state":
    print("device")
    sys.exit(0)
if verb == "push":
    if len(rest) >= 2:
        Path(root / "pushed.txt").write_bytes(Path(rest[0]).read_bytes())
    sys.exit(0)
if verb != "shell":
    sys.exit(0)

command = " ".join(rest)
if "base64 -d | sh" in command:
    match = re.search(r"echo ([A-Za-z0-9+/=]+) \\| base64 -d \\| sh", command)
    body = base64.b64decode(match.group(1)).decode() if match else ""
    for suffix in (".d", ".state", ".guard"):
        body = body.replace("/data/local/tmp/zshield-device.lock" + suffix, {lock!r} + suffix)
    body = body.replace("/data/local/tmp/zshield-device.lock", {lock!r})
    # A rule restore travels the same way; the staged bytes are the ones `push` kept.
    body = body.replace("/data/local/tmp/zs-restore-rules.txt", str(root / "pushed.txt"))
    # `am broadcast` is the app's seam, which a host test cannot run. A `broadcast.sh` in the fixture
    # supplies a stub with the same call shape, so the device-side half of the restore — the
    # trailing-newline sentinel and the byte-count check — is the real code, not a re-implementation.
    installer = root / "broadcast.sh"
    if installer.exists():
        body = body.replace("am broadcast", "zs_stub_broadcast")
        body = installer.read_text() + "\\n" + body
    completed = subprocess.run(["sh", "-c", body], capture_output=True, text=True,
                               env={{**os.environ, "STUB_ROOT": str(root)}})
    sys.stdout.write(completed.stdout)
    sys.stderr.write(completed.stderr)
    sys.exit(completed.returncode)

handler = root / "device.py"
if handler.exists():
    completed = subprocess.run(
        [{python!r}, str(handler), command], capture_output=True, text=True,
        env={{**os.environ, "STUB_ROOT": str(root)}},
    )
    sys.stdout.write(completed.stdout)
    sys.stderr.write(completed.stderr)
    sys.exit(completed.returncode)
sys.exit(0)
'''


class StubDevice:
    """A temporary device: the canonical lock, its state, and a stub `adb` that reaches them."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.bin = root / "bin"
        self.bin.mkdir(exist_ok=True)
        self.lock = root / "zshield-device.lock"
        self.state = Path(str(self.lock) + ".state")
        self.guard = Path(str(self.lock) + ".guard")
        self.log = root / "adb-calls.log"
        self._install()

    def _install(self) -> None:
        path = self.bin / "adb"
        path.write_text(
            STUB_ADB.format(python=sys.executable, root=str(self.root), lock=str(self.lock))
        )
        path.chmod(0o755)

    def handler(self, body: str) -> None:
        """Install a Python handler for non-lock `adb shell` calls, to emulate app surfaces."""
        (self.root / "device.py").write_text(
            f"#!{sys.executable}\nimport sys\n" + textwrap.dedent(body), encoding="utf-8"
        )

    def install_broadcast_stub(self, *, rewrite: str | None = None) -> None:
        """A stand-in for `am broadcast -a … DEBUG_SET_RULES … --es rules "$V"`.

        It records `$V` byte for byte and, unless `rewrite` says otherwise, installs exactly that — so
        a test can make the "app" install something *almost* the same and prove the re-read notices.
        """
        body = (
            "zs_stub_broadcast() {\n"
            "  while [ $# -gt 0 ]; do\n"
            "    case \"$1\" in\n"
            "      --es) shift 2; V=$1 ;;\n"
            "    esac\n"
            "    shift\n"
            "  done\n"
            "  printf '%s' \"$V\" > \"$STUB_ROOT/installed-raw.txt\"\n"
        )
        if rewrite is None:
            body += "  cp \"$STUB_ROOT/installed-raw.txt\" \"$STUB_ROOT/current-rules.txt\"\n"
        else:
            body += rewrite + "\n"
        body += "  echo 'Broadcast completed: result=0'\n}\n"
        (self.root / "broadcast.sh").write_text(body, encoding="utf-8")

    def seed_editor(self, rules: str) -> Path:
        """Write what the rules editor's field holds, so the reader's `cat` sees it."""
        state = self.root / "current-rules.txt"
        state.write_text(rules, encoding="utf-8")
        return state

    def navigable_editor(self, rules: str, *, raw_whitespace: bool = False) -> Path:
        """A device whose UI can actually be navigated to the editor, as the real app is.

        The reader taps 过滤器, then 自定义规则, then reads the field. A stub that answered every dump
        with the field would let a reader that never navigated (and therefore might have read a
        different screen) pass, so the fixture walks the same three phases and only the last dump
        carries an `EditText`.
        """
        state = self.seed_editor(rules)
        (self.root / "taps").write_text("0", encoding="utf-8")
        self._raw_whitespace = raw_whitespace
        self.handler(
            textwrap.dedent(
                """\
                import os, sys
                from pathlib import Path
                from xml.sax.saxutils import escape

                root = Path(os.environ["STUB_ROOT"])
                command = sys.argv[1]
                taps = root / "taps"
                phase = int(taps.read_text() or 0) if taps.exists() else 0

                if command.startswith("input tap"):
                    taps.write_text(str(phase + 1))
                    sys.exit(0)
                if command.startswith("am start"):
                    # Launching the app puts it back on its first screen, as the real one does, so the
                    # three-phase walk restarts. Without this the fixture would report the editor as
                    # unreachable on the second read of a single device — an artefact of the double,
                    # not of the reader.
                    taps.write_text("0")
                    sys.exit(0)
                if command.startswith("rm -f"):
                    sys.exit(0)
                if "uiautomator dump" in command:
                    print("UI hierchary dumped to: /sdcard/zs-ui.xml")
                    sys.exit(0)
                if "zs-ui.xml" in command and "cat" in command:
                    if phase == 0:
                        print('<hierarchy>'
                              '<node text="首页" bounds="[0,1700][270,1800]" />'
                              '<node text="过滤器" bounds="[270,1700][540,1800]" />'
                              '</hierarchy>')
                    elif phase == 1:
                        print('<hierarchy>'
                              '<node text="我的规则" bounds="[0,200][1080,260]" />'
                              '<node text="自定义规则" bounds="[0,300][1080,400]" />'
                              '</hierarchy>')
                    else:
                        value = (root / "current-rules.txt").read_text(encoding="utf-8")
                        encoded = escape(value).replace(chr(34), "&quot;").replace(chr(10), "&#10;")
                        # A lossless serialiser escapes tabs and CRs; a literal one would be folded
                        # into spaces by the parser, which is the case this fixture can also produce.
                        if not {raw}:
                            encoded = encoded.replace(chr(9), "&#9;").replace(chr(13), "&#13;")
                        print('<hierarchy><node class="android.widget.EditText" text="'
                              + encoded + '" bounds="[0,420][1080,1400]" /></hierarchy>')
                    sys.exit(0)
                sys.exit(0)
                """.replace("{raw}", "True" if self._raw_whitespace else "False")
            )
        )
        return state

    def calls(self) -> list[list[str]]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines() if line.strip()]

    def broadcast_count(self) -> int:
        return sum(1 for call in self.calls() if "DEBUG_SET_RULES" in " ".join(call))

    def seed(self, owner: str, when: float, *, token: str = "seeded", with_state: bool = True) -> None:
        """Write a lock as another task would have: canonical line, optional state beside it."""
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(when))
        self.lock.write_text(f"{owner} {stamp}\n", encoding="utf-8")
        if with_state:
            self.state.mkdir(exist_ok=True)
            (self.state / "meta").write_text(
                f"owner={owner}\nissued={int(when)}\nrenewed={int(when)}\ntoken={token}\n",
                encoding="utf-8",
            )

    def seed_canonical_only(self, owner: str, when: float) -> None:
        """The `AGENTS.md` convention exactly: one line, no auxiliary state."""
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(when))
        self.lock.write_text(f"{owner} {stamp}\n", encoding="utf-8")

    def meta(self) -> dict:
        path = self.state / "meta"
        if not path.exists():
            return {}
        return dict(
            line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines() if "=" in line
        )

    def env(self, **extra) -> dict:
        env = {
            **os.environ,
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "LOCK_PATH": str(self.lock),
            "LOCK_OWNER": "MYS-2820",
            "LOCK_TOKEN": "tok-a",
            "SERIAL": "stub",
            "TMPDIR": str(self.root),
        }
        for key in ("LOCK_STATE_DIR", "LOCK_GUARD_DIR", "LOCK_TTL", "LOCK_RENEW_EVERY"):
            env.pop(key, None)
        env.pop("LOCK_OWNER" if "OWNER" in extra else "LOCK_OWNER___", None)
        env.update(extra)
        return env

    def run(self, script: str, **extra) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", "-c", f'source "{LIB}"; {script}'],
            env=self.env(**extra), capture_output=True, text=True, timeout=120,
            cwd=str(fixtures.REPO),
        )

    def spawn(self, script: str, **extra) -> subprocess.Popen:
        return subprocess.Popen(
            ["bash", "-c", f'source "{LIB}"; {script}'],
            env=self.env(**extra), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            cwd=str(fixtures.REPO),
        )


class DeviceTransactionCase(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory(prefix="zs-device-")
        self.dir = Path(self._temp.name)
        self.device = StubDevice(self.dir / "device")

    def tearDown(self) -> None:
        self._temp.cleanup()


# ------------------------------------------------------------------------------------------------
# The lock
# ------------------------------------------------------------------------------------------------

class CanonicalLockTest(DeviceTransactionCase):
    """The lock other tasks observe is the lock this library takes."""

    def test_the_canonical_path_is_the_default(self) -> None:
        # The default must be the file `AGENTS.md` fixes, not a private directory beside it.
        result = self.device.run('printf "%s\\n" "$LOCK_PATH"', LOCK_PATH="")
        self.assertEqual(result.stdout.strip(), "/data/local/tmp/zshield-device.lock")

    def test_a_live_canonical_lock_from_another_task_is_refused(self) -> None:
        """The probe's first finding, with the exact fixture it used.

        A canonical lock naming another issue, written the `AGENTS.md` way (no state file), and the
        previous revision took the lock anyway. Now it must refuse and leave the file untouched.
        """
        self.device.seed_canonical_only("OTHER-ACTIVE-ISSUE", time.time())
        before = self.device.lock.read_text()
        result = self.device.run("lock_take")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.device.lock.read_text(), before, "the holder's canonical lock was changed")
        self.assertFalse(self.device.state.exists(), "a refused run created its own state file")

    def test_a_live_canonical_lock_with_state_beside_it_is_refused(self) -> None:
        self.device.seed("MYS-9999", time.time())
        result = self.device.run("lock_take")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.device.meta().get("owner"), "MYS-9999")

    def test_a_directory_where_the_canonical_file_belongs_is_refused(self) -> None:
        # A directory with no `meta` is the previous revision's directory format with no readable
        # holder: refused, never treated as debris. (A live one and an expired one are covered below.)
        self.device.lock.mkdir()
        result = self.device.run("lock_take")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("HELD_LEGACY_UNREADABLE", result.stderr)
        self.assertTrue(self.device.lock.is_dir(), "a directory lock was replaced")

    def test_a_live_legacy_directory_lock_is_honoured(self) -> None:
        """A run that started before this change may hold the old `.lock.d`; it still holds the phone."""
        legacy = Path(str(self.device.lock) + ".d")
        legacy.mkdir()
        (legacy / "meta").write_text(
            f"owner=MYS-OLD\ntoken=old\nissued={int(time.time())}\nrenewed={int(time.time())}\n",
            encoding="utf-8",
        )
        result = self.device.run("lock_take")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("HELD_LEGACY", result.stderr)
        self.assertFalse(self.device.lock.exists(), "a new canonical lock was taken over a live one")
        self.assertTrue(legacy.exists(), "a live legacy lock was removed")

    def test_an_expired_legacy_directory_lock_is_retired_and_taken_over(self) -> None:
        legacy = Path(str(self.device.lock) + ".d")
        legacy.mkdir()
        (legacy / "meta").write_text(
            f"owner=MYS-OLD\ntoken=old\nissued={int(time.time()) - 4 * 3600}\n"
            f"renewed={int(time.time()) - 4 * 3600}\n",
            encoding="utf-8",
        )
        result = self.device.run("lock_take")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(legacy.exists(), "the expired legacy lock was left in place")
        self.assertTrue(self.device.lock.exists())

    def test_an_unreadable_legacy_directory_lock_is_refused(self) -> None:
        legacy = Path(str(self.device.lock) + ".d")
        legacy.mkdir()
        result = self.device.run("lock_take")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(legacy.exists())

    def test_an_unparseable_canonical_line_is_refused(self) -> None:
        for body in ("just-a-word\n", "MYS-1\n", "MYS-1 not-a-time\n", "\n"):
            with self.subTest(body=body):
                self.device.lock.write_text(body, encoding="utf-8")
                shutil.rmtree(self.device.state, ignore_errors=True)
                result = self.device.run("lock_take")
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.device.lock.read_text(), body)

    def test_a_future_dated_lock_is_refused(self) -> None:
        # A stamp ahead of the clock never expires, so it would hold the phone forever.
        self.device.seed_canonical_only("MYS-FUTURE", time.time() + 86400)
        result = self.device.run("lock_take")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("HELD_FUTURE", result.stderr)

    def test_an_expired_canonical_lock_is_taken_over_in_the_same_format(self) -> None:
        self.device.seed_canonical_only("MYS-DEAD", time.time() - 3 * 3600)
        result = self.device.run("lock_take")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("took over an expired lock from MYS-DEAD", result.stdout)
        first = self.device.lock.read_text().splitlines()[0]
        owner, _, stamp = first.partition(" ")
        self.assertEqual(owner, "MYS-2820")
        # Still `<issue> <ISO time>`, which is what every other script parses.
        self.assertRegex(stamp, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_an_epoch_stamp_is_understood_too(self) -> None:
        # Older writers used `date +%s`; an ISO-only parser would read that as "unknown format" and
        # refuse a perfectly expired lock.
        self.device.lock.write_text(f"MYS-DEAD {int(time.time() - 4 * 3600)}\n", encoding="utf-8")
        result = self.device.run("lock_take")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_the_positive_path_take_renew_release(self) -> None:
        # Without this, every refusal above could be satisfied by refusing everything.
        taken = self.device.run("lock_take")
        self.assertEqual(taken.returncode, 0, taken.stdout + taken.stderr)
        self.assertEqual(self.device.meta().get("token"), "tok-a")
        self.assertEqual(self.device.meta().get("owner"), "MYS-2820")
        issued = self.device.meta().get("issued")

        renewed = self.device.run("lock_renew")
        self.assertEqual(renewed.returncode, 0, renewed.stdout + renewed.stderr)
        self.assertEqual(self.device.meta().get("issued"), issued, "renew reset the issue time")
        self.assertGreaterEqual(int(self.device.meta()["renewed"]), int(issued))

        released = self.device.run("lock_release")
        self.assertEqual(released.returncode, 0, released.stdout + released.stderr)
        self.assertFalse(self.device.lock.exists())
        self.assertFalse(self.device.state.exists(), "release left its own state behind")

    def test_a_foreign_token_cannot_renew_or_release(self) -> None:
        self.device.run("lock_take")
        before = self.device.lock.read_text()
        renewed = self.device.run("lock_renew", LOCK_TOKEN="tok-b")
        released = self.device.run("lock_release", LOCK_TOKEN="tok-b")
        self.assertNotEqual(renewed.returncode, 0, renewed.stdout + renewed.stderr)
        self.assertNotEqual(released.returncode, 0, released.stdout + released.stderr)
        self.assertEqual(self.device.lock.read_text(), before)
        self.assertEqual(self.device.meta().get("token"), "tok-a")

    def test_an_owner_with_a_space_is_refused_before_any_device_call(self) -> None:
        # A space would silently shorten the `<issue> <ISO>` line every other task parses.
        result = self.device.run("lock_take", LOCK_OWNER="MYS-2820 extra")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("cannot go into", result.stderr)
        self.assertFalse(self.device.lock.exists())

    def test_no_owner_is_refused(self) -> None:
        result = self.device.run("lock_take", LOCK_OWNER="")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("without LOCK_OWNER", result.stderr)
        self.assertFalse(self.device.lock.exists())


class CriticalSectionTest(DeviceTransactionCase):
    """The interleaving the probe drove deterministically: read, pause, another run takes over."""

    def test_two_runners_racing_an_expired_lock_yield_exactly_one_holder(self) -> None:
        """A **real** two-process race, run many times: at most one winner, every time.

        The probe's own deterministic barrier drove the old code down the losing branch by pausing
        between the read and the rename. The replacement has no such window to pause in — the whole
        read/verify/modify is inside one `mkdir` — so the property is asserted directly over real
        concurrent processes rather than over a barrier that only exists in the old design. The
        deterministic guard test below covers the interleaving itself.
        """
        for attempt in range(8):
            with self.subTest(attempt=attempt):
                shutil.rmtree(self.device.state, ignore_errors=True)
                shutil.rmtree(self.device.guard, ignore_errors=True)
                self.device.seed("MYS-DEAD", time.time() - 3 * 3600)
                first = self.device.spawn("lock_take", LOCK_TOKEN="tok-1")
                second = self.device.spawn("lock_take", LOCK_TOKEN="tok-2")
                out1, err1 = first.communicate(timeout=120)
                out2, err2 = second.communicate(timeout=120)
                winners = [code for code in (first.returncode, second.returncode) if code == 0]
                self.assertLessEqual(
                    len(winners), 1,
                    f"both runners took an expired lock (attempt {attempt}): "
                    f"{out1}{err1}{out2}{err2}",
                )
                holder = self.device.meta().get("token")
                self.assertIn(holder, {"tok-1", "tok-2", "seeded"})
                self.assertEqual(self.device.lock.read_text().split()[0], self.device.meta()["owner"])

    def test_a_crashed_guard_is_refused_never_stolen(self) -> None:
        """The critical section cannot be adopted from a dead process, and the message says how out."""
        self.device.guard.mkdir()
        (self.device.guard / "started").write_text(str(int(time.time()) - 600))
        (self.device.guard / "token").write_text("dead-run")
        self.device.seed_canonical_only("MYS-DEAD", time.time() - 4 * 3600)
        before = self.device.lock.read_text()
        result = self.device.run("lock_take")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("GUARD_BUSY", result.stderr)
        self.assertIn("rmdir", result.stderr)
        self.assertEqual(self.device.lock.read_text(), before, "a guarded takeover wrote anyway")
        self.assertTrue(self.device.guard.exists(), "the stale guard was removed by a run that did not own it")

    def test_the_guard_is_released_after_a_normal_operation(self) -> None:
        self.device.run("lock_take")
        self.assertFalse(self.device.guard.exists(), "a successful take left the critical section held")
        self.device.run("lock_renew")
        self.assertFalse(self.device.guard.exists())
        self.device.run("lock_release")
        self.assertFalse(self.device.guard.exists())

    def test_a_failed_guard_acquisition_exits_immediately(self) -> None:
        """No unbounded wait: a held guard is an immediate non-zero, not a hang."""
        self.device.guard.mkdir()
        started = time.monotonic()
        result = self.device.run("lock_take", )
        elapsed = time.monotonic() - started
        self.assertNotEqual(result.returncode, 0)
        self.assertLess(elapsed, 30, f"the refusal waited {elapsed:.1f}s")

    def test_the_takeover_decision_is_one_critical_section(self) -> None:
        """A holder that is still inside the section cannot have its lock replaced.

        This is the interleaving stated directly instead of by pausing the old code: while one runner
        holds the guard, a second runner — with a genuinely stale canonical lock in front of it — must
        refuse rather than decide for itself.
        """
        self.device.seed_canonical_only("MYS-DEAD", time.time() - 4 * 3600)
        self.device.guard.mkdir()
        (self.device.guard / "started").write_text(str(int(time.time())))
        (self.device.guard / "token").write_text("in-progress")
        before = self.device.lock.read_text()
        result = self.device.run("lock_take", LOCK_TOKEN="late")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.device.lock.read_text(), before)
        self.assertEqual((self.device.guard / "token").read_text(), "in-progress",
                         "the second runner cleared the first runner's guard")
        self.assertFalse(self.device.state.exists())


class TransportFailureTest(DeviceTransactionCase):
    """A failed write or a failed adb must not read as an acquisition."""

    def test_an_unwritable_canonical_path_is_not_an_acquisition(self) -> None:
        missing = self.dir / "absent" / "zshield-device.lock"
        result = self.device.run("lock_take", LOCK_PATH=str(missing))
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("WRITE_FAILED", result.stderr)
        self.assertFalse(missing.exists())

    def test_an_adb_that_answers_nothing_is_not_an_acquisition(self) -> None:
        result = self.device.run('lock_device() { return 1; }; lock_take')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("no usable verdict", result.stderr)
        self.assertFalse(self.device.lock.exists())

    def test_an_adb_that_answers_junk_is_not_an_acquisition(self) -> None:
        result = self.device.run('lock_device() { printf "garbage\\n"; }; lock_take')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("no usable verdict", result.stderr)

    def test_a_renewal_that_cannot_write_reports_failure(self) -> None:
        self.device.run("lock_take")
        # Make the state directory read-only for this operation: the read succeeds, the write cannot.
        original = (self.device.state / "meta").read_text()
        result = self.device.run(
            'write_meta() { return 1; }; lock_renew'.replace("write_meta", "true")
        )
        del result, original  # the override above is not reachable from the library's namespace
        # The reachable form: a device that answers a failed write.
        result = self.device.run(
            'lock_device() { '
            f'printf "%s\\n" "WRITE_FAILED meta"; '
            '}; lock_renew'
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("renewal refused", result.stderr)


class LeaseLossTest(DeviceTransactionCase):
    """A renewal that fails must be visible to the transaction, not just to the background subshell."""

    def test_lock_require_refuses_after_a_loss_marker(self) -> None:
        self.device.run("lock_take")
        marker = self.device.root / "lost.flag"
        written = self.device.run(
            f'LOCK_LOST_FILE={marker}; printf "renewal failed\\n" > "$LOCK_LOST_FILE"; lock_require'
        )
        self.assertNotEqual(written.returncode, 0, written.stdout + written.stderr)
        self.assertIn("LOST", written.stderr)

    def test_lock_require_allows_a_held_lease(self) -> None:
        """The positive control: holding it and having seen no loss is a pass.

        Note the `lock_take` — that is the point of the change. "No loss marker" alone used to be
        enough, which is why a fresh `cleanup` process wrote to a device it had never taken.
        """
        self.device.run("lock_take")
        marker = self.device.root / "kept.flag"
        result = self.device.run(f'LOCK_LOST_FILE={marker}; : > "$LOCK_LOST_FILE"; lock_require')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_lock_require_refuses_without_taking_the_lock(self) -> None:
        # The same command with no `lock_take`: the device says FREE, so no write is allowed.
        marker = self.device.root / "never.flag"
        result = self.device.run(f'LOCK_LOST_FILE={marker}; : > "$LOCK_LOST_FILE"; lock_require')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("FREE nothing-held", result.stderr)

    def test_lock_require_refuses_when_another_task_holds_the_lock(self) -> None:
        """An **empty** local loss marker is not evidence of holding the lock.

        A fresh process — `cleanup`, `restore`, a direct rule install — starts with no loss marker at
        all, so a check that only consults it says "fine" for a phone another task owns. The question
        goes to the device instead.
        """
        self.device.seed("MYS-OTHER", time.time())
        marker = self.device.root / "empty.flag"
        result = self.device.run(f'LOCK_LOST_FILE={marker}; : > "$LOCK_LOST_FILE"; lock_require')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("does not hold", result.stderr)

    def test_lock_require_refuses_when_no_lock_is_held_at_all(self) -> None:
        # Nothing on the device, no token: the same refusal, and the reason says so.
        marker = self.device.root / "empty2.flag"
        result = self.device.run(f'LOCK_LOST_FILE={marker}; : > "$LOCK_LOST_FILE"; lock_require')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_lock_require_refuses_an_expired_lease_of_its_own(self) -> None:
        self.device.run("lock_take")
        self.device.seed("MYS-2820", time.time() - 3 * 3600, token="tok-a")
        marker = self.device.root / "empty3.flag"
        result = self.device.run(f'LOCK_LOST_FILE={marker}; : > "$LOCK_LOST_FILE"; lock_require')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("EXPIRED", result.stderr)

    def test_a_failed_renewal_writes_the_marker(self) -> None:
        """The renewer notices a refused renewal and records it where the transaction looks."""
        self.device.run("lock_take")
        marker = self.device.root / "lost.flag"
        # A device that refuses every renewal: the token it reports is not this run's.
        result = self.device.run(
            "lock_device() { "
            'case "$*" in *base64*) printf "NOTMINE token=other\\n";; *) printf "\\n";; esac; }; '
            f"LOCK_LOST_FILE={marker}; LOCK_RENEW_EVERY=1; lock_start_renewer; "
            "for _ in 1 2 3 4 5 6 7 8 9 10; do sleep 0.5; lock_lost && break; done; "
            "lock_stop_renewer; lock_lost && echo MARKER-SET"
        )
        self.assertIn("MARKER-SET", result.stdout, result.stdout + result.stderr)
        self.assertIn("renewal failed", marker.read_text())

    def test_the_renewer_records_and_reaps_every_delay_it_starts(self) -> None:
        """A `sleep` left behind is a leaked process nobody can attribute; cleanup must not leave one."""
        pids = self.device.root / "renewer.pids"
        result = self.device.run(
            f"LOCK_RENEWER_PIDS_FILE={pids}; LOCK_LOST_FILE={self.device.root / 'lost.flag'}; "
            "LOCK_RENEW_EVERY=30; lock_start_renewer; sleep 0.6; "
            # Read the record *before* stopping: cleanup deletes the file on purpose, so reading it
            # afterwards would report "no delays" no matter what the renewer did.
            'while IFS= read -r pid; do echo "PID=$pid"; done < "$LOCK_RENEWER_PIDS_FILE"; '
            "lock_stop_renewer; echo STOPPED"
        )
        self.assertIn("STOPPED", result.stdout, result.stdout + result.stderr)
        recorded = [line.split("=", 1)[1].strip() for line in result.stdout.splitlines()
                    if line.startswith("PID=")]
        self.assertTrue(recorded, f"the renewer recorded no delay it started: {result.stdout}{result.stderr}")
        for pid in recorded:
            proc = Path("/proc") / pid
            if not proc.exists():
                continue
            # A reused pid is not ours; only a process still running `sleep` at that pid is.
            cmdline = (proc / "cmdline").read_bytes() if (proc / "cmdline").exists() else b""
            self.assertNotIn(b"sleep", cmdline, f"a renewer delay survived cleanup: pid {pid}")

    def test_a_second_start_does_not_spawn_a_second_renewer(self) -> None:
        pids = self.device.root / "renewer.pids"
        result = self.device.run(
            f"LOCK_RENEWER_PIDS_FILE={pids}; LOCK_LOST_FILE={self.device.root / 'lost.flag'}; "
            "LOCK_RENEW_EVERY=30; lock_start_renewer; first=$LOCK_RENEWER_PID; "
            "lock_start_renewer; second=$LOCK_RENEWER_PID; "
            'echo "SAME=$([ "$first" = "$second" ] && echo yes || echo no)"; '
            "lock_stop_renewer"
        )
        self.assertIn("SAME=yes", result.stdout, result.stdout + result.stderr)


# ------------------------------------------------------------------------------------------------
# The rules transaction
# ------------------------------------------------------------------------------------------------

class EditorSurface:
    """A device double whose rules editor carries the raw text, as the real one does.

    `RulesEditorScreen.kt:57` seeds the field from `FilterRepository.userRules.value`, so the field's
    `text` **is** the rule set. This double renders it the way `uiautomator` renders a Compose
    `TextField`: an `android.widget.EditText` node whose `text` attribute holds the value, with XML
    entities escaped and newlines as `&#10;` (attribute-value normalisation would otherwise fold them
    into spaces — writing a raw newline here would make the fixture easier than the device).
    """

    def __init__(self, rules: str, *, fields: int = 1, dumps: int = 2) -> None:
        self.rules = rules
        self.fields = fields
        self.dumps_left = dumps

    def open_rules_editor(self) -> None:
        """The editor is already on screen in this double."""

    def start_main_screen(self) -> None:
        pass

    def back(self) -> None:
        pass

    def tap(self, x: int, y: int) -> None:
        pass

    def shell(self, command: str) -> str:
        return ""

    def dump_ui(self) -> str:
        nodes = []
        # A read-only node first, so a reader that takes "the text attribute" rather than "the editable
        # node" would pick this one up and the test would fail.
        nodes.append('<node class="android.widget.TextView" text="自定义规则" bounds="[0,0][100,50]" />')
        for index in range(self.fields):
            nodes.append(
                '<node class="android.widget.EditText" text="'
                + _xml_attribute(self.rules)
                + '" bounds="[0,60][1080,600]" />'
            )
        return "<hierarchy>" + "".join(nodes) + "</hierarchy>"


def _xml_attribute(value: str) -> str:
    """Escape a value the way a lossless `uiautomator` serialiser does.

    Tabs and carriage returns are escaped too: written literally they would be folded into spaces by
    XML attribute-value normalisation, and the value would then be a near-miss that cannot be restored.
    """
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("\n", "&#10;")
        .replace("\t", "&#9;")
        .replace("\r", "&#13;")
    )


class RulesBackupModule:
    """`rules_backup.py` loaded as a module, so the reader's decisions are tested directly."""

    def __init__(self) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("rules_backup_under_test", RULES_BACKUP)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def read(self, device, **kwargs) -> dict:
        return self.module.read_rules(device, **kwargs)


class RulesCaptureTest(unittest.TestCase):
    """Capture is lossless or it fails; there is no third answer."""

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory(prefix="zs-rules-")
        self.dir = Path(self._temp.name)
        self.backup = RulesBackupModule()

    def tearDown(self) -> None:
        self._temp.cleanup()

    def test_an_empty_rule_set_is_captured_as_empty(self) -> None:
        state = self.backup.read(EditorSurface(""), source="editor")
        self.assertTrue(state["known"])
        self.assertEqual(state["rules"], "")

    def test_a_whitespace_only_rule_set_keeps_its_whitespace(self) -> None:
        # `ifBlank` calls this blank too, which is why the diagnostics screen cannot be the source.
        state = self.backup.read(EditorSurface("   \n\t\n"), source="editor")
        self.assertTrue(state["known"])
        self.assertEqual(state["rules"], "   \n\t\n")

    def test_a_literal_blank_marker_survives(self) -> None:
        """The probe's third finding: `（空）` is a rule set, not the absence of one."""
        state = self.backup.read(EditorSurface("（空）"), source="editor")
        self.assertTrue(state["known"])
        self.assertEqual(state["rules"], "（空）",
                         "a rule set that literally is the blank marker was read as empty")

    def test_trailing_newlines_survive(self) -> None:
        state = self.backup.read(EditorSurface("||a.example^\n\n\n"), source="editor")
        self.assertTrue(state["known"])
        self.assertEqual(state["rules"], "||a.example^\n\n\n")

    def test_awkward_characters_survive(self) -> None:
        state = self.backup.read(EditorSurface(AWKWARD_RULES), source="editor")
        self.assertTrue(state["known"])
        self.assertEqual(state["rules"], AWKWARD_RULES)

    def test_two_editable_fields_are_refused(self) -> None:
        # Which of the two is the rule set cannot be known, so neither is.
        state = self.backup.read(EditorSurface("x", fields=2), source="editor")
        self.assertFalse(state["known"])
        self.assertIn("editable field", state["error"])

    def test_no_editable_field_is_refused(self) -> None:
        state = self.backup.read(EditorSurface("x", fields=0), source="editor")
        self.assertFalse(state["known"])

    def test_a_changing_field_is_refused(self) -> None:
        class Moving(EditorSurface):
            def __init__(self) -> None:
                super().__init__("first")
                self.reads = 0

            def dump_ui(self) -> str:
                self.reads += 1
                self.rules = "first" if self.reads == 1 else "second"
                return super().dump_ui()

        state = self.backup.read(Moving(), source="editor")
        self.assertFalse(state["known"], "a field that changed between reads was captured anyway")
        self.assertIn("changed", state["error"])

    def test_a_debug_screen_marker_is_refused(self) -> None:
        """The diagnostics surface cannot separate three sets, so it must not claim to have read one."""
        class DebugScreen:
            def start_debug_screen(self) -> None:
                pass

            def dump_ui(self) -> str:
                return '<hierarchy><node text="自定义规则：（空）" /></hierarchy>'

        state = self.backup.read(DebugScreen(), source="debug")
        self.assertFalse(state["known"])
        self.assertIn("cannot be told apart", state["error"])

    def test_the_capture_cli_writes_the_digest_and_the_trailing_newline_count(self) -> None:
        device = StubDevice(self.dir / "device")
        device.navigable_editor(AWKWARD_RULES)
        out = self.dir / "rules.json"
        result = subprocess.run(
            [sys.executable, str(RULES_BACKUP), "capture", "--out", str(out),
             "--serial", "stub", "--source", "editor"],
            env=device.env(), capture_output=True, text=True, cwd=str(fixtures.REPO), timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(record["rules"], AWKWARD_RULES)
        self.assertEqual(record["trailing_newlines"], 3)
        self.assertEqual(record["sha256"], __import__("hashlib").sha256(
            AWKWARD_RULES.encode("utf-8")).hexdigest())
        self.assertEqual(record["source"], "editor")
        self.assertEqual(record["serial"], "stub")
        self.assertEqual(record["package"], "top.zztweb.zshield")

    def test_a_failed_capture_writes_zero_rule_broadcasts(self) -> None:
        """The review's "zero writes" requirement, at the CLI boundary."""
        device = StubDevice(self.dir / "device")
        device.handler(
            "import sys\nprint('<hierarchy><node class=\"android.widget.TextView\" text=\"x\" />"
            "</hierarchy>')\n"
        )
        out = self.dir / "rules.json"
        result = subprocess.run(
            [sys.executable, str(RULES_BACKUP), "capture", "--out", str(out),
             "--serial", "stub", "--source", "editor"],
            env=device.env(), capture_output=True, text=True, cwd=str(fixtures.REPO), timeout=120,
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertFalse(out.exists() or (out.exists() and json.loads(
            out.read_text(encoding="utf-8")).get("known")), "a failed capture wrote a usable backup")
        self.assertEqual(device.broadcast_count(), 0)


class RulesRestoreTest(unittest.TestCase):
    """Restore is byte-exact and re-read, and a refusal touches nothing."""

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory(prefix="zs-restore-")
        self.dir = Path(self._temp.name)

    def tearDown(self) -> None:
        self._temp.cleanup()

    def _device(self, *, current: str = "SEED", rewrite: str | None = None) -> tuple[StubDevice, Path]:
        """A device whose editor holds `current`, and whose rule broadcast replaces it.

        The stub runs the real device-side restore script in `sh`; the only substitution is `am
        broadcast` → `zs_stub_broadcast`. Everything the script does to the text on the way (the
        trailing-newline sentinel, the byte-count check) therefore runs for real, which is exactly
        what this class is about. The editor is reached by navigating the same three screens the real
        app has, so a reader that skipped the navigation could not read the field.
        """
        device = StubDevice(self.dir / "device")
        state = device.navigable_editor(current)
        device.install_broadcast_stub(rewrite=rewrite)
        return device, state

    def _run(self, device: StubDevice, *arguments: str, env: dict | None = None):
        return subprocess.run(
            [sys.executable, str(RULES_BACKUP), *arguments, "--serial", "stub"],
            env={**device.env(), **(env or {})}, capture_output=True, text=True,
            cwd=str(fixtures.REPO), timeout=180,
        )

    def _backup(self, rules: str) -> Path:
        import hashlib

        path = self.dir / "backup.json"
        path.write_text(json.dumps({
            "captured_at": time.time(), "serial": "stub", "package": "top.zztweb.zshield",
            "known": True, "source": "editor", "rules": rules,
            "rules_len": len(rules), "rules_bytes": len(rules.encode("utf-8")),
            "rules_lines": rules.count("\n") + (1 if rules else 0),
            "trailing_newlines": len(rules) - len(rules.rstrip("\n")),
            "sha256": hashlib.sha256(rules.encode("utf-8")).hexdigest(),
        }), encoding="utf-8")
        return path

    def test_a_round_trip_is_byte_exact(self) -> None:
        device, state = self._device()
        backup = self._backup(AWKWARD_RULES)
        result = self._run(device, "restore", "--from", str(backup))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state.read_text(encoding="utf-8"), AWKWARD_RULES)

    def test_a_literal_marker_round_trips(self) -> None:
        device, state = self._device()
        backup = self._backup("（空）")
        result = self._run(device, "restore", "--from", str(backup))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state.read_text(encoding="utf-8"), "（空）")

    def test_a_dump_that_folds_whitespace_is_refused_rather_than_approximated(self) -> None:
        """A read that cannot carry the whitespace exactly is a failed read, not a near-enough one.

        XML attribute-value normalisation turns a literal tab or CR inside the `text` attribute into a
        space, and that happens before any parser sees it. A dump that does this cannot be restored
        byte for byte, so the capture must fail — the same answer the tool gives when the diagnostics
        screen shows its blank marker. "Close enough" is what deleted a user's rules once already.
        """
        device = StubDevice(self.dir / "device")
        device.navigable_editor("  \n\t\n", raw_whitespace=True)
        out = self.dir / "rules.json"
        result = subprocess.run(
            [sys.executable, str(RULES_BACKUP), "capture", "--out", str(out),
             "--serial", "stub", "--source", "editor"],
            env=device.env(), capture_output=True, text=True, cwd=str(fixtures.REPO), timeout=120,
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("normalisation folds", result.stdout)
        self.assertEqual(device.broadcast_count(), 0)

    def test_an_empty_set_round_trips(self) -> None:
        device, state = self._device(current="something")
        backup = self._backup("")
        result = self._run(device, "restore", "--from", str(backup))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state.read_text(encoding="utf-8"), "")

    def test_a_whitespace_only_set_round_trips(self) -> None:
        device, state = self._device()
        backup = self._backup("  \n\t\n")
        result = self._run(device, "restore", "--from", str(backup))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state.read_text(encoding="utf-8"), "  \n\t\n")

    def test_a_backup_without_known_is_refused_and_nothing_is_written(self) -> None:
        device, state = self._device()
        path = self.dir / "unread.json"
        path.write_text('{"known": false, "rules": "^"}', encoding="utf-8")
        result = self._run(device, "restore", "--from", str(path))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(state.read_text(encoding="utf-8"), "SEED")
        self.assertEqual(device.broadcast_count(), 0)

    def test_a_backup_from_the_debug_surface_is_refused(self) -> None:
        device, state = self._device()
        path = self._backup("something")
        record = json.loads(path.read_text(encoding="utf-8"))
        record["source"] = "debug"
        path.write_text(json.dumps(record), encoding="utf-8")
        result = self._run(device, "restore", "--from", str(path))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(state.read_text(encoding="utf-8"), "SEED")

    def test_an_edited_backup_is_refused(self) -> None:
        device, state = self._device()
        path = self._backup("||a.example^\n")
        record = json.loads(path.read_text(encoding="utf-8"))
        record["rules"] = "||b.example^\n"
        path.write_text(json.dumps(record), encoding="utf-8")
        result = self._run(device, "restore", "--from", str(path))
        self.assertEqual(result.returncode, 2)
        self.assertIn("sha256", result.stdout)
        self.assertEqual(state.read_text(encoding="utf-8"), "SEED")

    def test_a_mismatch_after_the_write_is_a_failure(self) -> None:
        """The last line of defence: the re-read must compare the exact text, not a summary."""
        # A device that installs something *almost* right: every trailing newline dropped, which is
        # exactly the loss `"$(cat …)"` causes and the review named.
        device, state = self._device(
            rewrite='printf "%s" "$(cat "$STUB_ROOT/installed-raw.txt")" > "$STUB_ROOT/current-rules.txt"',
        )
        backup = self._backup("plain\n\n")
        result = self._run(device, "restore", "--from", str(backup))
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("MISMATCH", result.stdout)
        self.assertIn("trailing newlines", result.stdout)
        # The "app" installed the truncated text, and the tool said so rather than claiming success.
        self.assertEqual(state.read_text(encoding="utf-8"), "plain")

    def test_a_backup_that_does_not_exist_is_refused(self) -> None:
        device, state = self._device()
        result = self._run(device, "restore", "--from", str(self.dir / "nope.json"))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(state.read_text(encoding="utf-8"), "SEED")
        self.assertEqual(device.broadcast_count(), 0)

    def test_install_carries_the_same_bytes_as_restore(self) -> None:
        """The probe rules the transaction installs go through the same sentinel as the restore.

        `tunnel_acceptance.sh` and `condition.sh apply-test-lists` install their own rule files; before
        this, each had its own push-and-broadcast sequence and only the restore handled trailing
        newlines. One implementation means the bytes going in and the bytes coming out are the same
        question with the same answer.
        """
        device, state = self._device()
        source = self.dir / "probe-rules.txt"
        source.write_text(AWKWARD_RULES, encoding="utf-8")
        result = self._run(device, "install", "--from", str(source))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state.read_text(encoding="utf-8"), AWKWARD_RULES)

    def test_install_refuses_a_missing_file(self) -> None:
        device, state = self._device()
        result = self._run(device, "install", "--from", str(self.dir / "absent.txt"))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(state.read_text(encoding="utf-8"), "SEED")
        self.assertEqual(device.broadcast_count(), 0)


class OfflineSubcommandsNeedNoDeviceTest(unittest.TestCase):
    """The CLI entry point must not require a device for a command that never touches one.

    Round 1 resolved the serial before dispatching, so `show` — which reads a file already on this
    machine and prints it — exited 1 with "SERIAL is not set" when run with no phone attached and no
    `adb` on `PATH`. The lead measured the regression against the base commit: base exited 0, the
    round-1 tree exited 1.

    The property is checked at the entry point the operator actually uses: the real script, as a
    subprocess, with `SERIAL` cleared and a `PATH` that cannot contain adb.
    """

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory(prefix="zs-offline-")
        self.dir = Path(self._temp.name)
        self.backup = self.dir / "backup.txt"
        # A real, minimal backup body: `show` prints what the file holds, so the content only has to
        # parse. `{}` is what the lead used.
        self.backup.write_text("{}\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._temp.cleanup()

    def _run_without_a_device(self, *arguments: str) -> subprocess.CompletedProcess:
        # A PATH with no adb at all: this is stricter than "adb is present but reports no device",
        # and it is what the lead's repro used.
        bare = self.dir / "empty-bin"
        bare.mkdir(exist_ok=True)
        for tool in ("bash", "sh", "env"):
            found = shutil.which(tool)
            if found:
                (bare / tool).symlink_to(found)
        env = {key: value for key, value in os.environ.items()
               if key not in ("SERIAL", "PKG")}
        env["PATH"] = str(bare)
        env["PYTHONPATH"] = str(SCRIPTS)
        return subprocess.run(
            [sys.executable, str(RULES_BACKUP), *arguments],
            capture_output=True, text=True, timeout=120, env=env, cwd=str(fixtures.REPO),
        )

    def test_show_succeeds_with_no_device_and_no_adb(self) -> None:
        result = self._run_without_a_device("show", "--from", str(self.backup))
        self.assertEqual(result.returncode, 0,
                         "`show` is a local read; it must not need a device:\n"
                         + result.stdout + result.stderr)
        self.assertIn("known=", result.stdout)

    def test_show_prints_what_the_file_holds(self) -> None:
        result = self._run_without_a_device("show", "--from", str(self.backup))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("sha256=", result.stdout)

    def test_capture_reports_its_own_missing_argument_not_a_device_problem(self) -> None:
        """Argument errors are answered before device discovery, so the message names the real issue."""
        result = self._run_without_a_device("capture")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("--out", result.stdout + result.stderr)

    def test_a_device_command_still_refuses_without_a_serial(self) -> None:
        """The other half of the contract: `restore` writes to a phone, so it needs one."""
        result = self._run_without_a_device("restore", "--from", str(self.backup))
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("SERIAL", result.stderr)

    def test_an_explicit_serial_is_still_honoured_for_device_commands(self) -> None:
        """An explicit serial short-circuits discovery, so the failure is adb's, not the resolver's."""
        bare = self.dir / "empty-bin"
        bare.mkdir(exist_ok=True)
        for tool in ("bash", "sh", "env"):
            found = shutil.which(tool)
            if found:
                (bare / tool).symlink_to(found)
        env = {key: value for key, value in os.environ.items() if key != "PKG"}
        env["PATH"] = str(bare)
        env["PYTHONPATH"] = str(SCRIPTS)
        env["SERIAL"] = "explicit:5555"
        result = subprocess.run(
            [sys.executable, str(RULES_BACKUP), "restore", "--from", str(self.backup)],
            capture_output=True, text=True, timeout=120, env=env, cwd=str(fixtures.REPO),
        )
        self.assertNotIn("SERIAL is not set", result.stderr,
                         "an explicit serial must be used as given")


if __name__ == "__main__":
    unittest.main()
