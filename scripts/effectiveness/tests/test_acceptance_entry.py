"""The whole acceptance transaction, end to end, against a real origin and a stubbed device.

`tunnel_acceptance.sh` is the entry point the task card names, and the review's objection was that
nothing tested it as a program: every other test called the pieces. This file runs it for real, with:

  * a **real** `tunnel_origin.py` on loopback ports (plaintext, TLS/H2, TLS/H1);
  * a **stub `adb`** that answers the device probes, keeps a user-rules file, keeps the lock
    directory, and records every argv;
  * a **stub `tunnel_concurrency.py`**? No — the real harness runs, driven by a browser double
    injected through `PYTHONPATH`, so the arguments the wrapper passes, the readiness gate, the JSON
    report and the summary all execute as they would on the device.

What is proven:

  * a complete run **passes** and leaves the user rules exactly as it found them;
  * the **same** rules are restored on a failing run and on a SIGTERM;
  * an unreadable backup means **nothing is written** (the rules are untouched and the exit is
    non-zero);
  * every snapshot the wrapper takes carries this run's id, so `check` can require it.

The device itself is never touched: the stub is the only `adb`.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
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
HERE = Path(__file__).resolve().parent

#: The rules a run is supposed to find already installed and put back afterwards. Deliberately awkward:
#: an XML entity, an embedded newline, and a `#` comment — none of which a `grep`/`sed` scraper
#: survives.
ORIGINAL_RULES = (
    "! original set\n"
    "||kept.example^$removeparam=utm_source,all\n"
    "##.ad-banner > a[href^=\"https://track.example/?a=1&b=2\"]\n"
    "||multi.example^$removeparam=one\n"
    "||multi.example^$removeparam=two\n"
)


class StubDevice:
    """A stub `adb` that emulates exactly the surface the acceptance script uses.

    State lives in files under `root`, so the test can assert what the run did to them:

      user-rules   the rule set, as the debug screen would report it
      lock/        the lock directory, exactly as `mkdir`/`mv` would leave it
      log          every argv, one JSON array per line

    The debug screen's rules line is emitted as real `uiautomator` XML with the value **entity-escaped**,
    which is what the device actually sends — and what makes a `grep`-based reader wrong.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.bin = root / "bin"
        self.bin.mkdir(parents=True, exist_ok=True)
        self.log = root / "adb-log"
        self.rules = root / "user-rules"
        self.rules.write_text(ORIGINAL_RULES, encoding="utf-8")
        self.lock = root / "zshield-device.lock"
        self.fail_backup = False
        self.delay = 0.0
        self._write_stub()

    def _write_stub(self) -> None:
        script = textwrap.dedent(
            f'''\
            #!{sys.executable}
            """A stub `adb`: answers the probes, records every call, and keeps state in files."""
            import base64, json, os, shutil, subprocess, sys, time
            from pathlib import Path
            from xml.sax.saxutils import escape

            root = Path({str(self.root)!r})
            rules = root / "user-rules"
            lock = root / "zshield-device.lock"
            with open(root / "adb-log", "a") as handle:
                handle.write(json.dumps(sys.argv[1:]) + "\\n")

            args = sys.argv[1:]
            # Drop the `-s <serial>` pair, which every call carries.
            if "-s" in args:
                index = args.index("-s")
                del args[index:index + 2]
            verb = args[0] if args else ""
            rest = args[1:]

            if verb == "get-state":
                print("device")
                sys.exit(0)
            if verb == "push":
                # The wrapper pushes the rule file and then reads it on the device with `$(cat …)`;
                # the stub keeps the pushed bytes where the DEBUG_SET_RULES branch can find them.
                if len(rest) >= 2:
                    shutil.copy(rest[0], root / "pushed-rules.txt")
                sys.exit(0)
            if verb != "shell":
                sys.exit(0)

            command = " ".join(rest)
            # The lock protocol arrives as `sh -c '<script>'`; run it locally with the directory
            # redirected, so `mkdir`/`mv`/`sed` behave exactly as on the device.
            #
            # The body is `printf %q`-quoted, and re-deriving that quoting by hand is exactly the kind
            # of guess this whole rework is removing. Instead the stub hands the original argument
            # list to a shell: `sh -c "$script"` with the script passed *as a separate argv entry*, so
            # the quoting is the device shell's job, as it is on the device.
            if "base64 -d | sh" in command:
                # The lock protocol arrives as `echo <base64> | base64 -d | sh` — no quoting rules at
                # all, which is exactly why the library sends it that way. The stub decodes it, points
                # the lock directory at the test's own, and runs it with the same `sh`.
                blob = command.rsplit("echo ", 1)[1].split(" | base64", 1)[0]
                body = base64.b64decode(blob).decode()
                for suffix in (".d", ".state", ".guard"):
                    body = body.replace(
                        "/data/local/tmp/zshield-device.lock" + suffix, str(lock) + suffix
                    )
                body = body.replace("/data/local/tmp/zshield-device.lock", str(lock))
                # A rule restore travels through the same transport. The staged file is the one
                # `push` kept, and `am broadcast` becomes the stub below — so the device-side half of
                # the restore (the trailing-newline sentinel and the byte-count check) is real code.
                body = body.replace(
                    "/data/local/tmp/zs-restore-rules.txt", str(root / "pushed-rules.txt")
                )
                body = body.replace("am broadcast", "zs_stub_broadcast")
                body = (
                    'zs_stub_broadcast() {{\\n'
                    '  while [ $# -gt 0 ]; do case "$1" in --es) shift 2; V=$1 ;; esac; shift; done\\n'
                    '  printf %s "$V" > "' + str(root / "user-rules") + '"\\n'
                    '  echo "Broadcast completed: result=0"\\n'
                    '}}\\n' + body
                )
                completed = subprocess.run(["sh", "-c", body], capture_output=True, text=True)
                sys.stdout.write(completed.stdout)
                sys.exit(completed.returncode)

            if "dumpsys connectivity" in command:
                print("IS_VPN")
                sys.exit(0)
            if "pidof" in command:
                print("4242")
                sys.exit(0)
            if "appId" in command:
                print("10123")
                sys.exit(0)
            if "/proc/net/tcp" in command:
                print("readable=yes")
                print("sockets= 4 01")
                print("rss_kb=120000")
                print("threads=30")
                print("sockstat=TCP: inuse 40 orphan 0 tw 5 alloc 60 mem 3")
                sys.exit(0)
            if "zs-ui.xml" in command and "cat" in command:
                # The rules surface is now the **editor's text field**, not the diagnostics line:
                # the diagnostics screen renders `userRules.ifBlank { "（空）" }`, which collapses an
                # empty set, a whitespace-only set and a literal `（空）` into one string. The
                # editor is seeded from the repository value itself, so its field carries the text.
                #
                # `escape` with the quote entity: the value sits inside a double-quoted attribute, so
                # `"` must become `&quot;` and a newline `&#10;`/a tab `&#9;`/a CR `&#13;` — XML
                # attribute-value normalisation would otherwise fold them into spaces. Writing them
                # raw would make the fixture lossier than the device.
                value = (
                    escape(rules.read_text())
                    .replace(chr(34), "&quot;")
                    .replace(chr(10), "&#10;")
                    .replace(chr(9), "&#9;")
                    .replace(chr(13), "&#13;")
                )
                print(
                    '<hierarchy>'
                    '<node text="首页" bounds="[0,1700][270,1800]" />'
                    '<node text="过滤器" bounds="[270,1700][540,1800]" />'
                    '<node text="自定义规则" bounds="[0,300][1080,400]" />'
                    '<node class="android.widget.EditText" text="' + value
                    + '" bounds="[0,420][1080,1400]" /></hierarchy>'
                )
                sys.exit(0)
            if "uiautomator dump" in command:
                print("UI hierchary dumped to: /sdcard/zs-ui.xml")
                sys.exit(0)
            if "DEBUG_SET_RULES" in command:
                # The rules arrive as a file the device shell reads with `"$(cat …)"`; the stub reads
                # the same file out of the pushed path.
                payload = Path("/data/local/tmp/zs-restore-rules.txt")
                scratch = root / "pushed-rules.txt"
                if scratch.exists():
                    rules.write_text(scratch.read_text())
                    print("Broadcast completed: result=0")
                else:
                    print("Broadcast completed: result=0")
                sys.exit(0)
            sys.exit(0)
            '''
        )
        path = self.bin / "adb"
        path.write_text(script, encoding="utf-8")
        path.chmod(0o755)
        # `push` writes the payload where the stub's DEBUG_SET_RULES branch can find it.
        push = textwrap.dedent(
            f'''\
            #!{sys.executable}
            import shutil, sys
            from pathlib import Path
            root = Path({str(self.root)!r})
            source, target = sys.argv[1], sys.argv[2]
            if "restore" in target or "rules" in target:
                shutil.copy(source, root / "pushed-rules.txt")
            '''
        )
        # The stub `adb` handles `push` itself; this file exists only for the unit that drives it
        # directly, so it is not installed as `adb`.
        (self.bin / "_push_helper.py").write_text(push, encoding="utf-8")

    def rules_text(self) -> str:
        return self.rules.read_text(encoding="utf-8")

    def meta(self) -> dict:
        """This protocol's own extras (`…lock.state/meta`), beside the canonical file."""
        path = Path(str(self.lock) + ".state") / "meta"
        if not path.exists():
            return {}
        return dict(
            line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines() if "=" in line
        )

    def calls(self) -> list[list[str]]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines() if line.strip()]

    def commands(self) -> str:
        return "\n".join(" ".join(call) for call in self.calls())


class AcceptanceRunTest(unittest.TestCase):
    """`tunnel_acceptance.sh` as a program, against a real origin and a stubbed device."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.origin = fixtures.OriginFixture(tls=True, tls1=True, hold_ms=150).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.origin.stop()

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory(prefix="zs-accept-")
        self.dir = Path(self._temp.name)
        self.device = StubDevice(self.dir / "device")
        self.out = self.dir / "out"
        self.out.mkdir()
        self.browser_double = self._write_browser_double()
        #: The origin this instance is measuring against, when it was injected by a harness.
        self.origin = getattr(type(self), "origin", None)

    def tearDown(self) -> None:
        self._temp.cleanup()

    def _write_browser_double(self) -> Path:
        """A `cdp` module whose pages perform real HTTP against the origin.

        Written from `browser_double.py` beside this file rather than embedded here: the module is
        ordinary Python that needs `{}`, `{"a": 1}` and quote characters, and every one of those has to
        be doubled inside an f-string. Embedding it produced exactly the class of quoting bug this
        rework exists to remove, and it took three rounds of "syntax error in the fixture" to notice.
        The fixture reads the real file and substitutes only the two names it needs.
        """
        source = (HERE / "browser_double.py").read_text(encoding="utf-8")
        module = self.dir / "double" / "cdp.py"
        module.parent.mkdir(parents=True, exist_ok=True)
        module.write_text(source, encoding="utf-8")
        return module.parent

    def _env(self, *, owner: str | None = "MYS-2817", run_id: str = "txn-run") -> dict:
        env = {
            **os.environ,
            "PATH": f"{self.device.bin}{os.pathsep}{os.environ['PATH']}",
            "PYTHONPATH": f"{SCRIPTS}{os.pathsep}{os.environ.get('PYTHONPATH', '')}",
            # The explicit override, because a script's own directory outranks `PYTHONPATH` on
            # `sys.path` — the substitution cannot be done by path order alone.
            "ZS_CDP_MODULE": str(self.browser_double / "cdp.py"),
            # Which port is the TLS/H1 listener, so the double can tell the two TLS legs apart. A
            # hard-coded port in the double would mislabel the fixture's own free port.
            "ZS_TLS1_PORT": str(
                self.origin.https1_port if self.origin is not None else os.environ.get("ZS_TLS1_PORT", "0")
            ),
            "OUT": str(self.out),
            "SERIAL": "stub",
            "LOCK_PATH": str(self.device.lock),
        }
        env.pop("LOCK_OWNER", None)
        env.pop("LOCK_TOKEN", None)
        if owner:
            env["LOCK_OWNER"] = owner
        return env

    def _run(self, *, owner: str | None = "MYS-2817", timeout: float = 240.0,
             concurrency: str = "6", rounds: str = "1") -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(SCRIPTS / "tunnel_acceptance.sh"),
             "--origin", self.origin.base_tls,
             "--http-origin", self.origin.base,
             "--https-origin", self.origin.base_tls,
             "--tls1-origin", self.origin.base_tls1,
             "--rounds", rounds, "--concurrency", concurrency],
            env=self._env(owner=owner), capture_output=True, text=True,
            timeout=timeout, cwd=str(fixtures.REPO),
        )

    # -- the cases -------------------------------------------------------------------------
    def test_a_complete_run_passes_and_puts_the_rules_back(self) -> None:
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS", result.stdout)
        self.assertNotIn("ACCEPTANCE FAILED", result.stderr)
        # The rules are exactly what they were: the probe rules are gone and the original is intact.
        self.assertEqual(self.device.rules_text(), ORIGINAL_RULES)
        # The summary carries the origin's own concurrency evidence.
        self.assertIn("origin:", result.stdout)

    def test_the_run_holds_the_lock_for_the_whole_transaction(self) -> None:
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("device lock: taken by MYS-2817", result.stdout)
        self.assertIn("device lock: released", result.stdout)
        # And the snapshot pairs carry the run's identifier, so `check` can require it.
        before = self.out / "tunnel-snapshot-accept-before.txt"
        settled = self.out / "tunnel-snapshot-accept-settled.txt"
        self.assertTrue(before.exists() and settled.exists(), list(self.out.iterdir()))
        for path in (before, settled):
            body = path.read_text(encoding="utf-8")
            self.assertIn("run=", body)
            self.assertIn("ok=yes", body, f"{path.name} was not usable:\n{body}")

    def test_a_failing_run_still_restores_the_rules(self) -> None:
        # A concurrency of 1 per leg makes the group overlap check fail, so the run exits non-zero —
        # and the restore path must still put the rules back.
        result = self._run(concurrency="1")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.device.rules_text(), ORIGINAL_RULES)

    def test_a_sigterm_restores_the_rules(self) -> None:
        """An interrupted run must not leave the probe's rules installed.

        The run is started and signalled while it is still working; the exit trap has to restore.
        """
        process = subprocess.Popen(
            ["bash", str(SCRIPTS / "tunnel_acceptance.sh"),
             "--origin", self.origin.base_tls,
             "--http-origin", self.origin.base,
             "--https-origin", self.origin.base_tls,
             "--tls1-origin", self.origin.base_tls1,
             "--rounds", "3", "--concurrency", "12"],
            env=self._env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            cwd=str(fixtures.REPO),
        )
        try:
            # Wait until the rules have actually been replaced, so the signal lands mid-transaction.
            deadline = time.time() + 90
            while time.time() < deadline:
                if self.device.rules_text() != ORIGINAL_RULES:
                    break
                if process.poll() is not None:
                    break
                time.sleep(0.2)
            self.assertNotEqual(
                self.device.rules_text(), ORIGINAL_RULES,
                "the probe rules were never installed, so the restore was not exercised",
            )
            process.send_signal(signal.SIGTERM)
            process.communicate(timeout=120)
        finally:
            if process.poll() is None:  # pragma: no cover - the run ignored the signal
                process.kill()
                process.communicate()
        self.assertEqual(self.device.rules_text(), ORIGINAL_RULES,
                         "a signalled run left the probe rules installed")

    def test_a_lost_lease_stops_the_transaction_and_reports_it(self) -> None:
        """A lease lost mid-run must stop the run, not just the renewer.

        The lock is taken with a 1 s TTL and renewed every second, and another task takes it over once
        the probe rules are installed — a real takeover, not a stubbed answer. From then on:

          * no further rule write, because the phone belongs to the other task now;
          * the restore refuses and says the original set was **not** put back;
          * the exit status is non-zero, because "the user's rules are gone" must not exit 0.

        This is the half the previous revision could not see: a failed renewal ended only the
        background subshell, and the transaction kept writing to somebody else's device.
        """
        env = self._env()
        env["LOCK_TTL"] = "1"
        env["LOCK_RENEW_EVERY"] = "1"
        process = subprocess.Popen(
            ["bash", str(SCRIPTS / "tunnel_acceptance.sh"),
             "--origin", self.origin.base_tls,
             "--http-origin", self.origin.base,
             "--https-origin", self.origin.base_tls,
             "--tls1-origin", self.origin.base_tls1,
             "--rounds", "3", "--concurrency", "12"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            cwd=str(fixtures.REPO),
        )
        try:
            # Wait until the probe rules are in place, then take the lock over as another task would.
            deadline = time.time() + 120
            while time.time() < deadline:
                if self.device.rules_text() != ORIGINAL_RULES:
                    break
                if process.poll() is not None:
                    break
                time.sleep(0.1)
            foreign = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self.device.lock.write_text(f"MYS-OTHER {foreign}\n", encoding="utf-8")
            state = Path(str(self.device.lock) + ".state")
            state.mkdir(exist_ok=True)
            (state / "meta").write_text(
                f"owner=MYS-OTHER\nissued={int(time.time())}\n"
                f"renewed={int(time.time())}\ntoken=other-run\n",
                encoding="utf-8",
            )
            stdout, stderr = process.communicate(timeout=240)
        finally:
            if process.poll() is None:  # pragma: no cover - the run ignored the signal
                process.kill()
                stdout, stderr = process.communicate()
        combined = stdout + stderr
        self.assertNotEqual(process.returncode, 0, combined)
        self.assertIn("does not hold the device lock", combined, combined)
        self.assertIn("NOT RESTORED", combined, combined)
        # The renewer's own report names the takeover, so an operator can see *why* the lease went.
        self.assertIn("renewal failed", combined, combined)
        # And the other task's lock is untouched: a run that lost the lease must not delete it.
        self.assertTrue(self.device.lock.read_text().startswith("MYS-OTHER"),
                        "the losing run deleted the new holder's lock")
        self.assertEqual(self.device.meta().get("token"), "other-run")

    def test_an_unreadable_backup_means_nothing_is_written(self) -> None:
        # The UI dump carries no editable field, so the rules cannot be read; the run must stop
        # before installing anything. This is the review's "zero writes" requirement.
        self.device.rules.write_text("<unused>", encoding="utf-8")
        broken = self.device.bin / "adb"
        original = broken.read_text(encoding="utf-8")
        broken.write_text(
            original.replace(
                'if "zs-ui.xml" in command and "cat" in command:',
                'if "zs-ui.xml" in command and "cat" in command:\\n'
                '                print("<hierarchy><node text=\\"something else\\" /></hierarchy>")\\n'
                '                sys.exit(0)\\n'
                '            if False:',
            ),
            encoding="utf-8",
        )
        broken.chmod(0o755)
        rules_before = self.device.rules_text()
        result = self._run()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.device.rules_text(), rules_before,
                         "the run replaced rules it could not back up")
        # Not one rule broadcast: the capture is a precondition, and a failed one writes nothing.
        self.assertEqual(self._broadcast_count(), "0",
                         "the run installed rules despite failing to read the original set")

    def _broadcast_count(self) -> str:
        """How many times the run asked the app to install rules, as a string for the assertion."""
        return str(sum(1 for call in self.device.calls() if "DEBUG_SET_RULES" in " ".join(call)))


if __name__ == "__main__":
    unittest.main()
