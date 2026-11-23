"""The shell tools: the snapshot gate, the device lock, and the retired smoke test.

These run the scripts as subprocesses against temporary `OUT` directories and a stub `adb`, because
the properties under test are about **exit codes and refusals**, not about printing. The stage-2 review
found each of them reporting success out of a missing observation, so every case here pairs a refusal
with the control that shows the same script can still say yes:

  * `tunnel_snapshot.sh check` must exit 0 on a genuinely settled run, and non-zero on a missing
    socket line, an expired run label, a changed pid, a changed uid, and a grown 01/05/08;
  * `condition.sh` must refuse to run without a lock owner, must not take a live lock, must take over
    an expired one, and must release only its own;
  * `concurrency_smoke.py` must refuse every invocation of its retired interface.

The stub `adb` below answers from a prepared map, so nothing here touches a device.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import harness_fixtures as fixtures  # noqa: E402

SCRIPTS = fixtures.SCRIPTS


class SnapshotCheckTest(unittest.TestCase):
    """`check` is the gate the acceptance script polls: exit 0 or it is not a pass."""

    def setUp(self) -> None:
        import tempfile

        self._temp = tempfile.TemporaryDirectory(prefix="zs-snap-")
        self.dir = Path(self._temp.name)
        self.fixture = fixtures.SnapshotFixture(self.dir)
        self.fixture.write("before")
        self.fixture.write("settled")

    def tearDown(self) -> None:
        self._temp.cleanup()

    def test_a_settled_run_passes(self) -> None:
        result = self.fixture.check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("wound down", result.stdout)

    def test_missing_socket_observation_is_not_a_pass(self) -> None:
        # The review's second counter-example: the settled snapshot carried no `sockets=` **key** at
        # all, and the previous version read that as "no sockets" and reported settled. An absent key
        # is not an observation; an empty value is (see the genuinely-empty case below).
        self.fixture.write("settled", omit=("sockets",))
        result = self.fixture.check()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("missing ['sockets']", result.stderr)

    def test_an_unusable_snapshot_is_refused(self) -> None:
        self.fixture.write("settled", ok="no", collected="4/5")
        result = self.fixture.check()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("marked itself unusable", result.stderr)

    def test_an_unreadable_socket_table_is_refused(self) -> None:
        self.fixture.write("settled", readable="no", sockets="")
        result = self.fixture.check()
        self.assertNotEqual(result.returncode, 0)

    def test_a_changed_pid_is_refused(self) -> None:
        self.fixture.write("settled", pid="9999")
        result = self.fixture.check()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("process changed", result.stderr)

    def test_a_changed_uid_is_refused(self) -> None:
        # A reinstall keeps the pid slot and changes the uid; the socket counts then describe a
        # different app, so they cannot be compared.
        self.fixture.write("settled", uid="10999")
        result = self.fixture.check()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("uid changed", result.stderr)

    def test_a_snapshot_from_another_run_is_refused(self) -> None:
        self.fixture.write("settled", run="a-different-run")
        result = self.fixture.check()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("not this run", result.stderr)

    def test_close_wait_growth_is_refused(self) -> None:
        self.fixture.write("before", sockets=" 4 01 ")
        self.fixture.write("settled", sockets=" 4 01  6 08 ")
        result = self.fixture.check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("CLOSE_WAIT grew", result.stderr)

    def test_fin_wait2_growth_is_refused(self) -> None:
        # The review's third counter-example: FIN_WAIT2 grew 0 -> 1000 and the previous version did
        # not look at state 05 at all.
        self.fixture.write("before", sockets=" 4 01 ")
        self.fixture.write("settled", sockets=" 4 01  1000 05 ")
        result = self.fixture.check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("FIN_WAIT2 grew", result.stderr)

    def test_established_growth_beyond_the_allowance_is_refused(self) -> None:
        self.fixture.write("before", sockets=" 4 01 ")
        self.fixture.write("settled", sockets=" 20 01 ")
        result = self.fixture.check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("ESTABLISHED grew", result.stderr)

    def test_app_owned_established_growth_is_refused_even_by_two(self) -> None:
        # The review's case: pid and uid identical, app-owned ESTABLISHED 1 -> 3, and the old gate said
        # "wound down" because it granted the app's own sockets the browser's +2 allowance. The app
        # does not run the browser, so its counts get no allowance at all.
        self.fixture.write("before", sockets=" 1 01 ")
        self.fixture.write("settled", sockets=" 3 01 ")
        result = self.fixture.check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("ESTABLISHED grew 1 -> 3", result.stderr)

    def test_a_genuinely_empty_socket_table_passes(self) -> None:
        # The other side of "a read failure is not an empty table": a readable table with no rows is a
        # real observation, and a run that really closed everything must be able to pass.
        self.fixture.write("before", sockets="")
        self.fixture.write("settled", sockets="")
        result = self.fixture.check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("wound down", result.stdout)

    def test_an_unreadable_table_is_refused_even_when_empty(self) -> None:
        # `readable=no` and "no sockets" are different facts and must not share a representation.
        self.fixture.write("before", sockets="")
        self.fixture.write("settled", sockets="", readable="no")
        result = self.fixture.check()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("read failure is not an empty table", result.stderr)

    def test_a_kernel_wide_growth_is_refused(self) -> None:
        self.fixture.write("before", sockets=" 4 01 ")
        self.fixture.write("settled", sockets=" 4 01 ")
        before = (self.dir / "tunnel-snapshot-accept-before.txt").read_text(encoding="utf-8")
        settled = (self.dir / "tunnel-snapshot-accept-settled.txt").read_text(encoding="utf-8")
        (self.dir / "tunnel-snapshot-accept-before.txt").write_text(
            before.replace("inuse 40", "inuse 40"), encoding="utf-8"
        )
        (self.dir / "tunnel-snapshot-accept-settled.txt").write_text(
            settled.replace("inuse 40", "inuse 400"), encoding="utf-8"
        )
        result = self.fixture.check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("kernel TCP inuse grew", result.stderr)

    def test_missing_files_are_a_refusal_not_a_pass(self) -> None:
        (self.dir / "tunnel-snapshot-accept-settled.txt").unlink()
        result = self.fixture.check()
        self.assertEqual(result.returncode, 2)
        self.assertIn("missing snapshot", result.stderr)


class SnapshotSampleTest(unittest.TestCase):
    """`tunnel_snapshot.sh before|settled` must flag its own sample as usable or not."""

    def setUp(self) -> None:
        import tempfile

        self._temp = tempfile.TemporaryDirectory(prefix="zs-snap-sample-")
        self.dir = Path(self._temp.name)
        self.bin = Path(self._temp.name) / "bin"
        self.bin.mkdir()

    def tearDown(self) -> None:
        self._temp.cleanup()

    def _stub_adb(self, *, pid: str = "4242", uid: str = "10123", sockets: str = " 4 01 ",
                  rss: str = "120000", threads: str = "30", readable: str = "yes") -> None:
        script = textwrap.dedent(
            f"""\
            #!/usr/bin/env bash
            # A stub `adb`: answers the three shapes `tunnel_snapshot.sh` asks for. The uid probe is
            # `dumpsys package … | grep -oE 'appId=[0-9]+' | … | cut -d= -f2`, so the whole pipeline
            # is replaced by the number it would have produced.
            case "$*" in
              *"pidof"*) printf '%s\\n' "{pid}" ;;
              *"dumpsys package"*) printf '%s\\n' "{uid}" ;;
              *"/proc/net/tcp"*) printf 'readable={readable}\\nsockets={sockets}\\nrss_kb={rss}\\nthreads={threads}\\nsockstat=TCP: inuse 40 orphan 0 tw 5 alloc 60 mem 3\\n' ;;
              *) printf '' ;;
            esac
            """
        )
        path = self.bin / "adb"
        path.write_text(script, encoding="utf-8")
        path.chmod(0o755)

    def _sample(self, phase: str = "before") -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(SCRIPTS / "tunnel_snapshot.sh"), phase, "run1"],
            capture_output=True,
            text=True,
            # `SERIAL` names the stub: the tools refuse to invent one, and a fixture that leaves it
            # unset would test the refusal instead of the sampling it is here to check.
            env={**os.environ, "OUT": str(self.dir), "RUN_ID": "run-sample",
                 "SERIAL": "stub:5555", "PATH": f"{self.bin}:{os.environ['PATH']}"},
            cwd=str(fixtures.REPO),
        )

    def test_a_complete_sample_is_marked_usable(self) -> None:
        self._stub_adb()
        result = self._sample()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ok=yes", result.stdout)
        written = (self.dir / "tunnel-snapshot-run1-before.txt").read_text(encoding="utf-8")
        self.assertIn("ok=yes", written)
        self.assertIn("run=run-sample", written)

    def test_a_readable_empty_socket_table_is_usable_and_settles(self) -> None:
        # Zero sockets is a valid measurement when the table was actually readable.
        self._stub_adb(sockets="")
        result = self._sample()
        self.assertIn("ok=yes", result.stdout, result.stdout + result.stderr)
        self.assertIn("ok=yes", self._sample("settled").stdout)
        checked = self._sample("check")
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)

    def test_a_missing_socket_field_is_unusable(self) -> None:
        self._stub_adb(sockets="")
        path = self.bin / "adb"
        path.write_text(path.read_text().replace("sockets=\\n", ""))
        result = self._sample()
        self.assertIn("ok=no", result.stdout, result.stdout + result.stderr)

    def test_an_unreadable_table_is_marked_unusable(self) -> None:
        self._stub_adb(readable="no", sockets="")
        result = self._sample()
        self.assertIn("ok=no", result.stdout)

    def test_a_missing_pid_is_marked_unusable(self) -> None:
        self._stub_adb(pid="")
        result = self._sample()
        self.assertIn("ok=no", result.stdout)


class DeviceLockTest(unittest.TestCase):
    """The shared lock: required owner, atomic take, atomic stale takeover, tokens, expiry.

    The device side is a stub `adb` that redirects the lock directory into a temp directory and runs
    the protocol script with the same `sh`. That is a faithful stand-in for `mkdir`/`mv`/`sed`/`date`
    on `/data/local/tmp`, so the *script's* decisions are what these tests exercise — including the
    two-runner races, which are real concurrent processes, not simulated.
    """

    def setUp(self) -> None:
        import tempfile

        self._temp = tempfile.TemporaryDirectory(prefix="zs-lock-")
        self.dir = Path(self._temp.name)
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        self.lock = self.dir / "zshield-device.lock"
        self.calls_log = self.dir / "adb-calls.log"
        self._install_stub()

    def tearDown(self) -> None:
        self._temp.cleanup()

    def _install_stub(self) -> None:
        """A stub `adb` whose `shell <script>` runs the script locally with the lock path redirected.

        The protocol bodies are executed with the same `sh`, so `mkdir`, `mv` and `date` behave exactly
        as they do on the device — which is what makes the atomicity claims testable here.
        """
        stub = """#!{python}
# Stub adb: everything after `shell` is run locally. The lock protocol arrives base64-encoded
# (`echo <blob> | base64 -d | sh`), so the stub decodes it, points the lock directory at the test's
# own, and runs it with the same `sh` — the same path the device takes.
import base64, subprocess, sys
args = sys.argv[1:]
with open({log!r}, "a") as handle:
    handle.write(" ".join(args) + "\\n")
if "-s" in args:
    index = args.index("-s")
    del args[index:index + 2]
if not args or args[0] != "shell":
    sys.exit(0)
command = " ".join(args[1:])
if "base64 -d | sh" in command:
    blob = command.rsplit("echo ", 1)[1].split(" | base64", 1)[0]
    body = base64.b64decode(blob).decode()
    for suffix in (".d", ".state", ".guard"):
        body = body.replace("/data/local/tmp/zshield-device.lock" + suffix, {lock!r} + suffix)
    body = body.replace("/data/local/tmp/zshield-device.lock", {lock!r})
    completed = subprocess.run(["sh", "-c", body], capture_output=True, text=True)
    sys.stdout.write(completed.stdout)
    sys.exit(completed.returncode)
case = command
if any(word in case for word in ("uiautomator", "zs-ui.xml", "dumpsys", "logcat",
                                 "wm size", "window displays")):
    sys.exit(0)
sys.exit(0)
""".replace("{python}", sys.executable).replace("{log!r}", repr(str(self.calls_log))) \
   .replace("{lock!r}", repr(str(self.lock)))
        path = self.bin / "adb"
        path.write_text(stub, encoding="utf-8")
        path.chmod(0o755)

    def _run(self, args: list[str], *, owner: str | None = None,
             token: str | None = None) -> subprocess.CompletedProcess:
        env = {**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}", "LOCK_TTL": "7200",
               # The stub `adb` is the device. The tools have no default serial by design.
               "SERIAL": "stub:5555"}
        env.pop("LOCK_OWNER", None)
        env.pop("LOCK_TOKEN", None)
        if owner is not None:
            env["LOCK_OWNER"] = owner
        if token is not None:
            env["LOCK_TOKEN"] = token
        return subprocess.run(
            ["bash", str(SCRIPTS / "condition.sh"), *args],
            capture_output=True, text=True, env=env, cwd=str(fixtures.REPO),
        )

    #: Read the lock's metadata through the same stub, so the assertions describe the device's state.
    #:
    #: The canonical lock **file** carries `<issue> <ISO>`; this protocol's own extras (the token, the
    #: epoch stamps) live in `…lock.state/meta` beside it, exactly as on the device.
    def _meta(self) -> dict:
        meta = Path(str(self.lock) + ".state") / "meta"
        if not meta.exists():
            return {}
        values = {}
        for line in meta.read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                values[key] = value
        return values

    def _seed(self, owner: str, *, renewed_ago: float = 0, token: str = "seeded") -> None:
        """Write a lock the way another task would: canonical line, plus this protocol's state."""
        now = int(time.time())
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - int(renewed_ago)))
        self.lock.write_text(f"{owner} {stamp}\n", encoding="utf-8")
        state = Path(str(self.lock) + ".state")
        state.mkdir(exist_ok=True)
        (state / "meta").write_text(
            f"owner={owner}\nissued={now - int(renewed_ago)}\n"
            f"renewed={now - int(renewed_ago)}\ntoken={token}\n",
            encoding="utf-8",
        )

    def test_a_lock_command_without_an_owner_is_refused(self) -> None:
        result = self._run(["zshield-https"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("without LOCK_OWNER", result.stderr)
        self.assertFalse(self.lock.exists(), "a refused run must not have taken the lock")

    def test_a_run_takes_the_lock_and_records_its_token(self) -> None:
        result = self._run(["lock-take"], owner="MYS-2817", token="tok-a")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        meta = self._meta()
        self.assertEqual(meta.get("owner"), "MYS-2817")
        self.assertEqual(meta.get("token"), "tok-a")
        self.assertIn("token tok-a", result.stdout)

    def test_a_live_lock_held_by_another_task_is_refused(self) -> None:
        self._seed("MYS-9999")
        result = self._run(["lock-take"], owner="MYS-2817", token="tok-a")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("MYS-9999", result.stderr)
        self.assertEqual(self._meta().get("owner"), "MYS-9999", "the holder's lock was overwritten")

    def test_an_expired_lock_is_taken_over(self) -> None:
        self._seed("MYS-9999", renewed_ago=3 * 3600)
        result = self._run(["lock-take"], owner="MYS-2817", token="tok-a")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("took over an expired lock", result.stdout)
        meta = self._meta()
        self.assertEqual(meta.get("owner"), "MYS-2817")
        self.assertEqual(meta.get("token"), "tok-a")

    def test_a_lock_without_readable_metadata_is_never_overwritten(self) -> None:
        # A canonical line nobody can parse: no owner, no time, so no age. Nobody can say whose it is
        # or how old, and the safe answer is 'refuse' rather than 'mine'.
        self.lock.write_text("garbage-without-a-time\n", encoding="utf-8")
        result = self._run(["lock-take"], owner="MYS-2817", token="tok-a")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HELD_UNKNOWN_FORMAT", result.stderr)
        self.assertEqual(self.lock.read_text(), "garbage-without-a-time\n")

    def test_a_directory_at_the_canonical_path_is_never_overwritten(self) -> None:
        # An empty directory has no `meta`, so it is the legacy format with no readable holder: refused,
        # never treated as debris, and never removed.
        self.lock.mkdir()
        result = self._run(["lock-take"], owner="MYS-2817", token="tok-a")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HELD_LEGACY_UNREADABLE", result.stderr)
        self.assertTrue(self.lock.is_dir())

    def test_two_runners_racing_an_expired_lock_produce_one_holder(self) -> None:
        """The case the review asked to have tested: the takeover itself must be atomic.

        Both runners are started against the *same* expired lock at the same moment. Exactly one may
        end up holding it: the claim is a `mv`, and only one `mv` of the same source can succeed.
        """
        self._seed("MYS-DEAD", renewed_ago=3 * 3600)
        results: list[subprocess.CompletedProcess] = []
        lock = threading.Lock()

        def take(token: str) -> None:
            outcome = self._run(["lock-take"], owner="MYS-2817", token=token)
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=take, args=(f"tok-{index}",)) for index in (1, 2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        # At most one holder. The takeover is one critical section, so a second runner may also see
        # the section as busy and refuse before it gets a turn — that is a correct refusal, not a
        # second holder. What must never happen is two exits 0.
        winners = [result for result in results if result.returncode == 0]
        self.assertLessEqual(
            len(winners), 1,
            "both runners took an expired lock: " + "; ".join(
                result.stdout + result.stderr for result in results
            ),
        )
        if winners:
            holder_token = self._meta().get("token")
            self.assertIn(holder_token, {"tok-1", "tok-2"})

    def test_two_runners_racing_a_free_lock_produce_one_holder(self) -> None:
        results: list[subprocess.CompletedProcess] = []
        lock = threading.Lock()

        def take(token: str) -> None:
            outcome = self._run(["lock-take"], owner="MYS-2817", token=token)
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=take, args=(f"tok-{index}",)) for index in (1, 2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        winners = [result for result in results if result.returncode == 0]
        self.assertEqual(len(winners), 1, [r.stdout + r.stderr for r in results])

    def test_release_only_removes_a_lock_carrying_its_own_token(self) -> None:
        self._seed("MYS-2817", token="someone-else")
        result = self._run(["lock-release"], owner="MYS-2817", token="tok-a")
        self.assertTrue(self.lock.exists(), "a lock with another token was deleted")
        self.assertIn("nothing released", result.stderr + result.stdout)

    def test_release_removes_a_lock_carrying_its_own_token(self) -> None:
        self._seed("MYS-2817", token="tok-a")
        result = self._run(["lock-release"], owner="MYS-2817", token="tok-a")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.lock.exists())

    def test_renew_only_refreshes_a_lock_carrying_its_own_token(self) -> None:
        self._seed("MYS-2817", renewed_ago=100, token="tok-a")
        before = self._meta().get("renewed")
        result = self._run(["renew"], owner="MYS-2817", token="tok-a")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertGreater(int(self._meta()["renewed"]), int(before))

        self._seed("MYS-2817", renewed_ago=100, token="someone-else")
        refused = self._run(["renew"], owner="MYS-2817", token="tok-a")
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(self._meta().get("token"), "someone-else")

    def test_a_token_from_one_process_can_be_released_by_another(self) -> None:
        # The acceptance transaction takes the lock in its own process and lets commands run inside
        # it; the release must still be attributable to that transaction, which is what the token is.
        self.assertEqual(self._run(["lock-take"], owner="MYS-2817", token="tok-txn").returncode, 0)
        self.assertTrue(self.lock.exists())
        released = self._run(["lock-release"], owner="MYS-2817", token="tok-txn")
        self.assertEqual(released.returncode, 0, released.stdout + released.stderr)
        self.assertFalse(self.lock.exists())

    def test_a_condition_command_releases_its_own_lock_on_exit(self) -> None:
        # A single-command run must not leave its lock behind: the next run would be blocked by a lock
        # nobody holds. The stub answers every device probe with "nothing", so the condition itself
        # fails — and the exit path must still release the lock it took.
        self._run(["vpn-off"], owner="MYS-2817", token="tok-a")
        self.assertFalse(self.lock.exists(), "the run left its own lock behind")

    def test_a_condition_command_does_not_release_the_transactions_lock(self) -> None:
        # This is the review's item 1 in one assertion: a tool that takes the lock for a multi-command
        # transaction must still hold it after a command inside that transaction finishes.
        self.assertEqual(self._run(["lock-take"], owner="MYS-2817", token="tok-txn").returncode, 0)
        self._run(["vpn-off"], owner="MYS-2817", token="tok-a")
        self.assertTrue(self.lock.exists(), "a nested command released the transaction's lock")
        self.assertEqual(self._meta().get("token"), "tok-txn")

    def test_lock_status_reports_a_free_lock(self) -> None:
        result = self._run(["status"], owner="MYS-2817")
        self.assertIn("free", result.stdout)

    def test_lock_status_reports_a_held_lock_with_its_remaining_lease(self) -> None:
        self._seed("MYS-2817", renewed_ago=60, token="tok-a")
        result = self._run(["status"], owner="MYS-2817")
        self.assertIn("owner=MYS-2817", result.stdout)
        self.assertIn("remaining=", result.stdout)


class RetiredSmokeTest(unittest.TestCase):
    """`concurrency_smoke.py` must refuse every invocation of its old interface."""

    def test_it_refuses_and_names_the_replacement(self) -> None:
        result = fixtures.run_script(
            [sys.executable, str(SCRIPTS / "concurrency_smoke.py"),
             "--rounds", "5", "--concurrency", "20"]
        )
        code, out, err = result
        self.assertNotEqual(code, 0, out + err)
        self.assertIn("REFUSED", err)
        self.assertIn("tunnel_acceptance.sh", err)
        self.assertIn("were not run", err)

    def test_it_refuses_with_no_arguments_too(self) -> None:
        code, _out, err = fixtures.run_script(
            [sys.executable, str(SCRIPTS / "concurrency_smoke.py")]
        )
        self.assertNotEqual(code, 0, err)
        self.assertIn("REFUSED", err)


class AcceptanceScriptContractTest(unittest.TestCase):
    """The acceptance entry point's own contracts, checked without a device."""

    def test_it_refuses_to_run_without_a_controlled_origin(self) -> None:
        # Without `--origin` there is nothing that can report an id or a body digest, so the run would
        # be the "weak echo" case the assertions reject. It stops before touching the device.
        result = subprocess.run(
            ["bash", str(SCRIPTS / "tunnel_acceptance.sh"), "--rounds", "1", "--concurrency", "1"],
            capture_output=True, text=True, cwd=str(fixtures.REPO),
            env={**os.environ, "SERIAL": "127.0.0.1:1"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--origin", result.stderr)
        self.assertIn("controlled origin", result.stderr)
        # And it stops there: no device step ran, so no adb output is present.
        self.assertNotIn("tunnel:   IS_VPN", result.stdout)

    def test_it_has_no_hard_coded_rule_count_or_public_echo(self) -> None:
        # The two literals the review found: a catalog size that no longer exists, and an echo host
        # the run does not control.
        text = (SCRIPTS / "tunnel_acceptance.sh").read_text(encoding="utf-8")
        self.assertNotIn("2772", text)
        self.assertNotIn("httpbin", text.replace("httpbin-style", ""))

    def test_the_harness_has_no_hard_coded_public_echo_default(self) -> None:
        text = (SCRIPTS / "tunnel_concurrency.py").read_text(encoding="utf-8")
        self.assertNotIn("httpbingo.org", text)
        self.assertNotIn("httpbin.org/anything", text)


if __name__ == "__main__":
    unittest.main()
