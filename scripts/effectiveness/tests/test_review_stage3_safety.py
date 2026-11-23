"""The stage-3 safety probe, and the interleavings it could only model.

`review_stage3_safety.py` is the script the tech lead attached to MYS-2820, copied here **verbatim**
(`review/review_stage3_safety.py`; `cmp` against the attachment is byte-identical). Against the previous
revision it printed, and `review/stage3-r2-safety-before.log` is that run:

    active_canonical_lock:       take_exit=0;  canonical_unchanged=True; accepted=True
    stale_takeover_interleaving: A_exit=0; B_exit=0; both_acquired=True
    literal_marker_backup:       original='（空）'; known=True; stored=''; lossy=True

Two things about how this probe reports, which the assertions below respect:

* it has **no failure counter and no exit status for its verdicts** — it prints three lines and exits
  0 either way. The verdicts are the contract;
* its `lossy=` term is `state['rules'] != '（空）'`, so a capture that correctly **refuses** also prints
  `lossy=True` (nothing was stored, which is not the original). A refusal is not a loss, and the real
  property — "no rule was written and the capture said so" — is asserted from `known`/`stored` below.

What no longer runs is one line of the probe's own **diagnostics**: it prints
`(lock/'meta').read_text()` to describe the final lock, and `lock/meta` is the previous revision's
internal layout. The lock is now the canonical **file** `AGENTS.md` specifies, so that print raises
`NotADirectoryError` after the case's verdict has already been computed. So:

  * `VerbatimProbeTest` runs the attachment unmodified, asserts its first verdict, and drives the
    second and third properties directly with the probe's own fixtures and barrier technique;
  * `ProbeDerivedTest` runs a copy whose only change is that one diagnostic line, so the whole script
    finishes;
  * `test_the_derived_probe_can_still_fail` breaks the lock deliberately and requires the first verdict
    to flip back to `accepted=True`, so "all three answered" cannot mean "it stopped checking".

`test_device_transaction.py` repeats every property with two real processes, so a failure there names
the property rather than only "the script disagreed".
"""

from __future__ import annotations

import errno
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import harness_fixtures as fixtures  # noqa: E402

HERE = Path(__file__).resolve().parent
PROBE = HERE / "review" / "review_stage3_safety.py"
BEFORE = HERE / "review" / "stage3-r2-safety-before.log"


def stage_tree(destination: Path) -> Path:
    """A `zshield-android` tree the probe can find beside itself."""
    tree = destination / "zshield-android"
    (tree / "scripts").mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        fixtures.SCRIPTS,
        tree / "scripts" / "effectiveness",
        ignore=shutil.ignore_patterns("tests", "__pycache__", ".effectiveness"),
    )
    return tree


class ProbeCase(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory(prefix="zs-safety-")
        self.dir = Path(self._temp.name)
        self.tree = stage_tree(self.dir)

    def tearDown(self) -> None:
        self._temp.cleanup()

    def run_probe(self, script: Path, tree: Path | None = None) -> subprocess.CompletedProcess:
        run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=self.dir))
        target = run_dir / script.name
        shutil.copy(script, target)
        (run_dir / "zshield-android").symlink_to(tree or self.tree)
        return subprocess.run(
            [sys.executable, str(target)],
            capture_output=True, text=True, timeout=300, cwd=str(run_dir),
            env={**os.environ, "PYTHONPATH": str((tree or self.tree) / "scripts" / "effectiveness")},
        )


class VerbatimProbeTest(ProbeCase):
    """The attachment, unmodified: its verdicts hold, and its one obsolete print no longer runs."""

    def test_the_attachment_is_byte_identical(self) -> None:
        attached = (HERE / "review" / "review_stage3_safety.py").read_bytes()
        self.assertEqual(attached, PROBE.read_bytes(),
                         "the probe kept here is not the attachment any more")
        # The "before" log is what the fix is measured against, so it has to be the failing run.
        before = BEFORE.read_bytes()
        self.assertIn(b"accepted=True", before)
        self.assertIn(b"both_acquired=True", before)
        self.assertIn(b"lossy=True", before)

    def test_the_live_canonical_lock_is_refused(self) -> None:
        """Case 1, from the attachment's own output."""
        result = self.run_probe(PROBE)
        self.assertIn("accepted=False", result.stdout + result.stderr,
                     "the probe's first case did not pass:\n" + result.stdout + result.stderr)
        self.assertIn("canonical_unchanged=True", result.stdout + result.stderr)

    def test_the_takeover_interleaving_yields_at_most_one_holder(self) -> None:
        """Case 2, with the probe's own fixtures and its barrier on the rename.

        The probe pauses runner B immediately before the rename it used to perform, starts A while B is
        paused, then lets B go. The old code let both exit 0 and B's rename removed A's fresh lock. Now
        the rename is inside the critical section B already holds, so A is refused before it decides
        anything — one holder, and the lock it left is B's.
        """
        library = self.tree / "scripts" / "effectiveness" / "device-lock.sh"
        with tempfile.TemporaryDirectory(prefix="zs-case2-") as raw:
            work = Path(raw)
            bindir = work / "bin"
            bindir.mkdir()
            stub = bindir / "adb"
            stub.write_text(
                "#!/usr/bin/env python3\n"
                "import base64, os, re, subprocess, sys\n"
                # `\\|` in this (non-raw) string is `\|` in the file — the escaped pipe the probe's own
                # stub uses. Getting this wrong makes the stub match nothing and read as "no verdict",
                # which is a fixture failure rather than a lock failure.
                #
                # The decoded script inherits this process's stdout/stderr rather than being captured
                # and re-printed: the verdict **is** the script's last stdout line, and a stub that
                # captured it without forwarding would report "no usable verdict" for every call.
                'encoded = re.search(r"echo ([A-Za-z0-9+/=]+) \\| base64 -d", sys.argv[-1]).group(1)\n'
                "script = base64.b64decode(encoded).decode().replace('/data/local/tmp', "
                "os.environ['PROBE_DEVICE'])\n"
                "raise SystemExit(subprocess.run(['sh', '-c', script]).returncode)\n"
            )
            stub.chmod(0o755)
            # The same barrier the probe installs: hold runner B just before its rename.
            barrier = bindir / "mv"
            barrier.write_text(
                "#!/usr/bin/env python3\n"
                "import os, pathlib, subprocess, sys, time\n"
                "d = pathlib.Path(os.environ['PROBE_DEVICE'])\n"
                "if sys.argv[-1].endswith('.stale.B'):\n"
                "    (d/'ready').touch()\n"
                "    deadline = time.monotonic()+20\n"
                "    while not (d/'resume').exists():\n"
                "        if time.monotonic()>deadline: raise SystemExit(3)\n"
                "        time.sleep(.01)\n"
                "raise SystemExit(subprocess.run(['/usr/bin/mv', *sys.argv[1:]]).returncode)\n"
            )
            barrier.chmod(0o755)
            env = {
                **os.environ,
                "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
                "PROBE_DEVICE": str(work),
                "LOCK_OWNER": "review",
                "LOCK_TOKEN": "A",
                # Stub adb below is the device; without a serial the library refuses before the
                # barrier this case is built on is ever reached.
                "SERIAL": "stub:5555",
            }
            for key in ("LOCK_PATH", "LOCK_STATE_DIR", "LOCK_LEGACY_DIR", "LOCK_GUARD_DIR", "LOCK_TTL"):
                env.pop(key, None)
            lock = work / "race-lock"
            lock.mkdir()
            (lock / "meta").write_text("owner=old\nissued=1\nrenewed=1\ntoken=old\n")
            command = f'source "{library}"; lock_take'
            race_env = {**env, "LOCK_PATH": str(lock)}
            b = subprocess.Popen(["bash", "-c", command], env={**race_env, "LOCK_TOKEN": "B"},
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 30
                while not (work / "ready").exists():
                    if time.monotonic() > deadline:
                        self.fail("the barrier was never reached: runner B did not attempt the rename")
                    time.sleep(0.01)
                a = subprocess.run(["bash", "-c", command], env=race_env,
                                   capture_output=True, text=True, timeout=60)
                (work / "resume").touch()
                bout, berr = b.communicate(timeout=60)
            finally:
                if b.poll() is None:
                    b.kill()
                    b.communicate()
            # Assertions inside the `with`: the temporary directory is gone once it exits, and these
            # read the files the two runners left behind.
            self.assertFalse(
                a.returncode == 0 and b.returncode == 0,
                f"both contenders acquired the lock:\nA({a.returncode}): {a.stdout}{a.stderr}\n"
                f"B({b.returncode}): {bout}{berr}",
            )
            self.assertEqual(b.returncode, 0, f"the runner already inside the section failed: {berr}")
            # A is refused because B, inside the section, already owns the decision — not because it
            # lost a rename race after the fact.
            self.assertIn("GUARD_BUSY", a.stderr,
                          "A was not refused by the critical section:\n" + a.stdout + a.stderr)
            # The lock left behind belongs to B. The legacy directory lock it took over is gone
            # (renamed away and removed), so what remains at the canonical path is the file B wrote.
            self.assertTrue(lock.is_file(), "B wrote no canonical lock after the takeover")
            self.assertEqual(lock.read_text().split()[0], "review")
            survived = (Path(str(lock) + ".state") / "meta").read_text()
            self.assertIn("token=B", survived,
                          "the surviving lock is not the one held inside the section")

    def test_a_literal_blank_marker_is_not_stored_as_empty(self) -> None:
        """Case 3, against the tree under test: a refusal, not a lossy value."""
        probe = self.dir / "case3.py"
        probe.write_text(
            "import importlib.util, sys\n"
            f'spec = importlib.util.spec_from_file_location("rb", r"{self.tree}/scripts/effectiveness/rules_backup.py")\n'
            "m = importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(m)\n"
            "class D:\n"
            "    def start_debug_screen(self): pass\n"
            "    def dump_ui(self): return '<hierarchy><node text=\"自定义规则：（空）\" /></hierarchy>'\n"
            'state = m.read_rules(D(), source="debug")\n'
            'print(f"known={state[\'known\']}; stored={state[\'rules\']!r}; lossy={state[\'rules\'] is not None and state[\'rules\'] != \'（空）\'}")\n',
            encoding="utf-8",
        )
        result = subprocess.run([sys.executable, str(probe)], capture_output=True, text=True, timeout=120)
        output = result.stdout + result.stderr
        self.assertIn("known=False", output, output)
        self.assertIn("stored=None", output, output)
        self.assertIn("lossy=False", output, output)


class ProbeDerivedTest(ProbeCase):
    """The same probe with its one obsolete diagnostic line updated, so all three cases complete."""

    def derived(self) -> Path:
        source = PROBE.read_text(encoding="utf-8")
        updated = source.replace(
            "final_meta={(lock/'meta').read_text()!r}",
            "final_lock={lock.read_text()!r}",
        )
        self.assertNotEqual(updated, source, "the diagnostic line the probe prints has moved")
        path = self.dir / "review_stage3_safety_derived.py"
        path.write_text(updated, encoding="utf-8")
        return path

    def test_all_three_verdicts_are_answered(self) -> None:
        result = self.run_probe(self.derived())
        output = result.stdout + result.stderr
        self.assertIn("accepted=False", output, output)
        self.assertIn("both_acquired=False", output, output)
        self.assertIn("known=False", output, output)
        self.assertIn("stored=None", output, output)

    def test_the_derived_probe_can_still_fail(self) -> None:
        """The control: ignore the canonical lock again and the first verdict must flip.

        Without this, "all three answered" could mean the probe stopped checking. The break is minimal
        — the lock stops consulting the canonical path — and nothing else changes.
        """
        broken = self.dir / "broken-tree"
        shutil.copytree(self.tree, broken)
        library = broken / "scripts" / "effectiveness" / "device-lock.sh"
        source = library.read_text(encoding="utf-8")
        source = source.replace(
            'LOCK_PATH="${LOCK_PATH:-/data/local/tmp/zshield-device.lock}"',
            'LOCK_PATH="${LOCK_PATH:-/data/local/tmp/zshield-device.lock.private}"',
            1,
        )
        self.assertNotIn('LOCK_PATH="${LOCK_PATH:-/data/local/tmp/zshield-device.lock}"', source)
        library.write_text(source, encoding="utf-8")
        result = self.run_probe(self.derived(), tree=broken)
        output = result.stdout + result.stderr
        self.assertIn("accepted=True", output,
                      "the probe did not notice that the canonical lock was being ignored:\n" + output)


if __name__ == "__main__":
    unittest.main()
