"""The two review scripts attached to the parent issue must exit 0 against this tree.

They are the *independent* reproductions the reviewer wrote to prove the harness accepted invalid
input. Keeping them runnable is the point: a harness that only satisfies its own tests has not been
checked by anyone else, and the acceptance criterion for this stage names both files by name.

This file copies them into a scratch tree, places the checkout where they expect it (`./zshield-android`,
next to the script), and runs them. **Their assertions are not modified** — the only adaptation is the
path, which the scripts' own `Path(__file__).parent / 'zshield-android'` already expects, so a plain
copy next to the checkout is the whole of it.

Each test also asserts the script *can* fail: `review_stage2_r2.py` is fed a deliberately broken copy
of `tunnel_snapshot.sh` and must then exit non-zero, which is what makes its exit 0 above meaningful.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import harness_fixtures as fixtures  # noqa: E402

HERE = Path(__file__).resolve().parent
REVIEW_SCRIPTS = HERE / "review" / "review_stage2_harness.py", HERE / "review" / "review_stage2_r2.py"


def stage_tree(destination: Path, name: str = "zshield-android") -> Path:
    """Copy the repository's scripts next to the review script, as the review expects them.

    The scripts do `Path(__file__).parent / 'zshield-android/scripts/effectiveness/...'`, so the
    fixture is a directory holding the review script and a `zshield-android` tree with the scripts
    under test. Copying only `scripts/` keeps it small and removes any chance of a test editing the
    real checkout.
    """
    tree = destination / name
    (tree / "scripts").mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        fixtures.SCRIPTS, tree / "scripts" / "effectiveness",
        ignore=shutil.ignore_patterns("tests", "__pycache__"),
    )
    return tree


class ReviewScriptsTest(unittest.TestCase):
    """Both attached review scripts exit 0, and each is shown able to fail."""

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory(prefix="zs-review-")
        self.dir = Path(self._temp.name)
        self.tree = stage_tree(self.dir)

    def tearDown(self) -> None:
        self._temp.cleanup()

    def _run(self, script: Path, tree: Path | None = None, timeout: float = 180.0):
        """Run one review script with `zshield-android` beside it pointing at `tree`."""
        tree = tree or self.tree
        # Each run gets its own directory, so the sibling name the scripts hard-code can point at the
        # tree under test without two tests fighting over it.
        run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=self.dir))
        target = run_dir / script.name
        shutil.copy(script, target)
        (run_dir / "zshield-android").symlink_to(tree)
        return subprocess.run(
            [sys.executable, str(target)],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(run_dir),
            # The review scripts drive the real tools, which have no default device serial; these
            # probes are host-only, so the serial only has to be present and unambiguous.
            env={**os.environ, "PYTHONPATH": str(tree / "scripts"), "SERIAL": "stub:5555"},
        )

    def test_review_stage2_harness_exits_zero(self) -> None:
        result = self._run(REVIEW_SCRIPTS[0])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # Its four probes: three must be DETECTED and the empty-batch entry point must exit non-zero.
        self.assertIn("DETECTED", result.stdout)
        self.assertNotIn("MISSED", result.stdout)
        self.assertIn("0/4", result.stdout)

    def test_review_stage2_r2_exits_zero(self) -> None:
        result = self._run(REVIEW_SCRIPTS[1])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("missed=False", result.stdout)
        self.assertIn("0/3", result.stdout)

    def test_review_stage2_r2_can_still_fail(self) -> None:
        """The control: break the snapshot gate and the review script must notice.

        Without this, "exit 0" could mean the script stopped checking anything. Only the two snapshot
        probes regress here (the request-id probe is Python and is untouched), so the expected result
        is 2/3 accepted — a non-zero exit and a report that says so.
        """
        broken = self.dir / "broken-tree"
        shutil.copytree(self.tree, broken)
        snapshot = broken / "scripts" / "effectiveness" / "tunnel_snapshot.sh"
        snapshot.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        snapshot.chmod(0o755)
        result = self._run(REVIEW_SCRIPTS[1], tree=broken)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("2/3 invalid observations falsely accepted", result.stdout)

    def test_review_stage2_harness_can_still_fail(self) -> None:
        broken = self.dir / "broken-tree-2"
        shutil.copytree(self.tree, broken)
        harness = broken / "scripts" / "effectiveness" / "tunnel_concurrency.py"
        source = harness.read_text(encoding="utf-8")
        # A checker that accepts everything: the review script must report the misses.
        harness.write_text(
            source.replace(
                "def check_one(result: dict, scope: dict, expect: dict) -> list[str]:",
                "def check_one(result: dict, scope: dict, expect: dict) -> list[str]:\n"
                "    return []  # deliberately broken for the control case\n\n"
                "def _check_one_original(result, scope, expect) -> list[str]:",
                1,
            ),
            encoding="utf-8",
        )
        result = self._run(REVIEW_SCRIPTS[0], tree=broken)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("MISSED", result.stdout)


if __name__ == "__main__":
    unittest.main()
