#!/usr/bin/env python3
"""`scripts/build.sh` and `scripts/gen-keystore.sh`: the refusals that protect the release identity.

Three properties of the build entry point are safety properties, not conveniences, and each one is a
way a release has gone wrong somewhere before:

1. **A missing keystore stops the build** — with a freshly generated key it silently replaced the
   official signing identity, and every APK it produced was un-upgradable over the installed one.
2. **A build that cannot be signed destroys nothing** — the cleanup step used to run first, so a
   failed keystore check wiped the previous `dist/` artifact on its way to failing.
3. **`gen-keystore.sh` never overwrites** — losing the key store is losing the ability to upgrade.

These are checked by running the real scripts against a temporary keystore directory, so a future
edit that reintroduces the shortcut fails here rather than at release time. The cases stop before any
Gradle or cargo work: each of them is a refusal, which is exactly the code path that must be cheap.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent.parent  # scripts/effectiveness/tests -> scripts/
REPO = SCRIPTS.parent
BUILD = SCRIPTS / "build.sh"
GEN_KEYSTORE = SCRIPTS / "gen-keystore.sh"


def _script_env(**extra: str) -> dict:
    env = {key: value for key, value in os.environ.items()
           if key not in ("ZSHIELD_KEYSTORE_DIR", "ZSHIELD_RELEASE_KEYSTORE",
                          "ZSHIELD_KEYSTORE_PROPERTIES")}
    env.update(extra)
    return env


class MissingKeystoreTest(unittest.TestCase):
    """A release build without signing material refuses, and says how to supply it."""

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory(prefix="zs-build-")
        self.dir = Path(self._temp.name)
        self.keystore_dir = self.dir / "signing"  # deliberately never created

    def tearDown(self) -> None:
        self._temp.cleanup()

    def test_a_release_build_without_signing_material_is_refused(self) -> None:
        result = subprocess.run(
            ["bash", str(BUILD), "release"],
            capture_output=True, text=True, timeout=180, cwd=str(REPO),
            env=_script_env(ZSHIELD_KEYSTORE_DIR=str(self.keystore_dir)),
        )
        self.assertNotEqual(result.returncode, 0, "a release build must not proceed unsigned")
        self.assertIn("签名材料不存在", result.stderr)
        # The refusal names both files and both ways out, so the reader does not have to guess.
        self.assertIn("release.jks", result.stderr)
        self.assertIn("keystore.properties", result.stderr)
        self.assertIn("gen-keystore.sh", result.stderr)
        self.assertIn("ZSHIELD_KEYSTORE_DIR", result.stderr)

    def test_the_refusal_does_not_generate_a_key(self) -> None:
        subprocess.run(
            ["bash", str(BUILD), "release"],
            capture_output=True, text=True, timeout=180, cwd=str(REPO),
            env=_script_env(ZSHIELD_KEYSTORE_DIR=str(self.keystore_dir)),
        )
        self.assertFalse(
            (self.keystore_dir / "release.jks").exists(),
            "the build created signing material on its own — that is the identity-replacement bug",
        )

    def test_a_failed_build_preserves_the_previous_artifact(self) -> None:
        """The cleanup step must not run before the check that can fail.

        The marker file stands in for the previous release: if it survives a refused build, then a
        real `dist/zshield-*.apk` would have survived too.
        """
        dist = REPO / "dist"
        marker = dist / "PRESERVED_BY_TEST"
        created_dist = not dist.exists()
        dist.mkdir(exist_ok=True)
        marker.write_text("previous artifact\n", encoding="utf-8")
        try:
            result = subprocess.run(
                ["bash", str(BUILD), "release"],
                capture_output=True, text=True, timeout=180, cwd=str(REPO),
                env=_script_env(ZSHIELD_KEYSTORE_DIR=str(self.keystore_dir)),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(marker.is_file(),
                            "a refused build deleted dist/ — the check must precede the cleanup")
        finally:
            marker.unlink(missing_ok=True)
            if created_dist and dist.is_dir() and not any(dist.iterdir()):
                dist.rmdir()


class KeystoreGenerationTest(unittest.TestCase):
    """`gen-keystore.sh` honours the override directory and never replaces existing material."""

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory(prefix="zs-keystore-")
        self.dir = Path(self._temp.name)
        self.keystore_dir = self.dir / "signing"

    def tearDown(self) -> None:
        self._temp.cleanup()

    def _generate(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(GEN_KEYSTORE)],
            capture_output=True, text=True, timeout=180, cwd=str(REPO),
            env=_script_env(ZSHIELD_KEYSTORE_DIR=str(self.keystore_dir)),
        )

    def test_the_override_directory_is_used(self) -> None:
        result = self._generate()
        if result.returncode != 0 and "keytool not found" in result.stderr:
            self.skipTest("no keytool on this machine")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.keystore_dir / "release.jks").is_file())
        properties = self.keystore_dir / "keystore.properties"
        self.assertTrue(properties.is_file())
        self.assertEqual(properties.stat().st_mode & 0o777, 0o600,
                         "the password file must not be world-readable")
        # The override really is what was used: the default location was not touched by this run.
        self.assertNotIn(str(Path.home() / ".config" / "zshield"), result.stdout.replace(
            str(self.keystore_dir), "").replace("请自行备份", ""))

    def test_a_second_run_keeps_the_existing_key(self) -> None:
        first = self._generate()
        if first.returncode != 0 and "keytool not found" in first.stderr:
            self.skipTest("no keytool on this machine")
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        key = self.keystore_dir / "release.jks"
        before = key.read_bytes()

        second = self._generate()
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertIn("保持不变", second.stdout)
        self.assertEqual(key.read_bytes(), before,
                         "a re-run replaced the key store — previously signed APKs become un-upgradable")


class BuildPathRemappingTest(unittest.TestCase):
    """The remap flags, and the mechanism that carries them.

    Two properties here are regressions found by review, not invented:

    * the flags must be ordered so `rustc` applies the most specific rule — `rustc` applies the
      **last** matching `--remap-path-prefix`, not the longest, so `$HOME` comes before
      `$HOME/.cargo`, and the repository after its parent;
    * they must travel in `CARGO_ENCODED_RUSTFLAGS`, not `RUSTFLAGS`, because (a) the encoded
      variable *overrides* `RUSTFLAGS` outright, so an inherited one silently discarded the
      remapping, and (b) `RUSTFLAGS` is whitespace-split, so a checkout under a path containing a
      space produced broken flags.

    The merge function is exercised in a real shell, with a repository path that contains a space.
    """

    SPACED_REPO = "/home/me/My Project/zshield-android"

    def _function_body(self, name: str) -> str:
        source = BUILD.read_text(encoding="utf-8")
        match = re.search(rf"^{name}\(\) \{{(?P<body>.*?)^\}}", source,
                          re.DOTALL | re.MULTILINE)
        self.assertIsNotNone(match, f"{name} is gone from build.sh")
        return match.group("body")

    def _run(self, script: str, **env: str) -> subprocess.CompletedProcess:
        preamble = (
            "set -uo pipefail\n"
            f"REPO_ROOT={self.SPACED_REPO!r}\n"
            "HOME=/home/me\n"
            # The bodies are re-wrapped, not pasted bare: `remap_rustflags` takes `$1` and both use
            # `local`, so they are only valid inside a function definition.
            + "remap_rustflags() {" + self._function_body("remap_rustflags") + "}\n"
            + "merge_rustflags() {" + self._function_body("merge_rustflags") + "}\n"
        )
        base = {k: v for k, v in os.environ.items()
                if k not in ("CARGO_ENCODED_RUSTFLAGS", "RUSTFLAGS")}
        return subprocess.run(["bash", "-c", preamble + script],
                              capture_output=True, text=True, timeout=60, env={**base, **env})

    @staticmethod
    def _flags(stdout: str) -> list[str]:
        return [line.strip() for line in stdout.splitlines() if line.strip()]

    #: Prints one flag per line. The separator is produced by `printf` rather than written literally,
    #: so no layer of quoting has to carry a `\x1f` through.
    _DUMP = 'printf "%s" "$(merge_rustflags)" | tr "\\037" "\\n"'

    def _merged_flags(self, setup: str = "", **env: str) -> list[str]:
        result = self._run(setup + "\n" + self._DUMP, **env)
        self.assertEqual(result.returncode, 0,
                         f"setup failed: {setup!r}\n{result.stderr}")
        return self._flags(result.stdout)

    def test_general_home_rule_comes_before_the_specific_ones(self) -> None:
        body = self._function_body("remap_rustflags")
        home = body.index("--remap-path-prefix=$HOME=/home/build")
        cargo = body.index("--remap-path-prefix=$HOME/.cargo=/cargo")
        rustup = body.index("--remap-path-prefix=$HOME/.rustup=/rustup")
        self.assertLess(home, cargo,
                        "`$HOME` must come first: rustc applies the LAST matching prefix")
        self.assertLess(home, rustup)

    def test_the_repository_rule_comes_last(self) -> None:
        body = self._function_body("remap_rustflags")
        self.assertLess(body.index("dirname"),
                        body.index("--remap-path-prefix=$repo_root=/zshield"),
                        "the repository is more specific than its parent and must come last")

    def test_a_repository_path_with_a_space_survives_as_one_flag(self) -> None:
        flags = self._merged_flags("unset CARGO_ENCODED_RUSTFLAGS RUSTFLAGS")
        spaced = [flag for flag in flags if "My Project" in flag]
        self.assertEqual(len(spaced), 2, f"the spaced path was split or lost: {flags}")
        for flag in spaced:
            self.assertTrue(flag.startswith("--remap-path-prefix="), flag)

    def test_an_inherited_rustflags_is_kept_not_discarded(self) -> None:
        flags = self._merged_flags(
            "unset CARGO_ENCODED_RUSTFLAGS; RUSTFLAGS='--cfg caller_a --cfg caller_b'")
        self.assertIn("caller_a", flags, f"an inherited RUSTFLAGS was dropped: {flags}")
        self.assertIn("caller_b", flags)
        self.assertTrue(any("--remap-path-prefix=" in flag for flag in flags),
                        "the remapping must still be appended")

    def test_an_inherited_encoded_flags_value_is_kept(self) -> None:
        """The variable this script writes is the one that overrides `RUSTFLAGS`; it must be merged."""
        flags = self._merged_flags(
            "unset RUSTFLAGS; sep=$(printf '\\037'); "
            'CARGO_ENCODED_RUSTFLAGS="--cfg${sep}caller encoded"')
        self.assertIn("caller encoded", flags,
                      f"an element containing a space was split or dropped: {flags}")
        self.assertTrue(any("--remap-path-prefix=" in flag for flag in flags))

    def test_a_repository_directly_under_root_gets_no_parent_rule(self) -> None:
        """`--remap-path-prefix=/=…` would rewrite every absolute path in the build."""
        flags = self._merged_flags("unset CARGO_ENCODED_RUSTFLAGS RUSTFLAGS; REPO_ROOT=/zshield")
        self.assertNotIn("--remap-path-prefix=/=/build", flags)
        self.assertIn("--remap-path-prefix=/zshield=/zshield", flags)

    def test_the_flags_are_exported_through_the_encoded_variable(self) -> None:
        """A `RUSTFLAGS`-only build would lose the remapping whenever the caller set the encoded one."""
        source = BUILD.read_text(encoding="utf-8")
        self.assertIn("CARGO_ENCODED_RUSTFLAGS=\"$(merge_rustflags)\"", source)
        self.assertIn("export CARGO_ENCODED_RUSTFLAGS", source)
        self.assertNotIn("export RUSTFLAGS=", source,
                         "RUSTFLAGS is overridden by the encoded variable; setting it invites drift")


if __name__ == "__main__":
    unittest.main()
