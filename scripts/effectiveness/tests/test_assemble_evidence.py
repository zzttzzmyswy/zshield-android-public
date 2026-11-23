"""The evidence bundle must be reproducible, secret-free, and self-verifying.

The first delivery had no bundle at all — it referred to `<campaign-dir>`, a path on the machine that
produced it, which no reviewer can resolve. A bundle is only worth attaching if a reader can (a) check
that the bytes arrived intact and (b) run the recompute from inside it. Both are checked here, and so
is the one thing that must never happen: a key or a keystore travelling with the data.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent
REPO = SCRIPTS.parent

SPEC = importlib.util.spec_from_file_location("assemble_evidence",
                                              SCRIPTS / "assemble_evidence.py")
assemble = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules["assemble_evidence"] = assemble
SPEC.loader.exec_module(assemble)


def make_campaign(root: Path) -> Path:
    """A minimal campaign directory: a plan, one batch, and one raw meminfo answer."""
    campaign = root / "campaign"
    batch = campaign / "fixed-five--candidate--b1"
    raw = batch / "pss-fixed-five-candidate-b1.raw"
    raw.mkdir(parents=True)
    (campaign / "campaign.json").write_text(json.dumps({"plan": {}, "batches": []}),
                                            encoding="utf-8")
    (batch / "result.txt").write_text("1\t0\t90000\t5000\t60000\t4242\t1\t1\n", encoding="utf-8")
    (raw / "meminfo-1.txt").write_text("** MEMINFO in pid 4242 [top.zztweb.zshield] **\n"
                                       "        TOTAL PSS:    90000\n", encoding="utf-8")
    (batch / "apk-sha256-before.txt").write_text(f"{'a' * 64}  top.zztweb.zshield\n", encoding="utf-8")
    (batch / "apk-sha256-after.txt").write_text(f"{'a' * 64}  top.zztweb.zshield\n", encoding="utf-8")
    return campaign


class TheBundleIsSelfVerifying(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="zs-bundle-")
        self.root = Path(self._tmp.name)
        self.campaign = make_campaign(self.root)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _assemble(self) -> Path:
        out = self.root / "bundle.tar.gz"
        status = assemble.main(["--campaign", str(self.campaign), "--out", str(out)])
        self.assertEqual(status, 0)
        return out

    def _extract(self, bundle: Path) -> Path:
        target = self.root / "extracted"
        target.mkdir()
        with tarfile.open(bundle, "r:gz") as archive:
            archive.extractall(target, filter="data")
        return target

    def test_the_bundle_extracts_with_a_manifest_that_verifies(self) -> None:
        bundle = self._assemble()
        extracted = self._extract(bundle)
        self.assertTrue((extracted / "MANIFEST.sha256").is_file())
        result = subprocess.run(["sha256sum", "-c", "MANIFEST.sha256"], cwd=extracted,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("FAILED", result.stdout)

    def test_the_bundle_carries_the_tool_and_a_runnable_relative_command(self) -> None:
        # A reviewer must be able to run the recompute from inside the extracted directory: the
        # command uses relative paths only, and the tool it names is in the bundle.
        extracted = self._extract(self._assemble())
        self.assertTrue((extracted / "scripts/effectiveness/memory_profile.py").is_file())
        provenance = json.loads((extracted / "provenance.json").read_text(encoding="utf-8"))
        command = provenance["recompute_command"]
        self.assertNotIn("/tmp", command)
        self.assertNotIn(str(self.root), command)
        self.assertTrue(command.startswith("python3 scripts/effectiveness/memory_profile.py"))
        self.assertIn("campaign", command)

    def test_the_bundle_refuses_to_carry_a_key(self) -> None:
        (self.campaign / "release.jks").write_bytes(b"not really a keystore")
        with self.assertRaises(SystemExit) as raised:
            assemble.main(["--campaign", str(self.campaign), "--out",
                           str(self.root / "bundle.tar.gz")])
        self.assertIn("secret", str(raised.exception).lower())

    def test_a_keystore_properties_file_is_refused_too(self) -> None:
        (self.campaign / "keystore.properties").write_text("storePassword=x\n", encoding="utf-8")
        with self.assertRaises(SystemExit):
            assemble.main(["--campaign", str(self.campaign), "--out",
                           str(self.root / "bundle.tar.gz")])

    def test_the_manifest_lists_every_file_including_the_raw_answers(self) -> None:
        extracted = self._extract(self._assemble())
        listed = {line.split("  ", 1)[1]
                  for line in (extracted / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines()
                  if line.strip()}
        on_disk = {path.relative_to(extracted).as_posix()
                   for path in extracted.rglob("*") if path.is_file()}
        self.assertEqual(listed, on_disk - {"MANIFEST.sha256"})
        self.assertTrue(any("meminfo-1.txt" in name for name in listed),
                        "the raw device answers are in the bundle and in the manifest")

    def test_a_non_campaign_directory_is_refused(self) -> None:
        empty = self.root / "empty"
        empty.mkdir()
        with self.assertRaises(SystemExit) as raised:
            assemble.main(["--campaign", str(empty), "--out", str(self.root / "b.tar.gz")])
        self.assertIn("not a campaign directory", str(raised.exception))


class TheAssemblyNeverTouchesThePhone(unittest.TestCase):
    """Assembly is an offline operation over files another process produced.

    The previous revision called `adb shell` while bundling to describe the device's lock, VPN and
    logcat. That is wrong in kind: it can describe a different phone than the one measured, and an
    `adb` error is indistinguishable from a real "no lock / VPN off". These tests hold the boundary
    by mocking the external command surface to a counter and requiring zero.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="zs-bundle-offline-")
        self.root = Path(self._tmp.name)
        self.campaign = make_campaign(self.root)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_no_external_command_runs_during_assembly(self) -> None:
        calls: list[list[str]] = []
        saved = assemble.subprocess.run if hasattr(assemble, "subprocess") else None
        real_run = subprocess.run
        real_popen = subprocess.Popen

        def spy_run(*args, **kwargs):
            calls.append(list(args[0]) if args else [])
            raise AssertionError(f"assembly must not run {args!r}")

        subprocess.run = spy_run
        subprocess.Popen = spy_run
        try:
            status = assemble.main(["--campaign", str(self.campaign), "--out",
                                    str(self.root / "bundle.tar.gz")])
        finally:
            subprocess.run = real_run
            subprocess.Popen = real_popen
            if saved is not None:
                assemble.subprocess.run = saved
        self.assertEqual(status, 0)
        self.assertEqual(calls, [], f"assembly ran external commands: {calls}")

    def test_the_bundle_records_that_it_made_no_device_contact(self) -> None:
        with tarfile.open(self._open_bundle(), "r:gz") as archive:
            archive.extractall(self.root / "x", filter="data")
        provenance = json.loads((self.root / "x" / "provenance.json").read_text(encoding="utf-8"))
        self.assertIn("no adb call", provenance["device_contact"])
        self.assertEqual(provenance["commands"], [])

    def _open_bundle(self) -> Path:
        out = self.root / "bundle.tar.gz"
        assemble.main(["--campaign", str(self.campaign), "--out", str(out)])
        return out

    def test_an_absent_state_record_is_unknown_and_not_a_success_claim(self) -> None:
        # No `--state`: the bundle must say `unknown` with a reason, and must not say "VPN off" or
        # "lock absent". Absence of evidence about the device is not evidence about the device.
        (self.root / "x").mkdir()
        with tarfile.open(self._open_bundle(), "r:gz") as archive:
            archive.extractall(self.root / "x", filter="data")
        provenance = json.loads((self.root / "x" / "provenance.json").read_text(encoding="utf-8"))
        state = provenance["device_state"]
        self.assertFalse(state["available"])
        self.assertIn("no --state record", state["reason"])
        self.assertIn("does not mean the lock is free", state["reason"])
        self.assertNotIn("vpn_up", state)
        self.assertNotIn("device_lock", state)

    def test_a_state_record_is_carried_verbatim_and_cited(self) -> None:
        record = self.root / "cleanup.json"
        payload = {"device_lock": "absent", "vpn_up": False, "note": "released by the run"}
        record.write_text(json.dumps(payload), encoding="utf-8")
        out = self.root / "bundle.tar.gz"
        assemble.main(["--campaign", str(self.campaign), "--out", str(out),
                       "--state", str(record)])
        (self.root / "x").mkdir()
        with tarfile.open(out, "r:gz") as archive:
            archive.extractall(self.root / "x", filter="data")
        extracted = self.root / "x"
        # Verbatim, so the reviewer reads the run's own words rather than this tool's summary.
        self.assertEqual(json.loads((extracted / "state" / "cleanup.json").read_text()), payload)
        provenance = json.loads((extracted / "provenance.json").read_text(encoding="utf-8"))
        state = provenance["device_state"]
        self.assertTrue(state["available"])
        self.assertEqual(state["source"], "cleanup.json")
        self.assertEqual(state["recorded"], payload)
        self.assertIn("did not verify", state["note"])
        # ... and the recorded state is in the manifest like every other file.
        manifest = (extracted / "MANIFEST.sha256").read_text(encoding="utf-8")
        self.assertIn("state/cleanup.json", manifest)

    def test_an_unreadable_state_record_is_unknown_with_its_reason(self) -> None:
        record = self.root / "broken.json"
        record.write_text("{not json", encoding="utf-8")
        out = self.root / "bundle.tar.gz"
        assemble.main(["--campaign", str(self.campaign), "--out", str(out),
                       "--state", str(record)])
        (self.root / "x").mkdir()
        with tarfile.open(out, "r:gz") as archive:
            archive.extractall(self.root / "x", filter="data")
        state = json.loads((self.root / "x" / "provenance.json").read_text(encoding="utf-8"))[
            "device_state"]
        self.assertFalse(state["available"])
        self.assertIn("not readable JSON", state["reason"])

    def test_a_missing_state_path_is_unknown_rather_than_invented(self) -> None:
        out = self.root / "bundle.tar.gz"
        assemble.main(["--campaign", str(self.campaign), "--out", str(out),
                       "--state", str(self.root / "nowhere.json")])
        (self.root / "x").mkdir()
        with tarfile.open(out, "r:gz") as archive:
            archive.extractall(self.root / "x", filter="data")
        state = json.loads((self.root / "x" / "provenance.json").read_text(encoding="utf-8"))[
            "device_state"]
        self.assertFalse(state["available"])
        self.assertIn("does not exist", state["reason"])

    def test_an_external_command_and_its_exit_code_can_be_recorded(self) -> None:
        out = self.root / "bundle.tar.gz"
        assemble.main(["--campaign", str(self.campaign), "--out", str(out),
                       "--command", "adb -s stub install -r app.apk=exit:0",
                       "--command", "adb -s stub shell am force-stop pkg=exit:1"])
        (self.root / "x").mkdir()
        with tarfile.open(out, "r:gz") as archive:
            archive.extractall(self.root / "x", filter="data")
        commands = json.loads((self.root / "x" / "provenance.json").read_text(encoding="utf-8"))[
            "commands"]
        self.assertEqual(commands, [
            {"command": "adb -s stub install -r app.apk", "exit": 0},
            {"command": "adb -s stub shell am force-stop pkg", "exit": 1},
        ])

    def test_a_malformed_command_record_is_refused(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            assemble.main(["--campaign", str(self.campaign), "--out",
                           str(self.root / "b.tar.gz"), "--command", "adb install app.apk"])
        self.assertIn("exit:", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
