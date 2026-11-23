#!/usr/bin/env python3
"""`scripts/release/scrub_apk.py`: the APK leak scan, and the control that keeps it honest.

The scan is the last gate before a release artifact is published, so the property that matters most is
not "it finds leaks" but "it cannot report clean when it is broken". A pattern list that has been
miscompiled, a member traversal that skips the native libraries, or a read mode that mangles binary
data all produce an empty finding list — which reads exactly like a clean APK. The positive control is
what distinguishes the two, and these tests pin that behaviour.

Every case here builds a small ZIP in a temporary directory; nothing needs a real APK, a device, or the
network.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent.parent  # tests -> scripts/effectiveness -> scripts/
REPO = SCRIPTS.parent
TOOL = SCRIPTS / "release" / "scrub_apk.py"


def run_tool(*arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(TOOL), *arguments],
                          capture_output=True, text=True, timeout=120)


class ScrubCase(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory(prefix="zs-scrub-")
        self.dir = Path(self._temp.name)

    def tearDown(self) -> None:
        self._temp.cleanup()

    def apk(self, name: str, members: dict[str, bytes]) -> Path:
        path = self.dir / name
        with zipfile.ZipFile(path, "w") as archive:
            for member, data in members.items():
                archive.writestr(member, data)
        return path

    def control(self, name: str, data: bytes) -> Path:
        path = self.dir / name
        path.write_bytes(data)
        return path


class CleanApkTest(ScrubCase):
    def test_an_apk_with_no_host_values_is_clean(self) -> None:
        apk = self.apk("clean.apk", {
            "classes.dex": b"kotlin metadata and nothing else",
            "lib/arm64-v8a/libzshield.so": b"ELF /rustc/abcdef/src/lib.rs /cargo/registry/x.rs",
            "resources.arsc": b"ZShield",
        })
        control = self.control("control.so", b"/home/someone/workspace/core/src/lib.rs")
        result = run_tool(str(apk), "--control", str(control))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("findings: none", result.stdout)

    def test_documentation_addresses_are_not_findings(self) -> None:
        """RFC 5737 ranges are what tests use on purpose; flagging them would make the scan useless."""
        apk = self.apk("docs.apk", {
            "classes.dex": b"https://192.0.2.10:8443 https://198.51.100.4:443 127.0.0.1:8080",
        })
        control = self.control("control.so", b"/home/someone/x")
        result = run_tool(str(apk), "--control", str(control))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class LeakTest(ScrubCase):
    def test_a_host_path_is_a_finding(self) -> None:
        apk = self.apk("leak.apk", {
            "lib/arm64-v8a/libzshield.so": b"\x00/home/alice/workspace/zshield/core/src/tun.rs",
        })
        control = self.control("control.so", b"/home/someone/x")
        result = run_tool(str(apk), "--control", str(control))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("lib/arm64-v8a/libzshield.so", result.stdout)
        self.assertIn("host-path", result.stdout)

    def test_a_private_device_address_is_a_finding(self) -> None:
        apk = self.apk("device.apk", {"classes.dex": b"serial 10.1.2.3:5555"})
        control = self.control("control.so", b"/home/someone/x")
        result = run_tool(str(apk), "--control", str(control))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("device-address", result.stdout)

    def test_a_private_key_header_is_a_finding(self) -> None:
        apk = self.apk("key.apk", {"assets/leak.pem": b"-----BEGIN PRIVATE KEY-----\nAAAA"})
        control = self.control("control.so", b"/home/someone/x")
        result = run_tool(str(apk), "--control", str(control))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("secret", result.stdout)

    def test_an_extra_pattern_is_a_finding(self) -> None:
        apk = self.apk("extra.apk", {"classes.dex": b"build-host-name.internal"})
        control = self.control("control.so", b"/home/someone/x")
        result = run_tool(str(apk), "--control", str(control),
                          "--pattern", "build-host-name.internal")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("extra-1", result.stdout)


class PackagedSigningMaterialTest(ScrubCase):
    """A key store inside the APK: the leak is the file's *presence*, not its bytes.

    Regression for MYS-3034 round 1: a `.jks` is an opaque binary and `keystore.properties` is four
    short ASCII lines, so a content-only scan reported both as clean and exited 0. The two fixtures
    below are exactly that case — ordinary placeholder bytes, the leak only in the member name.
    """

    def _apk_with_member(self, name: str, member: str) -> Path:
        return self.apk(name, {
            member: b"placeholder bytes that match no content pattern",
            "classes.dex": b"ordinary",
        })

    def test_a_packaged_key_store_is_detected(self) -> None:
        apk = self._apk_with_member("jks.apk", "assets/release.jks")
        result = run_tool(str(apk), "--control", str(self.control("c.so", b"/home/someone/x")))
        self.assertEqual(result.returncode, 1,
                         "a packaged key store must not read as clean:\n" + result.stdout)
        self.assertIn("assets/release.jks", result.stdout)
        self.assertIn("signing-material", result.stdout)

    def test_packaged_keystore_properties_are_detected(self) -> None:
        apk = self._apk_with_member("props.apk", "assets/keystore.properties")
        result = run_tool(str(apk), "--control", str(self.control("c.so", b"/home/someone/x")))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("assets/keystore.properties", result.stdout)

    def test_a_key_store_under_any_directory_is_detected(self) -> None:
        for member in ("release.jks", "res/raw/keystore.jks", "assets/deep/dir/release.jks",
                       "assets/SIGNING.PROPERTIES", "assets/store.p12"):
            with self.subTest(member=member):
                apk = self._apk_with_member("m.apk", member)
                result = run_tool(str(apk), "--control", str(self.control("c.so", b"/home/x/y")))
                self.assertEqual(result.returncode, 1, f"{member} was not detected")

    def test_ordinary_names_are_not_flagged(self) -> None:
        """The control in the other direction: the name check must not fire on normal members."""
        apk = self.apk("normal.apk", {
            "classes.dex": b"x", "assets/rules/list.txt": b"y", "lib/arm64-v8a/libzshield.so": b"z",
            "META-INF/CERT.SF": b"w",
        })
        result = run_tool(str(apk), "--control", str(self.control("c.so", b"/home/x/y")))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_the_name_check_carries_its_own_control(self) -> None:
        """Its own positive control, because a content control cannot prove a name check works."""
        apk = self.apk("clean.apk", {"classes.dex": b"nothing"})
        result = run_tool(str(apk), "--control", str(self.control("c.so", b"/home/x/y")))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("name control: 5/5", result.stdout)

    def test_json_reports_the_name_control(self) -> None:
        apk = self._apk_with_member("jks.apk", "assets/release.jks")
        result = run_tool(str(apk), "--control", str(self.control("c.so", b"/home/x/y")), "--json")
        report = json.loads(result.stdout)
        self.assertEqual(report["nameControlChecked"], 5)
        categories = {finding["category"] for finding in report["findings"]}
        self.assertIn("signing-material", categories)


class RedactionTest(ScrubCase):
    """The report says where and what class, never the value.

    A scan whose output quotes the leak has moved the secret into the ticket, the PR and the CI log —
    the same places the scan exists to keep it out of.
    """

    def test_no_matched_value_appears_in_the_human_report(self) -> None:
        apk = self.apk("leak.apk", {
            "classes.dex": b"/home/realperson/project 10.1.2.3:5555",
            "assets/k.pem": b"-----BEGIN PRIVATE KEY-----",
        })
        result = run_tool(str(apk), "--control", str(self.control("c.so", b"/home/x/y")))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        for value in ("realperson", "10.1.2.3", "5555"):
            self.assertNotIn(value, result.stdout,
                             f"the report reproduced {value!r}")
        self.assertIn("/home/<user>", result.stdout)
        self.assertIn("private-ipv4:port", result.stdout)

    def test_no_matched_value_appears_in_the_json_report(self) -> None:
        apk = self.apk("leak.apk", {"classes.dex": b"/home/realperson/project"})
        result = run_tool(str(apk), "--control", str(self.control("c.so", b"/home/x/y")), "--json")
        self.assertNotIn("realperson", result.stdout)

    def test_an_operator_pattern_is_identified_by_position_not_value(self) -> None:
        """`--pattern` may itself be the sensitive string being hunted."""
        apk = self.apk("p.apk", {"classes.dex": b"internal-host.corp.example"})
        result = run_tool(str(apk), "--control", str(self.control("c.so", b"/home/x/y")),
                          "--pattern", "internal-host.corp.example", "--json")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("internal-host.corp.example", result.stdout)
        report = json.loads(result.stdout)
        self.assertTrue(any(f["category"] == "extra-1" for f in report["findings"]))


class ControlTest(ScrubCase):
    """A scan that cannot find a known-present value must not be read as "the APK is clean"."""

    def test_an_empty_control_fails_the_run(self) -> None:
        apk = self.apk("clean.apk", {"classes.dex": b"nothing"})
        control = self.control("control.so", b"a file with no host path at all")
        result = run_tool(str(apk), "--control", str(control))
        self.assertEqual(result.returncode, 2,
                         "a control with no hit means the scan is broken; it must not pass")
        self.assertIn("cannot detect anything", result.stderr)

    def test_the_control_is_reported_when_it_does_match(self) -> None:
        apk = self.apk("clean.apk", {"classes.dex": b"nothing"})
        control = self.control("control.so", b"/home/someone/x")
        result = run_tool(str(apk), "--control", str(control))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("control:", result.stdout)
        self.assertIn("host-path", result.stdout)

    def test_a_missing_control_is_a_usage_error(self) -> None:
        apk = self.apk("clean.apk", {"classes.dex": b"nothing"})
        result = run_tool(str(apk), "--control", str(self.dir / "nope.so"))
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)

    def test_scanning_without_a_control_warns_that_it_proves_nothing(self) -> None:
        apk = self.apk("clean.apk", {"classes.dex": b"nothing"})
        result = run_tool(str(apk))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("no --control given", result.stderr)

    def test_the_override_is_explicit(self) -> None:
        apk = self.apk("clean.apk", {"classes.dex": b"nothing"})
        control = self.control("control.so", b"no patterns here")
        result = run_tool(str(apk), "--control", str(control), "--allow-empty-control")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class JsonOutputTest(ScrubCase):
    def test_the_json_report_carries_the_counts_and_findings(self) -> None:
        apk = self.apk("leak.apk", {
            "classes.dex": b"/home/alice/a /home/alice/b",
            "lib/arm64-v8a/libzshield.so": b"/home/bob/c",
        })
        control = self.control("control.so", b"/home/someone/x")
        result = run_tool(str(apk), "--control", str(control), "--json")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["apk"], "leak.apk", "the report names the file, not its directory")
        self.assertEqual(report["membersScanned"], 2)
        self.assertGreater(report["controlHits"], 0)
        members = {finding["member"] for finding in report["findings"]}
        self.assertEqual(members, {"classes.dex", "lib/arm64-v8a/libzshield.so"})
        # The count is per value, so a repeated path is visible as one finding with count 2.
        # The detail is the redacted shape; counting is per (member, category, shape), so the two
        # hits inside `classes.dex` collapse into one finding with count 2, and the other member
        # gets its own.
        home = [f for f in report["findings"] if f["detail"] == "/home/<user>"]
        self.assertEqual(len(home), 2, "one finding per member that carries the shape")
        by_member = {finding["member"]: finding["count"] for finding in home}
        self.assertEqual(by_member["classes.dex"], 2)
        self.assertEqual(by_member["lib/arm64-v8a/libzshield.so"], 1)
        # And the value itself must not be reproduced anywhere in the report.
        self.assertNotIn("alice", result.stdout)
        self.assertNotIn("bob", result.stdout)


class EveryMemberIsScannedTest(ScrubCase):
    def test_a_leak_in_any_member_is_found(self) -> None:
        """Nothing may be skipped: the leaks this scan exists for live in binaries, not sources."""
        for member in ("classes.dex", "classes2.dex", "resources.arsc", "AndroidManifest.xml",
                       "lib/arm64-v8a/libzshield.so", "assets/rules/list.txt"):
            with self.subTest(member=member):
                apk = self.apk(f"m-{member.replace('/', '_')}.apk",
                               {member: b"/home/carol/project"})
                result = run_tool(str(apk), "--control", str(self.control("c.so", b"/home/x/y")))
                self.assertEqual(result.returncode, 1, f"{member} was not scanned:\n" + result.stdout)


if __name__ == "__main__":
    unittest.main()
