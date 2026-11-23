#!/usr/bin/env python3
"""Scan every member of an APK for build-environment values that must not ship.

A release APK is a public artifact, and it carries more than the code the author wrote: Rust embeds
the absolute path of every file whose code can panic, the Cargo registry path, and the toolchain path;
resource shrinking can leave whole strings behind in `resources.arsc`; a stray copy of a generated
file can land in `assets/`. The result is that an APK built on a developer machine tells anyone who
unzips it the user name, the workspace layout, the private test device's address and whatever else
ended up in a debug string.

This tool is the check that those values are gone — and, just as importantly, that the check itself
still works. It takes a **positive control**: a file known to contain the patterns. If the control
does not produce hits, the scan is broken (wrong pattern, wrong read mode, wrong member traversal)
and the run fails rather than reporting a clean APK. A scan that cannot fail is not evidence.

What it looks at
----------------
Every member of the ZIP is read as bytes and searched. That includes `classes*.dex`, every
`lib/<abi>/*.so`, `resources.arsc`, `assets/**` and `AndroidManifest.xml` — the binary members where
the interesting leaks live. Nothing is decompiled; strings are searched in place, which is what a
reader of the published APK would do.

Classes of value it looks for
-----------------------------
* **Absolute host paths** — `/home/<user>`, `/Users/<user>`, `C:\\Users\\<user>`, and any embedded
  workspace/cargo/rustup path. These identify the build machine and its directory layout.
* **Private device addresses used as adb serials** — a private-range IPv4 with a port. The pill's
  Wi-Fi debugging address is exactly this shape.
* **Credentials that must never be embedded** — PEM private-key headers, and the names of the
  signing material (`release.jks`, `keystore.properties`) appearing with a path that suggests a
  home directory, which would mean signing material was packaged.
* **Opt-in extra patterns** — `--pattern`, for project-specific values (a hostname, an account name).

Usage
-----
    scripts/release/scrub_apk.py dist/zshield-0.1.4-release.apk \
        --control baseline/lib/arm64-v8a/libzshield.so

    # The control only has to be a file the patterns are known to match. Point it at the previous
    # release's library to prove the scan would catch a regression rather than trust an empty result.

Exit status: 0 when the APK is clean **and** the control produced hits; 1 when the APK carries a
finding; 2 when the control failed (the scan itself is not trustworthy); 3 on a usage/IO problem.
"""

from __future__ import annotations

import argparse
import io
import re
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

#: Documentation IPv4 ranges (RFC 5737) and loopback: synthetic values are fine and tests use them.
_ALLOWED_IPV4 = (
    (192, 0, 2),
    (198, 51, 100),
    (203, 0, 113),
    (127, 0, 0),
)

#: A path that names a real person's home directory or a build workspace.
HOST_PATH_PATTERNS = (
    re.compile(rb"/home/(?!build\b)[A-Za-z0-9._-]+"),
    re.compile(rb"/Users/[A-Za-z0-9._-]+"),
    re.compile(rb"/root/[A-Za-z0-9._-]+"),
    re.compile(rb"[A-Za-z]:\\\\?Users\\\\?[A-Za-z0-9._-]+"),
    re.compile(rb"/\.cargo/registry"),
    re.compile(rb"/\.rustup/toolchains"),
)

#: Private key material, and the signing files that must never be inside the package.
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(rb"-----BEGIN OPENSSH PRIVATE KEY-----"),
)

#: `<private ipv4>:<port>` — the shape of an adb serial, and of nothing that belongs in a shipped app.
ADB_SERIAL_PATTERN = re.compile(rb"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b")

#: Signing material, recognised by **member name** rather than content.
#:
#: A packaged key store is the failure this scan exists for, and its bytes are opaque: a `.jks` is a
#: binary PKCS#12 container, and `keystore.properties` holds four short ASCII lines whose content the
#: content scan has no reason to flag. The leak is the *presence* of the file, so the name is what is
#: matched. Case-insensitive, and matched on the basename so a nested path cannot hide it.
SIGNING_MATERIAL_NAMES = (
    "release.jks",
    "keystore.properties",
    "keystore.jks",
    "signing.properties",
)
_SIGNING_NAME_PATTERN = re.compile(
    r"(?:^|/)(?:" + "|".join(re.escape(name) for name in SIGNING_MATERIAL_NAMES) + r")$",
    re.IGNORECASE,
)
#: Extensions whose mere presence in an APK means key material was packaged, whatever the name is.
_SIGNING_EXTENSION_PATTERN = re.compile(r"\.(?:jks|keystore|p12|pfx|bks)$", re.IGNORECASE)


@dataclass
class Finding:
    """One problem in one member.

    Deliberately carries **no matched text**. The point of the report is to say where and what kind
    the leak is, so it can be fixed; copying the value into a log, a PR or an issue would move the
    very thing the scan exists to keep out of public view into a public place. `detail` therefore
    holds a redacted shape only (a category name, or the structural part of a path), never the match.
    """

    member: str
    category: str
    detail: str
    count: int


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    members_scanned: int = 0
    bytes_scanned: int = 0

    @property
    def clean(self) -> bool:
        return not self.findings


def _is_private_address(octets: tuple[int, int, int, int]) -> bool:
    for prefix in _ALLOWED_IPV4:
        if octets[: len(prefix)] == prefix:
            return False
    first, second = octets[0], octets[1]
    return (
        first == 10
        or (first == 192 and second == 168)
        or (first == 172 and 16 <= second <= 31)
        or (first == 169 and second == 254)
    )


def _describe_path(match: bytes) -> str:
    """Describe a host-path match without reproducing the identifying part.

    `path:/home/<user>` says everything a fix needs (which class, and that it is a home directory)
    and nothing an attacker or a curious reader could use. The user segment and everything below it
    are dropped rather than shortened: a prefix of a real path is still a real path.
    """
    text = match.decode("utf-8", errors="replace")
    parts = [part for part in text.split("/") if part]
    if not parts:
        return "path:<empty>"
    root = parts[0]
    if root in ("home", "Users", "root") and len(parts) >= 2:
        # `/home/<user>/...` -> `/home/<user>`: name the shape, not the account.
        return f"/{root}/<user>"
    if root.endswith(":"):  # a Windows drive
        return f"{root}/<user>"
    return "/" + root


def scan_bytes(data: bytes, member: str, extra_patterns: list[re.Pattern]) -> list[Finding]:
    """Every finding in one member. Counting is per (member, category, value) so a count is exact."""
    findings: list[Finding] = []

    for pattern in HOST_PATH_PATTERNS:
        hits: dict[str, int] = {}
        for match in pattern.finditer(data):
            shape = _describe_path(match.group(0))
            hits[shape] = hits.get(shape, 0) + 1
        for shape, count in hits.items():
            findings.append(Finding(member, "host-path", shape, count))

    for pattern in SECRET_PATTERNS:
        matches = list(pattern.finditer(data))
        if matches:
            # The PEM header is itself the description; the key body is never read out.
            findings.append(
                Finding(member, "secret", "pem-private-key-header", len(matches))
            )

    serial_count = 0
    for match in ADB_SERIAL_PATTERN.finditer(data):
        octets = tuple(int(part) for part in match.group(1).split(b"."))
        if len(octets) != 4 or any(part > 255 for part in octets):
            continue
        if not _is_private_address(octets):  # type: ignore[arg-type]
            continue
        serial_count += 1
    if serial_count:
        # The address itself is the leak; the report says only that one of that class is present.
        findings.append(Finding(member, "device-address", "private-ipv4:port", serial_count))

    for index, pattern in enumerate(extra_patterns, start=1):
        # The *pattern* is operator-supplied and may itself be the sensitive value they are looking
        # for, so it is identified by position (`extra-1`, `extra-2`) and never echoed. Neither is
        # the match.
        count = sum(1 for _ in pattern.finditer(data))
        if count:
            findings.append(Finding(member, f"extra-{index}", "operator-pattern", count))

    return findings


def check_member_name(member: str) -> list[Finding]:
    """Signing material is recognised by its name; the bytes carry nothing searchable.

    Returned as one finding per matching member, with the member path (which is the location a fix
    needs) and no content.
    """
    if _SIGNING_NAME_PATTERN.search(member):
        return [Finding(member, "signing-material", "packaged-key-store", 1)]
    if _SIGNING_EXTENSION_PATTERN.search(member):
        return [Finding(member, "signing-material", "key-store-extension", 1)]
    return []


def scan_apk(apk: Path, extra_patterns: list[re.Pattern]) -> ScanResult:
    """Read every member of the ZIP and scan it. Nothing is skipped: the leaks live in binaries."""
    result = ScanResult()
    with zipfile.ZipFile(apk) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            # Name first: a packaged key store is caught here, and its content would scan clean.
            result.findings.extend(check_member_name(info.filename))
            with archive.open(info) as handle:
                data = handle.read()
            result.members_scanned += 1
            result.bytes_scanned += len(data)
            result.findings.extend(scan_bytes(data, info.filename, extra_patterns))
    return result


def control_names() -> list[str]:
    """The member names the positive control must be able to catch.

    A control file's *content* proves the byte scan works; nothing in a control file can prove the
    name check works, because the name check never looks at bytes. So the name check carries its own
    built-in control: these are run through `check_member_name` on every invocation and a miss is a
    broken scan, reported the same way an empty content control is.
    """
    return [f"assets/{name}" for name in SIGNING_MATERIAL_NAMES] + ["assets/release.p12"]


def check_control(control: Path, extra_patterns: list[re.Pattern]) -> tuple[int, list[str]]:
    """Count the findings in the positive control; zero means the scan cannot detect anything."""
    findings = scan_bytes(control.read_bytes(), control.name, extra_patterns)
    total = sum(finding.count for finding in findings)
    categories = sorted({finding.category for finding in findings})
    return total, categories


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("apk", type=Path, help="the APK to scan")
    parser.add_argument(
        "--control",
        type=Path,
        action="append",
        default=None,
        help="a file known to contain the patterns; the run fails if it produces no hit. Repeatable. "
             "The previous release's libzshield.so is the natural choice.",
    )
    parser.add_argument(
        "--pattern",
        action="append",
        default=[],
        help="an extra literal (or `re:`-prefixed regex) that must not appear in the APK",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--allow-empty-control",
        action="store_true",
        help="proceed even if the control produced no hit (for scanning an APK that has no baseline)",
    )
    arguments = parser.parse_args(argv)

    extra_patterns: list[re.Pattern] = []
    for spec in arguments.pattern:
        if spec.startswith("re:"):
            extra_patterns.append(re.compile(spec[3:].encode()))
        else:
            extra_patterns.append(re.compile(re.escape(spec).encode()))

    if not arguments.apk.is_file():
        print(f"error: {arguments.apk} is not a file", file=sys.stderr)
        return 3

    # The control runs first: if the scan cannot find a known-present value, its silence about the
    # APK means nothing, and reporting "clean" would be the exact failure this tool exists to prevent.
    # The name check cannot be proven by a control *file*, because it never looks at bytes: a broken
    # name pattern would report every APK clean and no content control would notice. So it is
    # exercised against its own expected-hit list on every run, and a miss fails the scan exactly as
    # an empty content control does.
    name_control_misses = [name for name in control_names() if not check_member_name(name)]
    if name_control_misses:
        print(
            "error: the packaged-signing-material name check missed "
            f"{len(name_control_misses)} of {len(control_names())} known names "
            f"({', '.join(name_control_misses[:3])}…), so it cannot be trusted to find a real one.",
            file=sys.stderr,
        )
        return 2

    control_total = 0
    control_report: list[str] = []
    if arguments.control:
        for control in arguments.control:
            if not control.is_file():
                print(f"error: control {control} is not a file", file=sys.stderr)
                return 3
            hits, categories = check_control(control, extra_patterns)
            control_total += hits
            control_report.append(
                f"{control} -> {hits} hit(s) in {len(categories)} categor(ies): "
                f"{', '.join(categories) if categories else 'NONE'}"
            )
        if control_total == 0 and not arguments.allow_empty_control:
            print(
                "error: the positive control produced no hit, so this scan cannot detect anything.\n"
                "       Fix the scan (or point --control at a file the patterns really match) before\n"
                "       reading a clean APK as evidence. `--allow-empty-control` overrides, and says\n"
                "       in the report that no positive control ran.",
                file=sys.stderr,
            )
            return 2
    else:
        print("warning: no --control given; a clean result is not evidence that the scan works",
              file=sys.stderr)

    try:
        result = scan_apk(arguments.apk, extra_patterns)
    except zipfile.BadZipFile:
        print(f"error: {arguments.apk} is not a ZIP/APK", file=sys.stderr)
        return 3

    if arguments.json:
        import json

        # The control is diagnostic context, not part of the machine-readable report: `--json` writes
        # exactly one JSON document to stdout, so anything else goes to stderr.
        for line in control_report:
            print(f"control: {line}", file=sys.stderr)
        print(json.dumps({
            # The basename only: this document is meant to be pasted into a release note or a review,
            # and a build machine's absolute path is exactly the class of value this scan removes.
            "apk": arguments.apk.name,
            "bytes": arguments.apk.stat().st_size,
            "membersScanned": result.members_scanned,
            "bytesScanned": result.bytes_scanned,
            "controlHits": control_total,
            "nameControlChecked": len(control_names()),
            "findings": [
                {"member": f.member, "category": f.category, "detail": f.detail, "count": f.count}
                for f in result.findings
            ],
        }, ensure_ascii=False, indent=2))
    else:
        for line in control_report:
            print(f"control: {line}")
        print(f"apk: {arguments.apk} ({arguments.apk.stat().st_size} bytes)")
        print(f"members scanned: {result.members_scanned}, bytes scanned: {result.bytes_scanned}")
        print(f"name control: {len(control_names())}/{len(control_names())} known signing-material "
              f"names detected")
        if result.clean:
            print("findings: none")
        else:
            print(f"findings: {len(result.findings)} entr(ies)")
            for finding in result.findings:
                print(f"  {finding.member}: {finding.category} x{finding.count}  {finding.detail}")

    return 0 if result.clean else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
