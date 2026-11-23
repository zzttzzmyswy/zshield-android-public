#!/usr/bin/env python3
"""Drive and check `core/examples/i2_jni_memory_profile.rs` (MYS-2866).

Two jobs, one program:

* ``run`` invokes the real example six times (five-list and nine-list groups, three independent
  processes each) into a fresh directory per attempt, keeps every attempt it made, and never
  overwrites an existing one. Then it writes a ``MANIFEST.sha256`` over the run's evidence, excluding
  the manifest itself.
* ``check`` reads a finished ``run`` directory and decides whether its evidence supports the claims a
  report may make. It exits non-zero on anything it cannot verify, and each refusal names the field
  and the reason.

The division matters. The example is the only thing that can observe a live JNI handle, so it records
raw observations; this program is the only thing that decides whether those observations are
*sufficient*, and it is deliberately willing to say no. A checker that only ever prints PASS is the
failure mode the earlier stages of this task kept hitting.

# What ``check`` refuses

Each of these is a rejection with its own message, not a warning:

* a document that is not the schema this program knows, or is not one JSON object;
* ``formal: false`` (a ``selftest`` run) presented as evidence for a real rule set;
* a list body whose size or SHA-256 does not match the group's manifest in
  ``docs/I2_MEMORY_PROFILE.md`` §6, or a group with the wrong number of bodies;
* a missing observation point, a point with no ``smaps`` fields, or one with no descriptor/thread
  count — an absent observation is never read as a zero;
* an unchanged reload that advanced the generation, rebuilt the rule objects, or reported a failed
  swap — 20 of them are required and each is checked individually;
* an A/B round under twelve, or any round whose declared effect does not match the artifact set it
  loaded, whose generation did not advance exactly once, whose identities disagree with the on-disk
  payloads, or that left the previous rule set alive;
* anything about the stop that did not finish: a handle still readable, a rule object still strongly
  referenced, or descriptors or threads above the process baseline;
* an ``extras``-only change that was not actually extras-only, since that is the premise the whole
  A/B control rests on;
* any numeric claim in the document that the raw observations do not reproduce.

# What ``check`` deliberately does NOT do

It never compares a host number against the device PSS threshold, and never reports a PSS verdict.
This is a glibc host process; Android links bionic/scudo with a JVM beside the core. The threshold
belongs to the device stage and stays there.

Usage::

    python3 scripts/effectiveness/jni_memory_profile.py run \\
        --binary core/target/release/examples/i2_jni_memory_profile \\
        --lists-five /path/to/lists-five --lists-nine /path/to/lists-nine \\
        --out /path/to/evidence [--trim-diagnostic]

    python3 scripts/effectiveness/jni_memory_profile.py check /path/to/evidence --json
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import math
import os
import shutil
import subprocess
import sys
from pathlib import Path

SCHEMA = "zshield.i2.jni-memory-profile/1"

#: `docs/I2_MEMORY_PROFILE.md` §6, in full. A run whose inputs disagree with this is not that group.
CANONICAL = {
    "adguard-base": (6458941, "1ec4df21f05a99e986e8b1c9d1dce18d2075fa8c4c0fdb52602960c3b4c2e693"),
    "adguard-tracking": (
        15125879,
        "297509825b155280a17d68266b079692149e187bfc642c059863dcf46e532308",
    ),
    "adguard-mobile": (530861, "f3262a5bb798cf02fe21cdc1720c6a1e43b0b438df83aa967ff84940dc354b61"),
    "adguard-url-tracking": (
        183673,
        "fe84fc5f8f12be9258b3f64353ad95107d8d57b82d4a2ba2f80d4fae500adece",
    ),
    "adguard-chinese": (718555, "0bf9d26038391b6e7a4c2664f029127e050c27379576cd808dff555020f16e5c"),
    "adguard-dns": (4597885, "d0edbf143873d060f03ea35891f2c44398d6cc9097d06f9d76b5d3d453ccf713"),
    "easylist-china": (498597, "e4dade0da96371cad630b9d740d5936ea6b41657f9d98e2d3e42530ef5adc3ae"),
    "ublock-unbreak": (282165, "91da37caebdcaec0dc111b293c0392dcb7ba5e447f636dd8529803176a825e94"),
    "ublock-quick-fixes": (
        86138,
        "c6b20fd6fbd8f284539140b5bc6b36cbf6e5d99b5f3dff76b95ce21b68b833c9",
    ),
}

#: The list ids each group compiles, in the order the group is defined.
GROUPS = {
    "five": [
        "adguard-base",
        "adguard-tracking",
        "adguard-mobile",
        "adguard-url-tracking",
        "adguard-chinese",
    ],
    "nine": [
        "adguard-base",
        "adguard-tracking",
        "adguard-mobile",
        "adguard-url-tracking",
        "adguard-chinese",
        "adguard-dns",
        "easylist-china",
        "ublock-unbreak",
        "ublock-quick-fixes",
    ],
}

UNCHANGED_RELOADS = 20
AB_ROUNDS = 12  # the card asks for "at least six"; the example runs twelve and the checker holds it

#: Phases the example must produce, in order. Missing any of these is a missing observation.
REQUIRED_PHASES = [
    "process-baseline",
    "compiled-a",
    "started-a",
    "first-removeparam-evaluation",
    "unchanged-reloads-done",
    "compiled-b",
    "reloaded-b",
    "settled",
    "stopped",
]

#: `/proc/self/smaps_rollup` fields a point must carry. Not every kernel prints every field, so the
#: set is the portable core; a missing one of *these* is a missing observation.
REQUIRED_SMAPS = ["Rss", "Pss_Anon", "Anonymous", "Private_Dirty"]

RUNS_PER_GROUP = 3


# ---------------------------------------------------------------------------------------------
# Reading evidence
# ---------------------------------------------------------------------------------------------

#: The phases that report a measured operation. A point in this set must carry its own window; a
#: point outside it must not. This is what stops a phase from reporting some earlier phase's
#: high-water mark as its own cost — the defect the review found in `started-a` and `stopped`.
OPERATION_PHASES = {
    "compiled-a",
    "started-a",
    "first-removeparam-evaluation",
    "unchanged-reloads-done",
    "compiled-b",
    "reloaded-b",
    "stopped",
}

#: The rule the A/B control moves, and the URL it is evaluated on. Held here as well as in the probe so
#: the checker can derive the *expected* effect from the rule text instead of trusting the document's
#: `expected_with_a`/`expected_with_b`.
AB_RULE_A = "removeparam=/^old=/"
AB_RULE_B = "removeparam=/^new=/"
EFFECT_BASE = "https://ab-memory.test/p"
EFFECT_PARAMS = ["old=1", "new=2", "keep=3"]


class Refusal(Exception):
    """An evidence problem, with the reason a reviewer needs."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def payload_identity(path: Path) -> tuple[str, int]:
    """SHA-256 and length of a compiled artifact's payload, past its 20-byte envelope header.

    The probe reports `payload_sha256`/`payload_bytes`; this recomputes them from the file, so an
    identity in the document is checked against bytes rather than taken on trust.
    """
    raw = path.read_bytes()
    if len(raw) < 20:
        raise Refusal(f"{path}: shorter than a compiled-artifact envelope header")
    payload = raw[20:]
    return hashlib.sha256(payload).hexdigest(), len(payload)


def load_document(path: Path) -> dict:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        raise Refusal(f"{path}: {error}") from error
    try:
        document = json.loads(raw)
    except ValueError as error:
        raise Refusal(f"{path}: not one JSON document: {error}") from error
    if not isinstance(document, dict):
        raise Refusal(f"{path}: the document is {type(document).__name__}, not an object")
    return document


def resolve_input_path(
    declared: str, document_path: Path, root: Path | None, group: str, list_id: str
) -> Path:
    """Resolve the specified group's sealed copy; never borrow another group's or a host file."""
    base = root if root is not None else document_path.parent.parent
    name = f"{list_id}.txt"
    candidate = base / "inputs" / f"lists-{group}" / name
    if Path(declared).name != name or not candidate.is_file():
        raise Refusal(f"{document_path}: the {group} input body {candidate} is not present")
    if not candidate.resolve().is_relative_to(base.resolve()):
        raise Refusal(f"{document_path}: the {group} input body is outside the campaign")
    return candidate


def verify_inputs(document: dict, where: str, root: Path | None = None) -> dict:
    """The compiled list bodies must be the group's canonical bodies, **as bytes on disk**.

    The first delivery compared only the hash the document *declared*, so replacing a list body while
    leaving the declaration untouched was accepted. Here the declaration is checked against the
    published manifest **and** the file is re-hashed: a changed body fails even when the document
    still claims the original size and hash.
    """
    group = document.get("group")
    if group not in GROUPS:
        raise Refusal(f"{where}: group {group!r} is not one of {sorted(GROUPS)}")
    inputs = document.get("inputs") or {}
    lists = inputs.get("lists")
    if not isinstance(lists, list):
        raise Refusal(f"{where}: no input list manifest")

    expected_ids = GROUPS[group]
    got_ids = [entry.get("id") for entry in lists]
    if got_ids != expected_ids:
        raise Refusal(
            f"{where}: the {group}-group must compile {expected_ids}, the run compiled {got_ids}"
        )

    document_path = Path(where)
    verified = []
    for entry in lists:
        list_id = entry.get("id")
        want_bytes, want_sha = CANONICAL[list_id]
        if entry.get("bytes") != want_bytes:
            raise Refusal(
                f"{where}: {list_id} is declared {entry.get('bytes')} B, the manifest says {want_bytes} B"
            )
        if entry.get("sha256") != want_sha:
            raise Refusal(
                f"{where}: {list_id} is declared as hashing to {entry.get('sha256')}, the manifest says "
                f"{want_sha}"
            )
        if entry.get("expected_sha256") not in (None, want_sha):
            raise Refusal(
                f"{where}: {list_id} declares expected_sha256 {entry.get('expected_sha256')}, the "
                f"published manifest says {want_sha}"
            )
        # The bytes the compile actually read. This is what the declaration is checked against.
        path = resolve_input_path(str(entry.get("path", "")), document_path, root, group, list_id)
        actual_sha = sha256_file(path)
        actual_bytes = path.stat().st_size
        if actual_bytes != want_bytes:
            raise Refusal(
                f"{where}: the input body {path} is {actual_bytes} B on disk, the manifest says "
                f"{want_bytes} B — the declared size does not describe the compiled input"
            )
        if actual_sha != want_sha:
            raise Refusal(
                f"{where}: the input body {path} hashes to {actual_sha} on disk, the manifest says "
                f"{want_sha} — the compiled input is not the canonical body"
            )
        if entry.get("lines") is not None:
            lines = len(path.read_text(encoding="utf-8", errors="replace").splitlines())
            if lines != entry.get("lines"):
                raise Refusal(
                    f"{where}: {list_id} is declared as {entry.get('lines')} lines, the file on disk has "
                    f"{lines}"
                )
        verified.append({"id": list_id, "path": str(path), "sha256": actual_sha})
    return {"group": group, "lists": len(verified), "bodies": verified}


def derive_effect_url(rule_marker: str) -> str:
    """What `$removeparam` necessarily leaves of the A/B URL, from the rule text alone.

    The control's claim is "this one rule removes exactly this one parameter". The parameter is the
    literal between `/^` and `=/`, so the expected URL follows from the rule rather than from anything
    the probe reports about its own evaluation.
    """
    prefix = "removeparam=/^"
    suffix = "=/"
    if not (rule_marker.startswith(prefix) and rule_marker.endswith(suffix)):
        raise Refusal(f"the A/B rule marker {rule_marker!r} is not a ^name= regex removeparam")
    parameter = rule_marker[len(prefix) : -len(suffix)]
    kept = [part for part in EFFECT_PARAMS if not part.startswith(parameter + "=")]
    return f"{EFFECT_BASE}?{'&'.join(kept)}"


def locate_artifact(name: str, role: str, entry: dict, document_path: Path, root: Path | None) -> Path:
    """Use this run's sealed artifact, including after the campaign is relocated."""
    candidate = document_path.parent / f"compiled-{role}" / name
    base = root if root is not None else document_path.parent
    if candidate.is_file() and candidate.resolve().is_relative_to(base.resolve()):
        return candidate
    raise Refusal(
        f"{document_path}: role {role}'s {name} is not on disk, so its identity cannot be checked"
    )


def verify_artifacts(document: dict, where: str, root: Path | None = None) -> dict:
    """The artifact identities must describe the files on disk, and the A/B premise is derived.

    `payload_sha256`/`payload_bytes` are recomputed from each artifact, so a document cannot claim an
    identity its bytes do not have. That dns and engine are identical and extras is not — the premise
    the whole A/B control rests on — follows from those bytes, not from the document's conclusion.
    """
    artifacts = document.get("artifacts")
    if not isinstance(artifacts, dict):
        raise Refusal(f"{where}: no artifact facts")
    roles = artifacts.get("roles")
    by_dir = artifacts.get("by_dir")
    if not isinstance(roles, dict) or not isinstance(by_dir, dict):
        raise Refusal(f"{where}: the artifact section must name an 'a' and a 'b' role and their dirs")
    if set(roles) != {"a", "b"}:
        raise Refusal(f"{where}: the A/B roles are {sorted(roles)}, exactly 'a' and 'b' are required")
    if len(set(roles.values())) != 2:
        raise Refusal(f"{where}: roles a and b point at the same compiled directory")

    document_path = Path(where)
    resolved: dict[str, dict] = {}
    for role in ("a", "b"):
        directory = roles[role]
        inner = by_dir.get(directory)
        if not isinstance(inner, dict):
            raise Refusal(f"{where}: role {role} has no artifact facts for {directory}")
        found: dict[str, dict] = {}
        for name in ("dns.bin", "engine.bin", "extras.txt"):
            if name not in inner:
                raise Refusal(f"{where}: role {role} is missing {name}")
            entry = inner[name]
            if not isinstance(entry, dict):
                raise Refusal(f"{where}: role {role}'s {name} carries no artifact facts")
            path = locate_artifact(name, role, entry, document_path, root)
            actual_sha, actual_bytes = payload_identity(path)
            declared_sha = entry.get("payload_sha256")
            declared_bytes = entry.get("payload_bytes")
            if declared_sha is None or declared_bytes is None:
                raise Refusal(
                    f"{where}: role {role}'s {name} declares no payload identity; a byte count is not a "
                    "content identity"
                )
            if actual_bytes != declared_bytes:
                raise Refusal(
                    f"{where}: role {role}'s {name} payload is {actual_bytes} B on disk, the document "
                    f"says {declared_bytes} B"
                )
            if actual_sha != declared_sha:
                raise Refusal(
                    f"{where}: role {role}'s {name} payload hashes to {actual_sha} on disk, the document "
                    f"says {declared_sha}"
                )
            found[name] = {
                "path": str(path),
                "payload_sha256": actual_sha,
                "payload_bytes": actual_bytes,
                "file_bytes": path.stat().st_size,
                "token": f"sha256:{actual_sha}:{actual_bytes}",
            }
        resolved[role] = found

    a, b = resolved["a"], resolved["b"]
    if a["dns.bin"]["payload_sha256"] != b["dns.bin"]["payload_sha256"]:
        raise Refusal(f"{where}: the A/B change also moved dns.bin, so the case is not extras-only")
    if a["engine.bin"]["payload_sha256"] != b["engine.bin"]["payload_sha256"]:
        raise Refusal(f"{where}: the A/B change also moved engine.bin, so the case is not extras-only")
    if a["extras.txt"]["payload_sha256"] == b["extras.txt"]["payload_sha256"]:
        raise Refusal(f"{where}: extras.txt is byte-identical between A and B, so no rule changed")

    # The A/B rule must actually be in the side it is claimed to be in, and absent from the other.
    for role, marker, other in (("a", AB_RULE_A, AB_RULE_B), ("b", AB_RULE_B, AB_RULE_A)):
        text = Path(resolved[role]["extras.txt"]["path"]).read_bytes()[20:].decode(
            "utf-8", errors="replace"
        )
        if marker not in text:
            raise Refusal(
                f"{where}: role {role}'s extras.txt does not contain {marker!r}, so the A/B control is "
                "not the rule transition it claims"
            )
        if other in text:
            raise Refusal(
                f"{where}: role {role}'s extras.txt also contains {other!r}; the two sides must differ "
                "by exactly one rule"
            )

    effect_a = derive_effect_url(AB_RULE_A)
    effect_b = derive_effect_url(AB_RULE_B)
    declared_a = (document.get("inputs") or {}).get("expected_with_a")
    declared_b = (document.get("inputs") or {}).get("expected_with_b")
    if declared_a is not None and declared_a != effect_a:
        raise Refusal(
            f"{where}: expected_with_a is declared {declared_a!r}, the A/B rule implies {effect_a!r}"
        )
    if declared_b is not None and declared_b != effect_b:
        raise Refusal(
            f"{where}: expected_with_b is declared {declared_b!r}, the A/B rule implies {effect_b!r}"
        )
    return {
        "roles": resolved,
        "dns_identical": True,
        "engine_identical": True,
        "extras_changed": True,
        "effect_a": effect_a,
        "effect_b": effect_b,
        "dns_payload_bytes": a["dns.bin"]["payload_bytes"],
        "engine_payload_bytes": a["engine.bin"]["payload_bytes"],
        "engine_file_bytes": a["engine.bin"]["file_bytes"],
        "extras_payload_bytes": a["extras.txt"]["payload_bytes"],
        "extras_a_sha256": a["extras.txt"]["payload_sha256"],
        "extras_b_sha256": b["extras.txt"]["payload_sha256"],
    }


def window_of(point: dict, where: str, phase: str) -> dict:
    """The measurement window of an operation point, validated.

    A window has to describe a closed interval in which a peak was actually observed, and the peak
    cannot be below the live heap at either end of the interval. Both are checked, so `2**60` and `-1`
    are rejected as the impossible numbers they are rather than compared as if they meant something.
    """
    window = point.get("window")
    if not isinstance(window, dict):
        raise Refusal(
            f"{where}: {phase} is an operation point with no measurement window of its own"
        )
    peak = window.get("peak_bytes")
    started_live = window.get("started_live_bytes")
    ended_live = window.get("ended_live_bytes")
    for field, value in (
        ("peak_bytes", peak),
        ("started_live_bytes", started_live),
        ("ended_live_bytes", ended_live),
    ):
        if not isinstance(value, int) or isinstance(value, bool):
            raise Refusal(f"{where}: {phase}'s window has no integer {field}")
        if value < 0:
            raise Refusal(f"{where}: {phase}'s window {field} is negative ({value})")
    # The allocator cannot peak above the address space, and cannot peak below what it held at either
    # end of the interval. An implausible peak is a fabricated observation, not a large one.
    start_ns = window.get("started_monotonic_ns")
    end_ns = window.get("ended_monotonic_ns")
    if not isinstance(start_ns, int) or not isinstance(end_ns, int):
        raise Refusal(f"{where}: {phase}'s window has no monotonic interval")
    if end_ns < start_ns:
        raise Refusal(f"{where}: {phase}'s window ends before it starts ({start_ns} → {end_ns})")
    if peak < max(started_live, ended_live):
        raise Refusal(
            f"{where}: {phase}'s window peak {peak} is below its own live heap "
            f"({started_live} → {ended_live}), which no allocator can do"
        )
    vm_peak_kib = point.get("vm_peak_kib")
    if isinstance(vm_peak_kib, int) and vm_peak_kib > 0:
        vm_peak_bytes = vm_peak_kib * 1024
        # `VmPeak` is process-wide and monotone, so it bounds every counted peak from above.
        if peak > vm_peak_bytes:
            raise Refusal(
                f"{where}: {phase}'s window peak {peak} B exceeds the process address-space high-water "
                f"mark {vm_peak_bytes} B, so the peak was not observed in this process"
            )
    return window


def verify_points(document: dict, where: str) -> dict[str, dict]:
    points = document.get("points")
    if not isinstance(points, list) or not points:
        raise Refusal(f"{where}: no observation points")
    by_phase: dict[str, dict] = {}
    for point in points:
        if not isinstance(point, dict):
            raise Refusal(f"{where}: an observation point is not an object")
        phase = point.get("phase")
        if not isinstance(phase, str) or not phase:
            raise Refusal(f"{where}: an observation point has no phase name")
        if phase in by_phase and not phase.startswith("trim-diagnostic-"):
            raise Refusal(f"{where}: phase {phase} is reported twice")
        by_phase[phase] = point

    for phase in REQUIRED_PHASES:
        if phase not in by_phase:
            raise Refusal(f"{where}: required phase {phase} was never observed")

    for phase, point in by_phase.items():
        counted = point.get("counted")
        if not isinstance(counted, dict):
            raise Refusal(f"{where}: {phase} has no counted live heap — an absent observation")
        live = counted.get("live_bytes")
        if not isinstance(live, int) or isinstance(live, bool) or live < 0:
            raise Refusal(f"{where}: {phase} has no counted live heap — an absent observation")
        smaps = point.get("smaps")
        if not isinstance(smaps, dict):
            raise Refusal(f"{where}: {phase} has no smaps_rollup fields")
        readings = ({name: smaps.get(name) for name in ("before", "after_first", "after_second")}
                    if phase.startswith("trim-diagnostic-") else {"smaps": smaps})
        for name, reading in readings.items():
            for field in REQUIRED_SMAPS:
                if not isinstance(reading, dict) or type(reading.get(field)) is not int or reading[field] < 0:
                    raise Refusal(f"{where}: {phase}/{name} is missing smaps field {field}")
        for field in ("fd_count", "thread_count"):
            if not isinstance(point.get(field), int):
                raise Refusal(f"{where}: {phase} has no {field}")

        if phase.startswith("trim-diagnostic-"):
            windows = point.get("windows")
            if not isinstance(windows, list) or len(windows) != 2:
                raise Refusal(f"{where}: {phase} needs two separate trim windows")
            for index, window in enumerate(windows):
                window_of({"window": window, "vm_peak_kib": point.get("vm_peak_kib")},
                          where, f"{phase}/trim-{index + 1}")

        is_operation = phase in OPERATION_PHASES or phase.startswith("ab-round-")
        if is_operation:
            window = window_of(point, where, phase)
            # `counted.peak_bytes` mirrors the window on a point. Both must exist and agree, so a
            # document cannot drop one of them and still look complete.
            if "peak_bytes" not in counted:
                raise Refusal(
                    f"{where}: {phase} reports no operation peak in `counted`; the peak must be this "
                    "operation's own, not an earlier phase's"
                )
            if counted.get("peak_bytes") != window["peak_bytes"]:
                raise Refusal(
                    f"{where}: {phase} reports counted.peak_bytes {counted.get('peak_bytes')!r} but its "
                    f"window peak is {window['peak_bytes']}"
                )
        elif not phase.startswith("trim-diagnostic-") and point.get("window") is not None:
            raise Refusal(
                f"{where}: {phase} observes a state but claims an operation window; a state has no peak "
                "of its own"
            )

        if phase in ("process-baseline", "compiled-a"):
            if point.get("handle_state") not in ("no-handle-yet", "released"):
                raise Refusal(
                    f"{where}: {phase} claims a live handle ({point.get('handle_state')!r})"
                )
        elif phase == "stopped":
            # Checked separately below: after the stop the handle must be gone.
            pass
        elif not phase.startswith("trim-diagnostic-"):
            if point.get("handle_state") != "live":
                raise Refusal(
                    f"{where}: {phase} reports handle_state {point.get('handle_state')!r}, not a live "
                    "handle"
                )
            if not isinstance(point.get("generation"), int) or point["generation"] < 1:
                raise Refusal(f"{where}: {phase} reports no generation")
            if not isinstance(point.get("ondisk_identity"), dict):
                raise Refusal(f"{where}: {phase} has no on-disk artifact identity")

    if by_phase["stopped"].get("handle_state") != "released":
        raise Refusal(
            f"{where}: the stop point reports {by_phase['stopped'].get('handle_state')!r}, not a "
            "released handle"
        )
    return by_phase


def verify_loaded_identity(
    document: dict, where: str, points: dict[str, dict], artifacts: dict
) -> dict:
    """What each point says is *loaded* must be what the artifacts on disk are.

    The review changed `started-a`'s extras identity to a zero hash and the checker accepted it,
    because nothing compared the reported identity with the artifact it claims to describe.
    """
    expect = {
        "started-a": ("a", points["started-a"]),
        "first-removeparam-evaluation": ("a", points["first-removeparam-evaluation"]),
        "unchanged-reloads-done": ("a", points["unchanged-reloads-done"]),
        "compiled-b": ("a", points["compiled-b"]),
        "reloaded-b": ("b", points["reloaded-b"]),
        "settled": ("b", points["settled"]),
    }
    for index in range(1, AB_ROUNDS + 1):
        phase = f"ab-round-{index:02}"
        if phase not in points:
            raise Refusal(f"{where}: required phase {phase} was never observed")
        expect[phase] = ("a" if index % 2 else "b", points[phase])
    for phase, (role, point) in expect.items():
        identities = point.get("identities")
        if not isinstance(identities, dict):
            raise Refusal(f"{where}: {phase} reports no loaded rule identity")
        for component, artifact in (
            ("dns", "dns.bin"),
            ("engine", "engine.bin"),
            ("extras", "extras.txt"),
        ):
            want = artifacts["roles"][role][artifact]["token"]
            got = identities.get(component)
            if got != want:
                raise Refusal(
                    f"{where}: {phase} reports {component}={got}, the artifact of record for role {role} "
                    f"is {want}"
                )
    return {"phases_checked": sorted(expect)}


def verify_assertions(document: dict, where: str) -> list[dict]:
    assertions = document.get("assertions")
    if not isinstance(assertions, list) or not assertions:
        raise Refusal(f"{where}: the run recorded no assertions")
    for item in assertions:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise Refusal(f"{where}: an assertion has no name")
    failures = [item for item in assertions if not item.get("ok")]
    if failures:
        names = ", ".join(str(item.get("name")) for item in failures[:5])
        raise Refusal(f"{where}: {len(failures)} control(s) failed: {names}")
    declared = document.get("assertion_count")
    if declared != len(assertions):
        raise Refusal(
            f"{where}: the document claims {declared} assertions but carries {len(assertions)}"
        )
    if document.get("failures"):
        raise Refusal(f"{where}: the document lists failures")
    # The same control cannot be counted twice under one name: a duplicated assertion would inflate
    # the count without adding evidence.
    names = [item["name"] for item in assertions]
    if len(set(names)) != len(names):
        duplicated = sorted({name for name in names if names.count(name) > 1})
        raise Refusal(f"{where}: assertions are duplicated: {duplicated[:5]}")
    return assertions


def observations_equal(raw: object, reported: object) -> bool:
    """Compare observations exactly, except for up to two ULPs in JSON float round trips.

    serde_json reads the journal before emitting run.json. Derived MiB/seconds floats can move by
    one representable step; byte counts, nanoseconds, identities, booleans and results cannot.
    """
    if type(raw) is not type(reported):
        return False
    if isinstance(raw, float):
        return (math.isfinite(raw) and math.isfinite(reported)
                and abs(raw - reported) <= 2 * max(math.ulp(raw), math.ulp(reported)))
    if isinstance(raw, dict):
        return raw.keys() == reported.keys() and all(
            observations_equal(value, reported[key]) for key, value in raw.items())
    if isinstance(raw, list):
        return len(raw) == len(reported) and all(
            observations_equal(a, b) for a, b in zip(raw, reported))
    return raw == reported


def abort_if_journal_lacks_observations(document: dict, where: str, root: Path | None) -> None:
    """The journal is the raw record the document was built from; an empty one proves nothing.

    The review replaced `journal.jsonl` with a single `{}` and the checker still accepted the run,
    because it never opened the journal at all. The document claims to be derived from it, so the
    derivation is checked: the journal must carry every point, every round and every assertion the
    document reports.
    """
    raw_declared = document.get("journal")
    if not isinstance(raw_declared, str) or not raw_declared:
        raise Refusal(f"{where}: the document names no journal, so its raw evidence is unknown")
    document_path = Path(where)
    candidates = [document_path.parent / "journal.jsonl"]
    if root is not None:
        candidates.append(root / document_path.parent.name / "journal.jsonl")
    journal = next((path for path in candidates if path.is_file()), None)
    if journal is None:
        raise Refusal(f"{where}: the journal {raw_declared!r} is not on disk")

    kinds: dict[str, list[dict]] = {"point": [], "round": [], "assertion": []}
    for line_number, line in enumerate(journal.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except ValueError as error:
            raise Refusal(f"{journal}:{line_number}: not JSON: {error}") from error
        if not isinstance(entry, dict):
            raise Refusal(f"{journal}:{line_number}: a journal record is not an object")
        kind = entry.get("record")
        if kind in kinds:
            kinds[kind].append(entry.get("value"))
        elif kind is None:
            raise Refusal(f"{journal}:{line_number}: a journal record names no kind")

    if not kinds["point"]:
        raise Refusal(f"{journal}: the journal contains no observation points")
    if not kinds["round"]:
        raise Refusal(f"{journal}: the journal contains no reload rounds")
    if not kinds["assertion"]:
        raise Refusal(f"{journal}: the journal contains no assertions")

    # Every point in the document must have come from the journal, by phase.
    document_phases = [point.get("phase") for point in document.get("points") or []]
    journal_phases = [point.get("phase") for point in kinds["point"] if isinstance(point, dict)]
    if document_phases != journal_phases:
        missing = sorted(set(document_phases) - set(journal_phases))
        extra = sorted(set(journal_phases) - set(document_phases))
        raise Refusal(
            f"{journal}: the document's observation points do not match the journal "
            f"(missing from journal: {missing[:5]}, only in journal: {extra[:5]})"
        )
    if len(document.get("rounds") or []) != len(kinds["round"]):
        raise Refusal(
            f"{journal}: the journal has {len(kinds['round'])} rounds, the document reports "
            f"{len(document.get('rounds') or [])}"
        )
    if len(document.get("assertions") or []) != len(kinds["assertion"]):
        raise Refusal(
            f"{journal}: the journal has {len(kinds['assertion'])} assertions, the document reports "
            f"{len(document.get('assertions') or [])}"
        )
    for kind, field in (("point", "points"), ("round", "rounds"), ("assertion", "assertions")):
        for index, (raw, reported) in enumerate(zip(kinds[kind], document[field]), start=1):
            if not observations_equal(raw, reported):
                raise Refusal(f"{journal}: {kind} record {index} content does not match the report")


def verify_rounds(document: dict, where: str, points: dict[str, dict], artifacts: dict) -> dict:
    """Every round is checked against the generation sequence and the derived A/B effect.

    The first delivery trusted each round's own `effect_expected` and `effect_ok`, so a document that
    changed the actual URL *and* the declared expectation together was accepted; and it counted rounds
    without checking their numbers, so one observation duplicated twenty times passed as twenty.
    """
    rounds = document.get("rounds")
    if not isinstance(rounds, list):
        raise Refusal(f"{where}: no per-round records")

    unchanged = [item for item in rounds if item.get("kind") == "unchanged"]
    ab = [item for item in rounds if item.get("kind") == "ab"]
    if len(unchanged) != UNCHANGED_RELOADS:
        raise Refusal(
            f"{where}: {len(unchanged)} unchanged reloads recorded, {UNCHANGED_RELOADS} required"
        )
    if len(ab) != AB_ROUNDS:
        raise Refusal(f"{where}: {len(ab)} A/B rounds recorded, {AB_ROUNDS} required")

    baseline_generation = points["started-a"].get("generation")
    if not isinstance(baseline_generation, int):
        raise Refusal(f"{where}: no generation at start")
    ab_start_generation = points["reloaded-b"].get("generation")
    if not isinstance(ab_start_generation, int):
        raise Refusal(
            f"{where}: no generation after the B reload, so the A/B rounds cannot be pinned"
        )
    if ab_start_generation != baseline_generation + 1:
        raise Refusal(
            f"{where}: the B reload moved the generation from {baseline_generation} to "
            f"{ab_start_generation}; one swap must advance it exactly once"
        )

    # Round numbers must be exactly 1..N, each exactly once. A duplicated record cannot stand in for
    # the rounds it is supposed to summarise.
    for label, items, count in (("unchanged", unchanged, UNCHANGED_RELOADS), ("A/B", ab, AB_ROUNDS)):
        numbers = [item.get("round") for item in items]
        if numbers != list(range(1, count + 1)):
            raise Refusal(
                f"{where}: the {label} rounds are numbered {numbers[:6]}…, expected 1..{count} each "
                "exactly once"
            )
        # An observation repeated verbatim is one observation, not N.
        signatures = {
            json.dumps({key: value for key, value in item.items() if key != "round"}, sort_keys=True)
            for item in items
        }
        if len(signatures) < 2:
            raise Refusal(
                f"{where}: all {count} {label} rounds carry identical observations, so they are one "
                "observation repeated rather than independent rounds"
            )

    for item in unchanged:
        index = item.get("round")
        window = item.get("window")
        if not isinstance(window, dict):
            raise Refusal(f"{where}: unchanged reload {index} has no measurement window")
        window_of({"window": window}, where, f"unchanged reload {index}")
        if not item.get("returned"):
            raise Refusal(f"{where}: unchanged reload {index} reported a failed swap")
        if item.get("generation") != baseline_generation:
            raise Refusal(
                f"{where}: unchanged reload {index} moved the generation to {item.get('generation')} "
                f"(start was {baseline_generation}) — an unchanged artifact set must install nothing"
            )
        if not item.get("objects_reused"):
            raise Refusal(f"{where}: unchanged reload {index} rebuilt the rule objects")
        # The effect is the derived one, not the round's own claim. A unchanged set is still A.
        if item.get("effect_url") != artifacts["effect_a"]:
            raise Refusal(
                f"{where}: unchanged reload {index} decided {item.get('effect_url')!r}, the rule in "
                f"force requires {artifacts['effect_a']!r}"
            )

    expected = ab_start_generation
    for item in ab:
        index = item.get("round")
        window = item.get("window")
        if not isinstance(window, dict):
            raise Refusal(f"{where}: A/B round {index} has no measurement window")
        window_of({"window": window}, where, f"A/B round {index}")
        expected += 1
        if not item.get("returned"):
            raise Refusal(f"{where}: A/B round {index} reported a failed swap")
        if item.get("generation") != expected:
            raise Refusal(
                f"{where}: A/B round {index} advanced the generation to {item.get('generation')}, "
                f"expected exactly {expected}"
            )
        # Which artifact set this round loaded decides what it must have decided. The round cannot
        # pick the expectation that suits whatever it recorded.
        loaded = item.get("loaded")
        if loaded not in ("a", "b"):
            raise Refusal(f"{where}: A/B round {index} does not say which artifact set it loaded")
        want = artifacts["effect_a"] if loaded == "a" else artifacts["effect_b"]
        # The sequence is A/B alternating from B; round 1 loads A.
        want_loaded = "a" if index % 2 == 1 else "b"
        if loaded != want_loaded:
            raise Refusal(
                f"{where}: A/B round {index} loaded {loaded!r}; the alternation requires {want_loaded!r}"
            )
        if item.get("effect_url") != want:
            raise Refusal(
                f"{where}: A/B round {index} loaded {loaded!r} and decided {item.get('effect_url')!r}, "
                f"the rule in force requires {want!r}"
            )
        if not item.get("identities_match_ondisk"):
            raise Refusal(f"{where}: A/B round {index} reported identities not on disk")
        if not item.get("previous_rules_released"):
            raise Refusal(f"{where}: A/B round {index} left the previous rule set strongly referenced")
        if not item.get("filter_object_stable"):
            raise Refusal(f"{where}: A/B round {index} replaced the filter object, not its contents")

    def same_window(observed: dict, reported: dict, label: str) -> None:
        # The point gives the operation a phase name, but all measured values must be identical.
        values = lambda w: {k: v for k, v in w.items() if k != "operation"}
        if not observations_equal(values(observed), values(reported)):
            raise Refusal(f"{where}: {label} window does not match its round observation")

    same_window(max(unchanged, key=lambda r: r["window"]["peak_bytes"])["window"],
                points["unchanged-reloads-done"]["window"], "unchanged-reloads-done")
    for item in ab:
        phase = f"ab-round-{item['round']:02}"
        if points[phase].get("generation") != item["generation"]:
            raise Refusal(f"{where}: {phase} generation does not match its round observation")
        same_window(item["window"], points[phase]["window"], phase)
    for phase in ("first-removeparam-evaluation", "unchanged-reloads-done", "compiled-b"):
        if points[phase].get("generation") != baseline_generation:
            raise Refusal(f"{where}: {phase} changed generation before the first swap")
    if points["settled"].get("generation") != ab[-1]["generation"]:
        raise Refusal(f"{where}: settled generation does not match the final A/B round")
    return {"unchanged": len(unchanged), "ab": len(ab), "ab_start_generation": ab_start_generation}


def verify_resources(document: dict, where: str, points: dict[str, dict]) -> dict:
    baseline = points["process-baseline"]
    stopped = points["stopped"]
    base_fds = baseline.get("fd_count")
    base_threads = baseline.get("thread_count")
    settle = stopped.get("fd_count"), stopped.get("thread_count")
    if settle[0] is not None and base_fds is not None and settle[0] > base_fds:
        raise Refusal(
            f"{where}: {settle[0]} descriptors remain after the stop, baseline was {base_fds}"
        )
    if settle[1] is not None and base_threads is not None and settle[1] > base_threads:
        raise Refusal(
            f"{where}: {settle[1]} threads remain after the stop, baseline was {base_threads}"
        )
    weaks = stopped.get("weaks")
    for field in ("filter_strong", "dns_strong", "engine_strong", "extras_strong"):
        if not isinstance(weaks, dict) or type(weaks.get(field)) is not int or weaks[field] != 0:
            raise Refusal(f"{where}: stopped {field} does not prove the rule object was released")
    return {
        "baseline_fds": base_fds,
        "baseline_threads": base_threads,
        "stopped_fds": settle[0],
        "stopped_threads": settle[1],
    }


def verify_summary(document: dict, where: str, points: dict[str, dict]) -> dict:
    """Every number the summary asserts must be recomputable from the raw windows and points.

    The review set `reload_peak_bytes` to `2**60` and `unchanged_reload_peak_bytes` to `-1`; both were
    accepted because the summary was never recomputed. Here each figure is derived and compared, and
    the derivation is the only definition of the field the checker accepts.
    """
    summary = document.get("summary")
    if not isinstance(summary, dict):
        raise Refusal(f"{where}: no summary")

    def counted_live(phase: str) -> int:
        value = points[phase]["counted"]["live_bytes"]
        if not isinstance(value, int):
            raise Refusal(f"{where}: {phase} has no counted live heap")
        return value

    def window_peak(phase: str) -> int:
        window = points[phase].get("window")
        if not isinstance(window, dict):
            raise Refusal(f"{where}: {phase} has no measurement window")
        return window["peak_bytes"]

    expected = {
        "baseline_live_bytes": counted_live("process-baseline"),
        "holding_live_bytes": counted_live("settled"),
        "post_stop_live_bytes": counted_live("stopped"),
        "unchanged_reload_peak_bytes": window_peak("unchanged-reloads-done"),
    }
    expected["released_by_stop_bytes"] = max(
        0, expected["holding_live_bytes"] - expected["post_stop_live_bytes"]
    )
    # The A/B rounds carry their own windows; the highest of them is the reload peak. Reading it from
    # the rounds rather than from a summary of points is what makes the figure traceable to the
    # individual swaps it claims to describe.
    ab_rounds = [item for item in document.get("rounds") or [] if item.get("kind") == "ab"]
    if not ab_rounds:
        raise Refusal(f"{where}: no A/B round observations")
    ab_peaks = []
    for item in ab_rounds:
        window = item.get("window")
        if not isinstance(window, dict):
            raise Refusal(f"{where}: A/B round {item.get('round')} has no measurement window")
        ab_peaks.append(window["peak_bytes"])
    expected["reload_peak_bytes"] = max(ab_peaks)

    for field, want in expected.items():
        got = summary.get(field)
        if got != want:
            raise Refusal(
                f"{where}: summary {field} is {got!r}, the raw observations give {want}"
            )

    # The excess figures must be the excess over the heap of the same instant, not over some later
    # steady state — that substitution is what turned 0.50 MiB into 0.30 MiB in the first report.
    excess = summary.get("unchanged_reload_excess_bytes")
    want_excess = expected["unchanged_reload_peak_bytes"] - counted_live("unchanged-reloads-done")
    if excess is not None and excess != want_excess:
        raise Refusal(
            f"{where}: summary unchanged_reload_excess_bytes is {excess!r}, the same-instant excess is "
            f"{want_excess}"
        )
    reload_excess = summary.get("reload_excess_max_bytes")
    if reload_excess is not None:
        want_reload_excess = expected["reload_peak_bytes"] - counted_live("settled")
        if reload_excess != want_reload_excess:
            raise Refusal(
                f"{where}: summary reload_excess_max_bytes is {reload_excess!r}, the same-instant "
                f"excess is {want_reload_excess}"
            )

    unchanged_live = counted_live("unchanged-reloads-done")
    if expected["unchanged_reload_peak_bytes"] < unchanged_live:
        raise Refusal(
            f"{where}: the unchanged reload peak {expected['unchanged_reload_peak_bytes']} is below the "
            f"live heap it settled to {unchanged_live}"
        )
    return {
        **expected,
        "unchanged_reload_excess_bytes": want_excess,
        "holding_rss_kib": (points["settled"].get("smaps") or {}).get("Rss"),
        "compiled_a_peak_bytes": window_peak("compiled-a"),
        "started_a_peak_bytes": window_peak("started-a"),
        "stopped_peak_bytes": window_peak("stopped"),
    }


def check_run(path: Path, root: Path | None = None) -> dict:
    """Check one run document. Returns the facts a report may quote, or raises Refusal."""
    document = load_document(path)
    where = str(path)
    if document.get("schema") != SCHEMA:
        raise Refusal(f"{where}: schema {document.get('schema')!r} is not {SCHEMA!r}")
    if document.get("result") != "pass":
        raise Refusal(f"{where}: the example reported {document.get('result')!r}")
    if document.get("formal") is not True:
        raise Refusal(
            f"{where}: formal={document.get('formal')!r}; a self-test run is not evidence for a real "
            "rule set"
        )

    inputs = verify_inputs(document, where, root)
    artifacts = verify_artifacts(document, where, root)
    points = verify_points(document, where)
    verify_loaded_identity(document, where, points, artifacts)
    assertions = verify_assertions(document, where)
    rounds = verify_rounds(document, where, points, artifacts)
    resources = verify_resources(document, where, points)
    summary = verify_summary(document, where, points)
    abort_if_journal_lacks_observations(document, where, root)
    verify_command(document, where, root)

    binary = document.get("binary") or {}
    if not isinstance(binary.get("sha256"), str) or len(binary["sha256"]) != 64:
        raise Refusal(f"{where}: no binary hash, so the example that produced this is unknown")

    return {
        "path": where,
        "run_id": document.get("run_id"),
        "group": inputs["group"],
        "pid": document.get("pid"),
        "started_unix_ns": document.get("started_unix_ns"),
        "duration_seconds": document.get("duration_seconds"),
        "binary_sha256": binary["sha256"],
        "inputs": inputs,
        "points": len(points),
        "assertions": len(assertions),
        "rounds": rounds,
        "premise": artifacts,
        "resources": resources,
        "summary": summary,
    }


def verify_command(document: dict, where: str, root: Path | None) -> dict:
    """The recorded invocation must agree with the document it produced.

    `command.json` is written by the driver, beside the run it drove. Checking it against the document
    is what makes an attempt directory evidence of *this* run rather than a place a document was put.
    """
    document_path = Path(where)
    candidates = [document_path.parent / "command.json"]
    if root is not None:
        candidates.append(root / document_path.parent.name / "command.json")
    command_path = next((path for path in candidates if path.is_file()), None)
    if command_path is None:
        raise Refusal(f"{where}: no command.json beside the run, so the invocation is unknown")
    try:
        command = json.loads(command_path.read_text(encoding="utf-8"))
    except ValueError as error:
        raise Refusal(f"{command_path}: not JSON: {error}") from error
    if not isinstance(command, dict):
        raise Refusal(f"{command_path}: not an object")
    if command.get("group") != document.get("group"):
        raise Refusal(
            f"{command_path}: the invocation ran group {command.get('group')!r}, the document reports "
            f"{document.get('group')!r}"
        )
    argv = command.get("argv")
    if not isinstance(argv, list) or "--group" not in argv:
        raise Refusal(f"{command_path}: no recorded argv")
    index = argv.index("--group")
    if index + 1 >= len(argv) or argv[index + 1] != document.get("group"):
        raise Refusal(f"{command_path}: argv does not select the document's group")
    if command.get("returncode") != 0:
        raise Refusal(f"{command_path}: the recorded invocation exited {command.get('returncode')}")
    if document.get("run_index") is not None and command.get("index") is not None:
        if command["index"] != document["run_index"]:
            raise Refusal(
                f"{command_path}: the invocation ran index {command['index']}, the document reports "
                f"{document['run_index']}"
            )
    return {"argv": argv}


# ---------------------------------------------------------------------------------------------
# Checking a whole run directory
# ---------------------------------------------------------------------------------------------


def run_documents(root: Path) -> list[Path]:
    """The evidence documents under `root`.

    Exactly `run.json` per attempt directory: the driver also writes `command.json` beside it, and
    globbing every `*.json` would read the driver's own bookkeeping as a second run of the same
    process — inflating the process count the independence check relies on.
    """
    return sorted(root.glob("*-run*/run.json"))


def check_tree(root: Path, *, require_manifest: bool = True) -> dict:
    if not root.is_dir():
        raise Refusal(f"{root}: not a directory")

    # The manifest is verified **first**: it is the integrity layer, so a tree that is missing a file
    # it claims to hold must be reported as tampering rather than as "too few runs".
    manifest = verify_manifest(root) if require_manifest else {"files": 0, "verified": False}

    paths = run_documents(root)
    if not paths:
        raise Refusal(f"{root}: no run documents (*-run*/run.json)")

    runs = [check_run(path, root) for path in paths]

    by_group: dict[str, list[dict]] = {}
    for run in runs:
        by_group.setdefault(run["group"], []).append(run)

    # A formal campaign is five *and* nine, three independent processes each. A tree that quietly
    # dropped one group is not a smaller complete campaign; it is an incomplete one.
    for group in GROUPS:
        if group not in by_group:
            raise Refusal(f"{root}: the {group}-list group is missing entirely")
    for group, items in by_group.items():
        if len(items) < RUNS_PER_GROUP:
            raise Refusal(
                f"{group}: {len(items)} independent process(es), {RUNS_PER_GROUP} required"
            )
        pids = {item["pid"] for item in items}
        if len(pids) != len(items):
            raise Refusal(
                f"{group}: two runs share a pid {sorted(pids)}, so they are not independent processes"
            )
        if any(item["pid"] is None for item in items):
            raise Refusal(f"{group}: a run reports no pid, so its independence cannot be checked")
        run_ids = {item["run_id"] for item in items}
        if len(run_ids) != len(items):
            raise Refusal(f"{group}: two runs share a run_id {sorted(run_ids)}")
        # Three processes of one group must have compiled the same rule content — otherwise the
        # samples describe different rule sets and a median over them means nothing.
        identities = {item["premise"]["dns_payload_bytes"] for item in items}
        if len(identities) != 1:
            raise Refusal(f"{group}: the runs compiled dns.bin of different sizes {sorted(identities)}")
        engines = {item["premise"]["engine_payload_bytes"] for item in items}
        if len(engines) != 1:
            raise Refusal(f"{group}: the runs compiled engine.bin of different sizes {sorted(engines)}")
        extras = {
            (item["premise"]["extras_a_sha256"], item["premise"]["extras_b_sha256"])
            for item in items
        }
        if len(extras) != 1:
            raise Refusal(f"{group}: the runs compiled different extras.txt on at least one side")

    started = sorted(
        (item["started_unix_ns"], item["pid"]) for item in runs if item["started_unix_ns"] is not None
    )
    if len(started) != len(runs):
        raise Refusal(f"{root}: a run reports no start time, so the campaign has no order")
    if [pid for _, pid in started] != [pid for _, pid in sorted(started)]:
        raise Refusal(f"{root}: the runs are not ordered by their own start times")

    return {
        "root": str(root),
        "runs": runs,
        "groups": sorted(by_group),
        "manifest": manifest,
        "verdict": "evidence-structurally-valid",
        "not_claimed": [
            "Android PSS",
            "the 84.6 MiB five-list threshold",
            "device behaviour of any kind",
        ],
    }


def manifest_relpath(path: Path, root: Path) -> str:
    """The manifest lists evidence documents, not the derived compiled artifacts.

    `dns.bin`/`engine.bin` are ~500 MB across six runs and are *derived*: they are exactly what the
    compile produces from the input bodies and the binary, both of which the manifest does cover.
    Hashing them would make the evidence package unshippable while adding nothing a reviewer can act
    on. They stay on disk beside their runs; the package's `COMPILED.sha256` records them for anyone
    who needs to re-check a specific run in place.
    """
    return str(path.relative_to(root))


def manifest_targets(root: Path) -> list[Path]:
    """Every file the manifest covers.

    Everything present except the manifest itself — the compiled artifacts included when they are on
    disk. Sealing more is stronger evidence, and sealing less would let an artifact change under a
    package that still verified.
    """
    return [
        path
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != "MANIFEST.sha256"
    ]


def verify_manifest(root: Path) -> dict:
    """Every listed file must be present and unchanged, and no evidence file may be unlisted."""
    manifest_path = root / "MANIFEST.sha256"
    if not manifest_path.is_file():
        raise Refusal(f"{root}: no MANIFEST.sha256")
    listed: dict[str, str] = {}
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        digest, _, name = line.partition("  ")
        if not digest or not name:
            raise Refusal(f"{root}: malformed MANIFEST line {line!r}")
        if name in listed:
            raise Refusal(f"{root}: MANIFEST lists {name} twice")
        if name == "MANIFEST.sha256":
            raise Refusal(
                f"{root}: the MANIFEST lists itself, which cannot be verified and is excluded by "
                "the card's '不含自身' requirement"
            )
        listed[name] = digest

    for name, digest in listed.items():
        target = root / name
        if not target.is_file():
            raise Refusal(f"{root}: MANIFEST lists {name}, which does not exist")
        actual = sha256_file(target)
        if actual != digest:
            raise Refusal(f"{root}: {name} hashes to {actual}, the MANIFEST says {digest}")

    # Every file present must be listed: an unlisted file is evidence nobody sealed.
    present = {
        str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()
    } - {"MANIFEST.sha256"}
    unlisted = present - set(listed)
    if unlisted:
        raise Refusal(f"{root}: files present but not in the MANIFEST: {sorted(unlisted)[:5]}")
    # A listed file that is not on disk was already refused above. Anything else the manifest chose to
    # cover — the compiled artifacts included — is accepted once it verifies: a manifest that covers
    # *more* is stronger evidence, and refusing it would punish a fuller seal.
    return {
        "files": len(listed),
        "verified": True,
        "covers_compiled_artifacts": any("/compiled-" in name for name in listed),
        "excludes": "itself",
    }


def prepare_input_copy(source: Path, destination: Path) -> dict:
    """Copy a list directory read-only, then verify the copy against the published manifest.

    The copy is what the run compiles from, so the original cache is never opened for writing and a
    later accidental write cannot change the evidence's inputs. Verification happens on the *copy*:
    a hash taken from the source would say nothing about the bytes the compile will read.
    """
    if not source.is_dir():
        raise Refusal(f"{source}: not a directory")
    if destination.exists():
        raise Refusal(f"{destination}: already exists; attempts are never overwritten")
    shutil.copytree(source, destination)
    for path in destination.rglob("*"):
        if path.is_file():
            path.chmod(0o444)
    return verify_list_directory(destination)


def verify_list_directory(directory: Path) -> dict:
    """Every `.txt` in `directory` must match the published manifest, and nothing else may be there."""
    found: dict[str, dict] = {}
    for path in sorted(directory.glob("*.txt")):
        digest = sha256_file(path)
        size = path.stat().st_size
        found[path.stem] = {"bytes": size, "sha256": digest, "path": str(path)}
    unknown = [name for name in found if name not in CANONICAL]
    if unknown:
        raise Refusal(f"{directory}: bodies that are not in the manifest: {unknown}")
    bad = [
        name
        for name, facts in found.items()
        if (facts["bytes"], facts["sha256"]) != CANONICAL[name]
    ]
    if bad:
        raise Refusal(f"{directory}: bodies that do not match the manifest: {bad}")
    return found


def write_manifest(root: Path) -> Path:
    """Hash every evidence file under `root`, **excluding the manifest itself**.

    A file cannot contain its own hash, so the card requires a manifest that leaves itself out. The
    exclusion is honest rather than a gap: the manifest's own bytes are reproducible from the tree,
    and every file it *does* list is verified.
    """
    manifest = root / "MANIFEST.sha256"
    if manifest.exists():
        raise Refusal(f"{manifest}: already exists; a run directory is never rewritten")
    entries = [
        f"{sha256_file(path)}  {manifest_relpath(path, root)}" for path in manifest_targets(root)
    ]
    manifest.write_text("\n".join(entries) + "\n", encoding="utf-8")
    return manifest


def run_group(binary: Path, group: str, lists: Path, out: Path, *, trim_diagnostic: bool) -> list[Path]:
    """Three independent processes of one group, each into its own new directory."""
    produced = []
    for index in range(1, RUNS_PER_GROUP + 1):
        run_dir = out / f"{group}-run{index:02d}"
        if run_dir.exists():
            raise Refusal(f"{run_dir}: already exists; a previous attempt is never overwritten")
        run_dir.mkdir(parents=True)
        command = [
            str(binary),
            "--work",
            str(out),
            "--lists",
            str(lists),
            "--group",
            group,
            "--run",
            str(index),
            "--run-id",
            f"{group}-r{index}",
        ]
        if trim_diagnostic:
            command.append("--trim-diagnostic")
        started = datetime.datetime.now(datetime.timezone.utc).isoformat()
        result = subprocess.run(command, capture_output=True, text=True)
        # Every attempt is kept, successful or not: a failed process is evidence about the run. The
        # example's single JSON document is the evidence file, so it is written as `run.json` and
        # *not* duplicated as `stdout.json` — one observation, one file, so the checker cannot read
        # the same run twice and count it as two processes.
        (run_dir / "run.json").write_text(result.stdout, encoding="utf-8")
        (run_dir / "stderr.log").write_text(result.stderr, encoding="utf-8")
        (run_dir / "command.json").write_text(
            json.dumps(
                {
                    "argv": command,
                    "started_at": started,
                    "returncode": result.returncode,
                    "group": group,
                    "index": index,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        if result.returncode != 0:
            raise Refusal(
                f"{run_dir}: the example exited {result.returncode}; see its stderr.log"
            )
        produced.append(run_dir / "run.json")
        print(f"  {group} run {index}: exit 0", file=sys.stderr)
    return produced


def command_run(args: argparse.Namespace) -> int:
    binary = Path(args.binary)
    if not binary.is_file():
        raise Refusal(f"{binary}: no such binary; build the example first")
    out = Path(args.out)
    if out.exists():
        raise Refusal(f"{out}: already exists; a run directory is never overwritten")

    out.mkdir(parents=True)
    inputs = out / "inputs"
    inputs.mkdir()
    plan = {
        "binary": {"path": str(binary), "sha256": sha256_file(binary)},
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "runs_per_group": RUNS_PER_GROUP,
        "groups": {},
        "trim_diagnostic": bool(args.trim_diagnostic),
        "note": (
            "host glibc process; not Android PSS and not the 84.6 MiB device threshold"
        ),
    }
    for group, source in (("five", args.lists_five), ("nine", args.lists_nine)):
        if source is None:
            if group == "nine":
                # Allow a partial diagnostic run; the formal checker still requires both groups.
                continue
            raise Refusal(f"--lists-{group} is required")
        copy = inputs / f"lists-{group}"
        plan["groups"][group] = prepare_input_copy(Path(source), copy)
        print(f"inputs for {group}: {len(plan['groups'][group])} bodies verified", file=sys.stderr)

    (out / "plan.json").write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")

    produced = []
    for group in plan["groups"]:
        produced.extend(
            run_group(
                binary,
                group,
                inputs / f"lists-{group}",
                out,
                trim_diagnostic=bool(args.trim_diagnostic),
            )
        )

    manifest = write_manifest(out)
    print(f"wrote {len(produced)} run documents and {manifest}", file=sys.stderr)
    return 0


def command_check(args: argparse.Namespace) -> int:
    root = Path(args.root)
    try:
        report = check_tree(root, require_manifest=not args.no_manifest)
    except Refusal as error:
        if args.json:
            print(json.dumps({"ok": False, "problems": [str(error)]}, indent=2))
        else:
            print(f"REFUSED: {error}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps({"ok": True, **report}, indent=2))
    else:
        print(f"evidence under {root}: {len(report['runs'])} run(s), groups {report['groups']}")
        for run in report["runs"]:
            summary = run["summary"]
            print(
                f"  {run['group']} pid {run['pid']}: "
                f"holding {summary['holding_live_bytes'] / 1048576:.3f} MiB, "
                f"reload peak {summary['reload_peak_bytes'] / 1048576:.3f} MiB, "
                f"released by stop {summary['released_by_stop_bytes'] / 1048576:.3f} MiB"
            )
        print(f"manifest: {report['manifest']['files']} files verified")
        print("not claimed: " + ", ".join(report["not_claimed"]))
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="drive the example into a fresh evidence directory")
    run.add_argument("--binary", required=True)
    run.add_argument("--lists-five", required=True)
    run.add_argument("--lists-nine", default=None)
    run.add_argument("--out", required=True)
    run.add_argument("--trim-diagnostic", action="store_true")
    run.set_defaults(func=command_run)

    check = sub.add_parser("check", help="decide whether a run directory's evidence holds")
    check.add_argument("root")
    check.add_argument("--json", action="store_true")
    check.add_argument(
        "--no-manifest",
        action="store_true",
        help="skip the manifest requirement (for a directory being inspected before it is sealed)",
    )
    check.set_defaults(func=command_check)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Refusal as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
