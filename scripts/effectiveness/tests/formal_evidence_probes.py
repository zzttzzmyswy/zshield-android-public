#!/usr/bin/env python3
"""Offline probes: the acceptable campaign is accepted, and each defect is refused.

The point of pairing them in one run is that a rejection only means something next to a positive
control. `build_formal_fixture.py` writes a campaign whose three evidence layers all hold; this
script first confirms `recompute` gives it a formal verdict, then applies one defect at a time and
confirms the verdict is withdrawn **for that reason**.

Every probe runs `recompute` as a subprocess on a copy of the fixture: no adb, no device, no network.

Usage:
    formal_evidence_probes.py [REPO]        # REPO defaults to the repository root

Exit status is 0 only when the positive control passed and every defect was refused.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_REPO = HERE.parent.parent.parent
TOOL_RELATIVE = Path("scripts/effectiveness/memory_profile.py")
FIXTURE_RELATIVE = Path("scripts/effectiveness/tests/build_formal_fixture.py")

#: name -> (mutate(campaign_dir), a substring one refused problem must contain)
DEFECTS = {}


def defect(name: str, needle: str):
    def register(function):
        DEFECTS[name] = (function, needle)
        return function
    return register


@defect("missing_order", "no `attempts` list")
def _missing_order(campaign: Path) -> None:
    record = json.loads((campaign / "campaign.json").read_text())
    record.pop("attempts")
    record.pop("order", None)
    (campaign / "campaign.json").write_text(json.dumps(record))


@defect("forged_plan_order", "consecutively")
def _forged_plan_order(campaign: Path) -> None:
    """The delivered bundle's shape: `order` claims alternation, the runs do not alternate."""
    record = json.loads((campaign / "campaign.json").read_text())
    for entry in record["attempts"]:
        if entry["cell"][0] == "v012":
            entry["started_at"] = "2026-11-13T00:50:00Z"
            entry["finished_at"] = "2026-11-13T00:58:00Z"
    (campaign / "campaign.json").write_text(json.dumps(record))


@defect("rerun_overwrote_history", "result file says")
def _rerun_overwrote_history(campaign: Path) -> None:
    """Later data stuffed into a past slot: the result file's own stamp no longer matches."""
    for result in sorted(campaign.glob("default-nine--v012--b*/result.txt")):
        text = result.read_text()
        result.write_text(re.sub(r"at=\S+", "at=2026-11-13T03:40:00Z", text, count=1))


@defect("one_second_samples", "s apart but the batch declares")
def _one_second_samples(campaign: Path) -> None:
    for result in sorted(campaign.glob("*/result.txt")):
        lines = []
        for line in result.read_text().splitlines():
            if re.match(r"^\d+\t", line):
                parts = line.split("\t")
                parts[1] = parts[0]
                line = "\t".join(parts)
            lines.append(line)
        result.write_text("\n".join(lines) + "\n")


@defect("same_second_samples", "strictly increase")
def _same_second_samples(campaign: Path) -> None:
    for result in sorted(campaign.glob("*/result.txt")):
        lines = []
        for line in result.read_text().splitlines():
            if re.match(r"^\d+\t", line):
                parts = line.split("\t")
                parts[1] = "0"
                line = "\t".join(parts)
            lines.append(line)
        result.write_text("\n".join(lines) + "\n")


@defect("reversed_samples", "strictly increase")
def _reversed_samples(campaign: Path) -> None:
    for result in sorted(campaign.glob("*/result.txt")):
        rows, other = [], []
        for line in result.read_text().splitlines():
            (rows if re.match(r"^\d+\t", line) else other).append(line)
        rewritten = []
        for line in rows:
            parts = line.split("\t")
            parts[1] = str((6 - int(parts[0])) * 60)
            rewritten.append("\t".join(parts))
        result.write_text("\n".join(other + rewritten) + "\n")


@defect("missing_input_records", "no input record at all")
def _missing_input_records(campaign: Path) -> None:
    record = json.loads((campaign / "campaign.json").read_text())
    record["plan"].pop("inputs")
    (campaign / "campaign.json").write_text(json.dumps(record))


@defect("missing_list_content_hash", "no content hash for list(s)")
def _missing_list_content_hash(campaign: Path) -> None:
    record = json.loads((campaign / "campaign.json").read_text())
    record["plan"]["inputs"]["candidate/fixed-five"]["lists"][0].pop("sha256")
    (campaign / "campaign.json").write_text(json.dumps(record))


@defect("missing_artifact_hash", "missing loaded_artifacts_sha256")
def _missing_artifact_hash(campaign: Path) -> None:
    record = json.loads((campaign / "campaign.json").read_text())
    record["plan"]["inputs"]["candidate/fixed-five"].pop("loaded_artifacts_sha256")
    (campaign / "campaign.json").write_text(json.dumps(record))


@defect("legacy_counts_only", "cannot produce a content identity")
def _legacy_counts_only(campaign: Path) -> None:
    """A legacy build cannot print a content hash; recording one for it is invented evidence."""
    record = json.loads((campaign / "campaign.json").read_text())
    record["plan"]["builds"]["v012"]["legacy"] = True
    record["plan"]["builds"]["v012"]["identities"] = {
        "fixed-five": "engine_bytes=32198109 block_rules=180571 network_rules=406819",
        "default-nine": "engine_bytes=32198109 block_rules=180571 network_rules=406819",
    }
    (campaign / "campaign.json").write_text(json.dumps(record))


def recompute(tool: Path, campaign: Path) -> tuple[int, dict]:
    run = subprocess.run([sys.executable, str(tool), "recompute", str(campaign), "--json"],
                         capture_output=True, text=True)
    document = json.loads(run.stdout) if run.stdout.lstrip().startswith("{") else {}
    return run.returncode, document


def main(argv: list[str]) -> int:
    repo = Path(argv[0]).resolve() if argv else DEFAULT_REPO
    tool = repo / TOOL_RELATIVE
    fixture = repo / FIXTURE_RELATIVE
    if not tool.is_file() or not fixture.is_file():
        raise SystemExit(f"{repo}: expected {TOOL_RELATIVE} and {FIXTURE_RELATIVE}")

    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="formal-probes-") as name:
        root = Path(name)
        pristine = root / "pristine"
        build = subprocess.run([sys.executable, str(fixture), str(pristine)],
                               capture_output=True, text=True)
        if build.returncode != 0:
            print(build.stdout + build.stderr, file=sys.stderr)
            raise SystemExit("the reference fixture could not be written")

        status, document = recompute(tool, pristine)
        layer = document.get("layer") or {}
        comparisons = document.get("comparisons") or []
        accepted = (status == 0 and document.get("ok") is True
                    and layer.get("formally_comparable") is True and len(comparisons) == 2)
        print(f"valid_formal_campaign: exit={status} ok={document.get('ok')} "
              f"samples={layer.get('samples_valid')} inputs={layer.get('inputs_proven')} "
              f"order={layer.get('order_proven')} comparisons={len(comparisons)} "
              f"expected=exit 0 with 2 comparisons")
        if not accepted:
            failures.append(
                "valid_formal_campaign: the positive control never reached the judged criterion, "
                "so every rejection below would be meaningless")

        for name, (mutate, needle) in DEFECTS.items():
            campaign = root / name
            shutil.copytree(pristine, campaign)
            mutate(campaign)
            status, document = recompute(tool, campaign)
            refused = status != 0 and document.get("ok") is False
            reasons = ((document.get("problems") or [])
                       + (document.get("input_problems") or [])
                       + (document.get("order_problems") or []))
            stated = any(needle in reason for reason in reasons)
            print(f"{name}: exit={status} ok={document.get('ok')} "
                  f"comparisons={len(document.get('comparisons') or [])} "
                  f"reason_stated={stated} expected=refused with a stated reason")
            if not refused:
                failures.append(f"{name}: accepted as formal evidence")
            elif not stated:
                failures.append(f"{name}: refused, but no reason containing {needle!r}")

    for entry in failures:
        print(f"FAIL {entry}", file=sys.stderr)
    print(f"probe failures: {len(failures)} "
          f"(positive control + {len(DEFECTS)} defects)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
