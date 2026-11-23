#!/usr/bin/env python3
"""Measure idle PSS across versions and rule sets, decide on repeatability, and re-derive everything offline.

Why a second tool next to `pss_idle.sh`
--------------------------------------
`pss_idle.sh` answers one question well: *what is the idle PSS of one launch of one build under one
declared rule set?* It refuses to produce a number unless the process, handle, generation and rule
content are all provably this launch's own, and every refusal it makes was added because a review
found a way for a number to be reported for something else. That tool is the unit of measurement.
Its numbers are what this task had to explain.

What it deliberately does not do is the thing the memory attribution card asks for, and adding it
there would have meant editing an accepted tool:

* it measures **one** batch; the card needs several independent cold-start batches per
  (version, rule set) cell, because a single batch's spread was wider than the difference between
  the two versions — 5.1–7.0 MiB against 1.15 MiB (`docs/EFFECTIVENESS.md` §16.2). Reporting one
  batch per cell and comparing medians across cells is how a regression hides behind drift;
* it has no notion of a **campaign**: the order of batches, which samples belong to which batch, the
  per-cell median of medians, and the between-batch range. Those are the numbers the judgement needs
  and no single process can see them;
* it cannot **re-derive** a finished campaign from the files on disk. The stage-5/6 evidence was
  re-checked by hand, and the card asks for a command that does it without a phone.

So this tool composes `pss_idle.sh` as the unit of measurement — it never re-implements sampling,
readiness, identity or the device lock — and adds the campaign, the statistics and the offline
recompute. The unit stays in one place, which is also why a fix to it reaches both.

What it refuses to do
---------------------
The failures this tool is built to make impossible, each of which a previous round produced:

* a cell whose batches are not all the same rule content is **not** comparable, and the campaign is
  voided rather than averaged: the rule identity each batch reported is checked against the cell's
  declared identity, and a batch that disagrees voids the cell;
* a batch that came from a different app build voids the cell: the APK's SHA-256 is read from the
  device before and after each batch, and a campaign declares the two builds it compares;
* a median over samples from a voided batch is not computed at all — `pss_idle.sh` refuses to print
  one, and this tool treats "no median" as a voided batch rather than as a missing number to skip;
* the batch order is **alternating** by construction (`A B A B A B`), not one version's batches
  then the other's, because the phone warms up and the system's memory pressure drifts. A campaign
  file records the order it actually ran;
* `RSS` is never substituted for PSS, and MiB is derived from the raw kB median once, by
  `pss_idle.sh`;
* a difference between versions smaller than the between-batch range is reported as **not
  established** — the card's own rule, which the previous round violated in both directions.

Offline recompute
-----------------
`recompute` reads the campaign directory and prints the same table from the files, so a reviewer
needs no phone. It validates what it reads: sample counts per batch, one identity per cell, one APK
per version, the unit of every number, and that every batch's median really is the median of its
samples. Any of those failing is a non-zero exit, not a footnote.

Usage
-----
    memory_profile.py run --plan PLAN.json --out DIR [--issue MYS-2840]
    memory_profile.py recompute DIR [--json]
    memory_profile.py plan-check --plan PLAN.json

Exit codes: 0 success; 1 a batch or the campaign was voided; 2 the plan or the evidence is invalid.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
PSS_IDLE = HERE / "pss_idle.sh"
DEFAULT_PACKAGE = os.environ.get("PKG", "top.zztweb.zshield")

sys.path.insert(0, str(HERE))

import device_serial  # noqa: E402

#: The five lists the card fixes as 「固定五表」, and the four the default set adds. Spelled here so a
#: plan that names a different set is rejected by name rather than silently measured.
FIXED_FIVE = (
    "adguard-base",
    "adguard-tracking",
    "adguard-mobile",
    "adguard-url-tracking",
    "adguard-chinese",
)
DEFAULT_NINE_EXTRA = ("adguard-dns", "easylist-china", "ublock-unbreak", "ublock-quick-fixes")
RULE_SETS = {
    "fixed-five": FIXED_FIVE,
    "default-nine": FIXED_FIVE + DEFAULT_NINE_EXTRA,
}

#: The acceptance thresholds from `docs/DESIGN.md`, per rule set, in MiB. There is exactly one: the
#: fixed five-list set at 84.6. The nine-list set has **no** gate, and applying the five-list gate to
#: it — which the previous revision did — invents a requirement the design never set.
THRESHOLDS = {"fixed-five": 84.6}
#: Kept for the reports and plans that name the single threshold the card fixes.
THRESHOLD_MIB = THRESHOLDS["fixed-five"]

#: Identity format the core prints and `pss_idle.sh --expect-identity` accepts.
IDENTITY_TOKEN = re.compile(r"^(?:-|sha256:[0-9a-f]{64}:[0-9]+)$")
#: The `## median N kB = X MiB (min …, max …)` line `pss_idle.sh` prints for a formal run.
MEDIAN_LINE = re.compile(
    r"^## median (?P<kb>\d+(?:\.\d+)?) kB = (?P<mib>\d+\.\d+) MiB "
    r"\(min (?P<min>\d+) kB, max (?P<max>\d+) kB\)$"
)
#: A sample row: `index<TAB>elapsed<TAB>total_kb<TAB>java<TAB>native<TAB>pid<TAB>gen<TAB>handle`.
SAMPLE_ROW = re.compile(r"^(?P<index>\d+)\t(?P<elapsed>\d+)\t(?P<total>\d+)\t(?P<java>[\d?]+)\t"
                        r"(?P<native>[\d?]+)\t(?P<pid>[\d]+)\t(?P<gen>\d+)\t(?P<handle>\d+)$")
#: The batch's own start stamp and declared cadence, from its `# idle PSS — label=… at=<ISO>Z` header
#: and the `samples=N interval=<S>s` line beside it.
RESULT_STAMP = re.compile(r"at=(?P<at>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)")
RESULT_INTERVAL = re.compile(r"interval=(?P<seconds>\d+)s")
#: A legacy batch's row: six columns, because a build without `rules identity:` has no generation or
#: handle to print. Kept a distinct pattern rather than making those two columns optional, so a
#: *candidate* row that lost them is still refused — the two shapes must not be confused.
LEGACY_SAMPLE_ROW = re.compile(r"^(?P<index>\d+)\t(?P<elapsed>\d+)\t(?P<total>\d+)\t"
                               r"(?P<java>[\d?]+)\t(?P<native>[\d?]+)\t(?P<pid>[\d]+)$")
#: The identity line `pss_idle.sh` echoes once it has verified the live content against the target,
#: and the equivalent line a legacy batch writes. Both carry one `<key>=<value>` spelling or the
#: other; the value is kept verbatim so a legacy cell's numbers stay visibly numbers.
CONTENT_LINE = re.compile(r"^# effective rule content: (?P<content>\S.*)$")
#: What the app package's on-device APK hashes to, from the batch's raw directory.
APK_LINE = re.compile(r"^(?P<sha>[0-9a-f]{64})\s+\S+$")


class PlanError(Exception):
    """The plan or the evidence on disk is not usable. Exit 2."""


class CampaignError(Exception):
    """The campaign ran but produced a result that is not evidence. Exit 1."""


# ---------------------------------------------------------------------------------------------
# The plan
# ---------------------------------------------------------------------------------------------

@dataclass
class Build:
    """One app build under comparison."""

    name: str
    apk_sha256: str
    #: The `--expect-identity` string for each rule set, per compiled artifact directory on the host.
    #: Derived with `pss_idle.sh --identity <dir>` before the campaign, never typed from a document.
    identities: dict[str, str] = field(default_factory=dict)
    #: Where the APK lives on the host, so a batch can install it and a reviewer can re-hash it.
    apk_path: str = ""
    #: True for a build that predates `core/src/rules_identity.rs` and therefore cannot be measured by
    #: `pss_idle.sh`. Such a build is sampled by [`run_legacy_batch`] with the strongest evidence it
    #: can offer, and every cell it contributes to says so.
    legacy: bool = False
    #: `"declared"` tokens were computed on the host from the same list bodies the phone holds;
    #: `"device"` tokens are pinned from the phone's own first successful `rules identity:` line of
    #: the cell. The second exists because the phone's list bodies cannot be read from a release
    #: build, so a host compile is not always of the same inputs — see `docs/I2_MEMORY_PROFILE.md`
    #: §3.3. A `"device"` pin is enforced for every later batch of the cell; it is a pin, not an
    #: independent derivation, and the report says so.
    identity_source: str = "declared"

    def identity_for(self, rule_set: str) -> str:
        try:
            return self.identities[rule_set]
        except KeyError:
            raise PlanError(f"build {self.name!r} declares no identity for rule set {rule_set!r}") from None


@dataclass
class Plan:
    """What a campaign is meant to measure: builds × rule sets × batches, in an alternating order."""

    builds: dict[str, Build]
    rule_sets: dict[str, tuple[str, ...]]
    batches: int
    samples: int
    interval: int
    #: The compiled-artifact directory each (build, rule set) identity was derived from, for the record.
    artifact_dirs: dict[str, dict[str, str]] = field(default_factory=dict)
    #: Where the APK for each build lives on the host, so its hash can be re-checked offline.
    apk_paths: dict[str, str] = field(default_factory=dict)
    #: `ui` drives the app's list selection; `none` assumes it is already made and proves it per batch.
    select: str = "ui"
    #: A probe, not the card's matrix: its recompute is reported as diagnostic, never as acceptance.
    diagnostic: bool = False
    #: What the campaign can say about its *inputs*: per (build, rule_set) the list ids and their
    #: enabled state, the list-body SHA-256s, the user-rule and allowlist digests, and the loaded
    #: artifact hashes. Recorded by whatever collected them; this tool never invents one. A missing
    #: field is reported as missing and blocks the formal comparison it would have supported.
    inputs: dict[str, dict[str, object]] = field(default_factory=dict)

    def cells(self) -> list[tuple[str, str]]:
        """Every (build, rule set) cell, grouped by rule set so a rule-set switch happens once."""
        return [(build, rule_set) for rule_set in self.rule_sets for build in self.builds]

    def order(self) -> list[tuple[str, str, int]]:
        """The batch order: the two builds alternate inside one rule-set block.

        Two properties, both about not attributing drift to a version:

        * **the builds alternate batch for batch** (`A B A B A B`), not one build's batches followed
          by the other's. The phone warms up, the system's memory pressure moves, and background work
          comes due; a build measured entirely inside one of those windows would carry the window as
          if it were the build. Alternating spreads each build's batches across the whole window;
        * **the rule set switches once per block**, not between every batch. Toggling lists makes the
          app recompile, and a recompile between batches would put the 200 MiB compile transient in
          one cell's window and not the other's. Cells are only ever compared to the same rule set,
          so blocking by rule set costs nothing and removes that confound.

        A campaign file records the order it actually ran, so a reader can check both properties
        against the file rather than against this docstring.
        """
        ordered: list[tuple[str, str, int]] = []
        for rule_set in self.rule_sets:
            for index in range(self.batches):
                for build in self.builds:
                    ordered.append((build, rule_set, index + 1))
        return ordered


def load_plan(path: Path) -> Plan:
    """Read and validate a plan. Every rejection names the field, because a plan is hand-written."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PlanError(f"{path}: cannot read the plan: {error}") from None
    if not isinstance(raw, dict):
        raise PlanError(f"{path}: the plan must be a JSON object")

    builds_raw = raw.get("builds")
    if not isinstance(builds_raw, dict) or not builds_raw:
        raise PlanError("the plan must declare at least one build under \"builds\"")
    builds: dict[str, Build] = {}
    for name, entry in builds_raw.items():
        if not isinstance(entry, dict):
            raise PlanError(f"build {name!r} must be an object")
        sha = str(entry.get("apk_sha256", "")).lower()
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise PlanError(f"build {name!r}: apk_sha256 is not a SHA-256 hex digest")
        identities = entry.get("identities", {})
        if not isinstance(identities, dict):
            raise PlanError(f"build {name!r}: identities must be an object")
        legacy = bool(entry.get("legacy", False))
        identity_source = str(entry.get("identity_source", "declared"))
        if identity_source not in ("declared", "device"):
            raise PlanError(f"build {name!r}: identity_source must be 'declared' or 'device', "
                            f"got {identity_source!r}")
        for rule_set, token in identities.items():
            # A legacy build's token is not a content identity: it is `<key>=<value>` pairs of the
            # numbers that build *does* print (engine bytes and rule counts). Validated as such
            # below, and never passed to `pss_idle.sh`.
            if legacy:
                continue
            validate_identity(f"build {name!r} rule set {rule_set!r}", str(token))
        if legacy:
            for rule_set, token in identities.items():
                validate_legacy_identity(f"build {name!r} rule set {rule_set!r}", str(token))
        apk_path = str(entry.get("apk_path", ""))
        if not apk_path:
            raise PlanError(f"build {name!r} declares no apk_path; the runner installs the declared "
                            f"build before its batches")
        builds[name] = Build(name=name, apk_sha256=sha, apk_path=apk_path, legacy=legacy,
                             identity_source=identity_source,
                             identities={k: str(v) for k, v in identities.items()})
    if len({b.apk_sha256 for b in builds.values()}) != len(builds):
        raise PlanError("two builds share one apk_sha256; the campaign would compare a build to itself")

    # `select` names how the rule set reaches the phone for each block: `ui` drives the app's own
    # filters screen and re-verifies through the identity line (the only way that works for a build
    # that was never measured before), `none` assumes the phone is already in that state and lets the
    # per-batch identity check prove it. `none` is right when the selection was made once, by hand,
    # and verified; it is not a way to skip the check, which still runs on every batch.
    select = str(raw.get("select", "ui"))
    if select not in ("ui", "none"):
        raise PlanError(f"select must be 'ui' or 'none', got {select!r}")

    rule_sets_raw = raw.get("rule_sets") or {}
    if not rule_sets_raw:
        raise PlanError("the plan must declare the rule sets to measure under \"rule_sets\"")
    rule_sets: dict[str, tuple[str, ...]] = {}
    for name, lists in rule_sets_raw.items():
        if not isinstance(lists, list) or not lists:
            raise PlanError(f"rule set {name!r} must be a non-empty list of list ids")
        rule_sets[name] = tuple(str(item) for item in lists)

    for build in builds.values():
        for rule_set in rule_sets:
            if build.identity_source == "device":
                continue
            build.identity_for(rule_set)

    batches = raw.get("batches")
    samples = raw.get("samples")
    interval = raw.get("interval")
    # A **formal** plan needs >= 3 batches, because one batch per cell cannot separate a version
    # effect from drift; that is also enforced by `check_formal_shape` below, together with the rest
    # of the card's matrix. A plan that declares itself diagnostic may be shorter — that is what
    # makes it a probe — but its recompute is then never acceptance evidence.
    diagnostic = bool(raw.get("diagnostic", False))
    batch_minimum = 1 if diagnostic else 3
    for field_name, value, minimum in (("batches", batches, batch_minimum),
                                       ("samples", samples, 1), ("interval", interval, 1)):
        if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
            raise PlanError(f"{field_name} must be an integer >= {minimum}, got {value!r}"
                            + ("" if diagnostic else
                               " (a diagnostic plan may be shorter; add \"diagnostic\": true)"))
    if not diagnostic and batches < 3:
        raise PlanError("fewer than 3 batches per cell cannot separate a version effect from drift")

    artifact_dirs = raw.get("artifact_dirs") or {}
    apk_paths = raw.get("apk_paths") or {}
    plan = Plan(builds=builds, rule_sets=rule_sets, batches=batches, samples=samples,
                interval=interval, artifact_dirs=artifact_dirs, apk_paths=apk_paths,
                select=select, diagnostic=diagnostic,
                inputs={str(k): dict(v) for k, v in (raw.get("inputs") or {}).items()
                        if isinstance(v, dict)})
    check_formal_shape(plan, str(path))
    return plan


#: The formal matrix the task card fixes: two builds, the fixed five and the default nine, at least
#: three batches of six samples at 60 s. A plan may be shorter only by asking for diagnostic mode,
#: so a probe can never be summarised as acceptance evidence.
FORMAL_BATCHES = 3
FORMAL_SAMPLES = 6
FORMAL_INTERVAL = 60


def check_formal_shape(plan: "Plan", where: str) -> None:
    """Require a *formal* plan to be the card's matrix; allow a short probe only when declared.

    The first delivery ran one build on one rule set and called it the campaign. Shortening the
    matrix is legitimate while building the tool, so `diagnostic: true` is how a plan says so — and
    a diagnostic plan's recompute is reported as diagnostic and never as acceptance evidence. What is
    not legitimate is a plan that looks formal and is a subset of it.
    """
    if getattr(plan, "diagnostic", False):
        return
    problems: list[str] = []
    if len(plan.builds) != 2:
        problems.append(f"only {len(plan.builds)} build(s); the card requires the candidate and "
                        f"v0.1.2 to be compared")
    missing = [name for name in ("fixed-five", "default-nine") if name not in plan.rule_sets]
    if missing:
        problems.append(f"rule set(s) {', '.join(missing)} missing; the card requires both")
    for name, lists in plan.rule_sets.items():
        expected = RULE_SETS.get(name)
        if expected is None:
            problems.append(f"rule set {name!r} is not one of the card's sets "
                            f"({', '.join(sorted(RULE_SETS))})")
        elif tuple(lists) != tuple(expected):
            problems.append(f"rule set {name!r} is {list(lists)} but the card fixes it as "
                            f"{list(expected)}")
    if plan.batches < FORMAL_BATCHES:
        problems.append(f"{plan.batches} batches; the card requires at least {FORMAL_BATCHES}")
    if plan.samples != FORMAL_SAMPLES:
        problems.append(f"{plan.samples} samples per batch; the card fixes {FORMAL_SAMPLES}")
    if plan.interval != FORMAL_INTERVAL:
        problems.append(f"{plan.interval} s sample interval; the card fixes {FORMAL_INTERVAL}")
    if problems:
        raise PlanError(
            f"{where}: this plan is not the formal matrix the card fixes, and it does not declare "
            f"itself diagnostic:\n  - " + "\n  - ".join(problems) +
            "\nAdd \"diagnostic\": true to run it as a probe (its recompute will be reported as "
            "diagnostic, never as acceptance evidence), or complete the matrix.")


def plan_from_record(record: dict, *, where: str) -> "Plan":
    """[`load_plan`]'s validation, applied to the plan a campaign file carries.

    A campaign is re-derived with the same strictness its plan had to pass to be run at all.
    Re-implementing "read the plan section" loosely is how the first revision re-derived a campaign
    from a two-field plan nobody would have been allowed to run.
    """
    materialised = dict(record)
    materialised.setdefault("apk_path", "")  # unused by validation; builds carry their own
    return _plan_from_mapping(materialised, where)


def _plan_from_mapping(raw: dict, where: str) -> "Plan":
    """The body of [`load_plan`], over an already-parsed mapping."""
    import tempfile
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    try:
        json.dump(raw, handle)
        handle.close()
        return load_plan(Path(handle.name))
    finally:
        Path(handle.name).unlink(missing_ok=True)


#: What a legacy (pre-`rules_identity`) build can declare instead of a content hash: the engine
#: payload's byte count and the four rule counts its own load line reports. A *necessary* condition
#: only — two rule sets of one length and one rule count share these numbers — which is why a legacy
#: cell is labelled as such rather than being compared as an equal.
LEGACY_IDENTITY_KEYS = ("engine_bytes", "block_rules", "network_rules")


def validate_legacy_identity(where: str, token: str) -> None:
    """Require `engine_bytes=N block_rules=N network_rules=N`, all whole and positive."""
    seen: dict[str, str] = {}
    for part in token.split():
        if "=" not in part:
            raise PlanError(f"{where}: {part!r} is not <key>=<value>")
        key, value = part.split("=", 1)
        if key not in LEGACY_IDENTITY_KEYS:
            raise PlanError(f"{where}: unknown legacy key {key!r} "
                            f"(expected {', '.join(LEGACY_IDENTITY_KEYS)})")
        if not value.isdigit():
            raise PlanError(f"{where}: {key}={value!r} is not a whole number")
        seen[key] = value
    missing = [key for key in LEGACY_IDENTITY_KEYS if key not in seen]
    if missing:
        raise PlanError(f"{where}: missing legacy key(s) {', '.join(missing)}")


def validate_identity(where: str, token: str) -> None:
    """Require `dns=… engine=… extras=…` with a well-formed token per component."""
    seen = {}
    for part in token.split():
        if "=" not in part:
            raise PlanError(f"{where}: {part!r} is not <component>=<value>")
        name, value = part.split("=", 1)
        if name not in ("dns", "engine", "extras"):
            raise PlanError(f"{where}: unknown component {name!r}")
        if not IDENTITY_TOKEN.match(value):
            raise PlanError(f"{where}: {name}={value!r} is not '-' or sha256:<hex>:<bytes>")
        seen[name] = value
    missing = [name for name in ("dns", "engine", "extras") if name not in seen]
    if missing:
        raise PlanError(f"{where}: missing component(s) {', '.join(missing)}")
    if all(value == "-" for value in seen.values()):
        raise PlanError(f"{where}: every component is '-' — that declares no rule content")


# ---------------------------------------------------------------------------------------------
# Reading what `pss_idle.sh` produced
# ---------------------------------------------------------------------------------------------

@dataclass
class BatchResult:
    """One cell's one batch, as read back from `pss_idle.sh`'s own result file.

    Every field here is something the offline validator must be able to check, which is why the
    generation/handle and the before/after APK hashes are carried: the first revision of this record
    collected only the pid, so a batch whose rule generation or handle changed mid-batch — two
    different rule sets behind one rule identity, or two different processes behind one pid — read as
    valid evidence. The reviewer's probe demonstrated exactly that with five of six samples and a
    changed generation/handle, and it exited 0 with `ok=true`.
    """

    build: str
    rule_set: str
    index: int
    directory: Path
    median_kb: float | None
    median_mib: float | None
    samples_kb: list[int]
    identity: str | None
    apk_sha256: str | None
    failure: str | None = None
    #: The samples as printed: (index, pid, generation, handle, total_kb). Kept whole so continuity,
    #: identity stability and the raw-meminfo cross-check can each be asked separately.
    rows: list[tuple[int, int, int, int, int]] = field(default_factory=list)
    #: The APK the batch started on and the one it ended on. Both must exist and agree with the cell.
    apk_before: str | None = None
    apk_after: str | None = None
    #: How many distinct (pid, generation, handle) triples the samples named. One batch is one state.
    states: int = 0
    #: Whether the raw `dumpsys meminfo` answers backing these samples were present and agreed.
    raw_verified: bool = False
    #: The batch's own start stamp, read from its result header (`at=...Z`). This is the *only* place
    #: a batch's real time comes from: the plan's order is what was intended, and a campaign file's
    #: `order` is a claim. The second review caught the delivered campaign claiming an alternating
    #: order while its six v0.1.2 batches actually ran 17:59–18:30Z, after all six candidate batches
    #: had finished at 17:42Z — and `finished_at` (17:55Z) predated the re-run it supposedly covered.
    started_at: str | None = None
    #: The per-sample elapsed seconds as printed, so the 60 s cadence can be checked rather than
    #: assumed. A file whose samples are 1..6 seconds apart is not a 6 × 60 s batch.
    elapsed_s: list[int] = field(default_factory=list)
    #: The cadence the batch itself declares (`interval=60s`), when the header carries it.
    declared_interval_s: int | None = None

    @property
    def ok(self) -> bool:
        return self.failure is None and self.median_kb is not None


def parse_batch(directory: Path, build: str, rule_set: str, index: int, *,
                expected_samples: int = 0) -> BatchResult:
    """Read one batch's result file and its raw directory into a validated record.

    The rule this implements is the task card's: *a batch is evidence only when every part of it can
    be checked*. So it refuses — it does not warn — on each of the following, every one of which the
    first delivery accepted:

    * a sample count other than the plan's (five of six samples is not a batch of six);
    * sample indexes that are not 1..N in order (a gap or a repeat is a re-assembled file);
    * more than one (pid, generation, handle) triple. A change of generation or handle means the rule
      set in force changed, which is precisely what one batch may not do; a change of pid means a
      restart. The first delivery only compared the pid, so a generation or handle swap read as
      valid;
    * a missing, unreadable, or non-`sha256:` APK hash on **either** side of the batch, or a
      before/after pair that differs;
    * a `## median` that is not the median of the samples in the same file, or a MiB that is not its
      kB / 1024;
    * a raw `dumpsys meminfo` answer that is absent, or whose `TOTAL PSS` does not equal the sample
      row it backs. Without this a result file could claim any number at all.

    A batch that fails any of these carries a `failure` and no `median_kb`, so no later step can
    average it, and the cell it belongs to is voided.
    """
    result_file = directory / "result.txt"
    if not result_file.is_file():
        return BatchResult(build, rule_set, index, directory, None, None, [], None, None,
                           failure=f"{result_file}: no result file for this batch")

    text = result_file.read_text(encoding="utf-8", errors="replace")
    rows: list[tuple[int, int, int, int, int]] = []
    samples: list[int] = []
    printed_indexes: list[int] = []
    elapsed: list[int] = []
    median_kb = median_mib = None
    identity = None
    failure = None
    started_at = None
    declared_interval = None

    for line in text.splitlines():
        # The header's own stamps. `at=` is when the batch began; `interval=` is the cadence the batch
        # declares, both written by `pss_idle.sh` before it samples anything.
        # Every header comment is inspected: `pss_idle.sh` writes the start stamp on its first line
        # and the declared cadence on the next (`# serial=… samples=6 interval=60s owner=…`), so
        # looking only at the first line finds no cadence at all.
        if line.startswith("#"):
            stamp = RESULT_STAMP.search(line)
            if stamp and started_at is None:
                started_at = stamp.group("at")
            cadence = RESULT_INTERVAL.search(line)
            if cadence and declared_interval is None:
                declared_interval = int(cadence.group("seconds"))
            if line.startswith("# idle PSS"):
                continue
        row = SAMPLE_ROW.match(line)
        if row:
            printed_indexes.append(int(row.group("index")))
            samples.append(int(row.group("total")))
            elapsed.append(int(row.group("elapsed")))
            rows.append((int(row.group("index")), int(row.group("pid")),
                         int(row.group("gen")), int(row.group("handle")),
                         int(row.group("total"))))
            continue
        legacy_row = LEGACY_SAMPLE_ROW.match(line)
        if legacy_row:
            # A legacy build prints no generation/handle, so there is nothing to compare there. The
            # row is still checked for pid, count, index continuity and against its raw meminfo; the
            # generation/handle columns are recorded as 0, which `states` then reads as "one state".
            printed_indexes.append(int(legacy_row.group("index")))
            samples.append(int(legacy_row.group("total")))
            elapsed.append(int(legacy_row.group("elapsed")))
            rows.append((int(legacy_row.group("index")), int(legacy_row.group("pid")), 0, 0,
                         int(legacy_row.group("total"))))
            continue
        median = MEDIAN_LINE.match(line)
        if median:
            if median_kb is not None:
                return BatchResult(build, rule_set, index, directory, None, None, samples, None,
                                   None, failure="the result file carries two medians; exactly one "
                                                 "batch belongs in one result file")
            median_kb = float(median.group("kb"))
            median_mib = float(median.group("mib"))
            continue
        content = CONTENT_LINE.match(line)
        if content:
            identity = content.group("content").strip()
            continue
        if line.startswith("FAIL:"):
            failure = line[len("FAIL:"):].strip()

    apk_before = read_apk_sha(directory, "before")
    apk_after = read_apk_sha(directory, "after")
    apk_sha = apk_before
    states = len({(row[1], row[2], row[3]) for row in rows})

    def refuse(reason: str) -> BatchResult:
        return BatchResult(build, rule_set, index, directory, None, None, samples, identity,
                           apk_sha, failure=reason, rows=rows, apk_before=apk_before,
                           apk_after=apk_after, states=states, started_at=started_at,
                           elapsed_s=elapsed, declared_interval_s=declared_interval)

    if failure is not None:
        return refuse(f"pss_idle.sh refused this batch: {failure}")
    if not samples:
        return refuse("the result file carries no sample row")
    if expected_samples and len(samples) != expected_samples:
        return refuse(f"{len(samples)} sample row(s) for a batch the plan declares as "
                      f"{expected_samples}; a short batch does not have the same weight as a full "
                      f"one and is not allowed to stand in for it")
    if printed_indexes != list(range(1, len(samples) + 1)):
        return refuse(f"sample indexes {printed_indexes} are not 1..{len(samples)} in order; the "
                      f"file is a re-assembly, not one batch")
    if states != 1:
        triples = sorted({(row[1], row[2], row[3]) for row in rows})
        detail = ", ".join(f"pid={pid} gen={gen} handle={handle}" for pid, gen, handle in triples)
        return refuse(f"the samples name {states} different (pid, generation, handle) states "
                      f"({detail}); one batch is one process running one rule generation, and a "
                      f"change means the samples describe different rule sets")
    if median_kb is None:
        return refuse("the result file carries samples but no median line")
    recomputed = statistics.median(samples)
    if abs(recomputed - median_kb) > 1e-9:
        return refuse(f"the printed median {format_kb(median_kb)} kB is not the median of these "
                      f"{len(samples)} samples ({format_kb(recomputed)} kB)")
    if abs(median_mib - median_kb / 1024.0) > 5e-10:
        return refuse(f"the printed {median_mib} MiB is not {format_kb(median_kb)} kB / 1024")
    if identity is None:
        return refuse("the result file declares no effective rule content")
    # Both APK hashes are required. A batch that recorded only one side cannot show that the phone
    # ran one build throughout it, which is the whole point of recording it at all.
    if apk_before is None or apk_after is None:
        missing = "before" if apk_before is None else "after"
        return refuse(f"the {missing}-batch APK SHA-256 is missing or unreadable; the batch cannot "
                      f"show which build it measured")
    if apk_before != apk_after:
        return refuse(f"the device's APK changed during the batch ({apk_before} -> {apk_after})")
    raw_problem = verify_raw_meminfo(directory, rows)
    if raw_problem is not None:
        return refuse(raw_problem)
    return BatchResult(build, rule_set, index, directory, median_kb, median_mib, samples, identity,
                       apk_sha, rows=rows, apk_before=apk_before, apk_after=apk_after,
                       states=states, raw_verified=True, started_at=started_at,
                       elapsed_s=elapsed, declared_interval_s=declared_interval)


#: The `TOTAL PSS:` line inside one raw `dumpsys meminfo` answer, and its pid header.
RAW_HEADER = re.compile(r"\*\* MEMINFO in pid (\d+) \[([^\]]+)\] \*\*")
RAW_TOTAL = re.compile(r"TOTAL PSS:\s+(\d+)")


def verify_raw_meminfo(directory: Path, rows: list[tuple[int, int, int, int, int]]) -> str | None:
    """Cross-check every sample against the raw device answer it claims to come from.

    `pss_idle.sh` writes each `dumpsys meminfo` answer to `pss-*.raw/meminfo-N.txt` and the row it
    parsed into the result file. The result file is the summary a reader quotes; the raw answer is
    the device's own words. A result row with no backing answer, or one whose `TOTAL PSS` disagrees
    with the row, is a number nobody can attribute — the stage-5 review rejected exactly this shape
    of "the summary says so" evidence.

    Returns the problem, or `None` when every row checks out.
    """
    # Two layouts have existed: `pss_<label>.raw/` (the candidate sampler) and `raw/` (the legacy
    # sampler). Both hold the same files, and which one is used is an implementation detail of the
    # batch tool — so the check looks for the *answers*, not for a particular directory name.
    raw_dirs = [path for path in [*sorted(directory.glob("*.raw")), directory / "raw"]
                if path.is_dir()]
    if not raw_dirs:
        return ("no raw device output for this batch (neither `*.raw/` nor `raw/`); a result file "
                "without the `dumpsys meminfo` answers behind it cannot be re-checked offline")
    raw = raw_dirs[0]
    for row_index, pid, _generation, _handle, total_kb in rows:
        path = raw / f"meminfo-{row_index}.txt"
        if not path.is_file():
            return (f"sample {row_index} has no raw `dumpsys meminfo` answer ({path.name} is "
                    f"missing); the number cannot be attributed to the device")
        text = path.read_text(encoding="utf-8", errors="replace")
        headers = RAW_HEADER.findall(text)
        if len(headers) != 1:
            return (f"the raw answer for sample {row_index} carries {len(headers)} MEMINFO headers; "
                    f"exactly one process is required")
        if int(headers[0][0]) != pid:
            return (f"the raw answer for sample {row_index} is for pid {headers[0][0]}, but the "
                    f"result row says pid {pid}")
        totals = RAW_TOTAL.findall(text)
        if len(totals) != 1:
            return (f"the raw answer for sample {row_index} carries {len(totals)} TOTAL PSS values; "
                    f"exactly one is required")
        if int(totals[0]) != total_kb:
            return (f"sample {row_index} records {total_kb} kB but the raw `dumpsys meminfo` answer "
                    f"says {totals[0]} kB")
    return None


def format_kb(value: float) -> str:
    """A kB count as `pss_idle.sh` prints it: whole when it is whole, one decimal for a half-step."""
    return f"{int(value)}" if float(value).is_integer() else f"{value:.1f}"


def read_apk_sha(directory: Path, side: str) -> str | None:
    """The on-device APK hash a batch recorded for `before` or `after`, or `None` if unusable.

    The side is named rather than "whichever file sorts first": the first revision globbed
    `apk-sha256*.txt` and took the first, so a batch that had only a `before` hash looked exactly
    like one that had both, and a `before` that disagreed with the `after` was never compared.
    """
    if side not in ("before", "after"):
        raise ValueError(f"side must be before or after, got {side!r}")
    path = directory / f"apk-sha256-{side}.txt"
    if not path.is_file():
        return None
    match = APK_LINE.match(path.read_text(encoding="utf-8", errors="replace").strip())
    return match.group("sha") if match else None


# ---------------------------------------------------------------------------------------------
# The statistics
# ---------------------------------------------------------------------------------------------

@dataclass
class CellSummary:
    """One (build, rule set) cell: its batches, and what can and cannot be concluded from them."""

    build: str
    rule_set: str
    batches: list[BatchResult]

    @property
    def ok(self) -> bool:
        return bool(self.batches) and all(batch.ok for batch in self.batches)

    @property
    def medians_kb(self) -> list[float]:
        return [batch.median_kb for batch in self.batches if batch.median_kb is not None]

    @property
    def centre_kb(self) -> float | None:
        """The batch median of the batch medians — the cell's figure.

        Not the median of every sample: a cell whose batches each contributed a different number of
        samples would then weight them unevenly, and the point of batches is that each is one
        independent launch whose centre is its own median.
        """
        medians = self.medians_kb
        return statistics.median(medians) if medians else None

    @property
    def spread_kb(self) -> float | None:
        medians = self.medians_kb
        return (max(medians) - min(medians)) if len(medians) >= 2 else None


def compare(left: CellSummary, right: CellSummary) -> dict[str, object]:
    """Describe the difference between two cells — and nothing more.

    The previous revision turned this into a **direction verdict**: "established" when the difference
    exceeded the between-batch spread, "not established" otherwise. The second review rejected that
    inference, and it is gone. Two reasons, both about what the numbers can carry:

    * the spread of three batches is not an error bar. It is a sample of the machine's drift, and
      comparing one cell's spread against a difference says nothing about whether the difference is
      real — a small spread on both sides is not evidence of a small true difference;
    * deciding a direction is a claim about the *product*, and this tool's job is to report what was
      measured. A reviewer reads the two centres, the spreads and the sample counts and decides.

    So the comparison is descriptive: the two centres, their difference, and each cell's
    between-batch range, all stated as numbers. Whether a difference means anything is not this
    function's conclusion to make.
    """
    if left.centre_kb is None or right.centre_kb is None:
        return {"comparable": False, "reason": "a cell has no batches",
                "left_mib": None, "right_mib": None, "difference_mib": None,
                "left_range_mib": None, "right_range_mib": None}
    left_mib = left.centre_kb / 1024.0
    right_mib = right.centre_kb / 1024.0
    return {
        "comparable": True,
        "left_mib": left_mib,
        "right_mib": right_mib,
        "difference_mib": left_mib - right_mib,
        "left_range_mib": (left.spread_kb / 1024.0) if left.spread_kb is not None else None,
        "right_range_mib": (right.spread_kb / 1024.0) if right.spread_kb is not None else None,
        "left_batches": len(left.batches),
        "right_batches": len(right.batches),
    }


# ---------------------------------------------------------------------------------------------
# Running a campaign
# ---------------------------------------------------------------------------------------------

LOCK_HELPER = HERE / "hold-device-lock.sh"


class DeviceLock:
    """The canonical device lock, held across the preparation phase of one batch.

    The rule this enforces is the card's: *nothing may change on the phone before the lock is held*.
    Installing an APK, toggling a list and force-stopping the app are all writes, and the first
    delivery did them before any lock existed — so it could take a phone another task owned. This
    wrapper takes the lock through the same `device-lock.sh` library every other tool uses, so
    "held", "expired" and "mine" mean one thing everywhere.

    It is released before each sampler starts, because `pss_idle.sh` takes the lock itself and would
    refuse a phone whose lock is already held by this process. The sampler re-verifies the rule
    content inside its own batch, so the hand-over gap cannot turn into a number attributed to
    content nobody selected.
    """

    def __init__(self, owner: str, serial: str) -> None:
        self.owner = owner
        self.serial = serial
        self.token = f"{os.getpid()}-{int(time.time())}"
        self.held = False

    def _run(self, action: str) -> tuple[int, str]:
        result = subprocess.run(
            ["bash", str(LOCK_HELPER), self.owner, self.token, action],
            cwd=REPO, capture_output=True, text=True,
            env={**os.environ, "SERIAL": self.serial})
        return result.returncode, (result.stdout + result.stderr).strip()

    def take(self) -> None:
        code, output = self._run("take")
        if code != 0 or "TAKEN" not in output:
            raise CampaignError(
                f"the device lock is not available: {output or '<no output>'}. Nothing was installed, "
                f"toggled or cleared: this run refuses to touch a phone it does not own")
        self.held = True

    def release(self) -> None:
        if not self.held:
            return
        code, output = self._run("release")
        self.held = False
        if code != 0:
            raise CampaignError(f"the device lock could not be released: {output}")

    def __enter__(self) -> "DeviceLock":
        self.take()
        return self

    def __exit__(self, *_exc) -> None:
        try:
            self.release()
        except CampaignError:
            # A release failure must not swallow the reason the block was exiting; the caller records
            # the batch's outcome from its own evidence.
            pass


def run_campaign(plan: Plan, out: Path, issue: str, serial, package: str) -> int:
    """The CLI entry for a device campaign: refuse, unconditionally, until the protocol is accepted.

    `serial` is a **callable** returning the serial (usually `device_serial.serial_from`-flavoured),
    not the serial itself, and it is only called once the gate below has been passed. Resolving it
    earlier would make the refusal depend on a phone being attached, which is the opposite of what a
    refusal is for.

    Every statement below the refusal in this function used to be the runner itself. It has been
    moved to [`device_campaign_draft`], which is **not reachable from any CLI path**, so the code
    that would touch a phone cannot run by accident while the transaction protocol is unfinished.
    The draft is kept rather than deleted because the protocol work starts from it, and because its
    existing tests (lock before write, stdout median kept) are what will have to keep passing when
    it is finished. Deleting it would delete that coverage along with it.
    """
    # ---- the transaction gate ----------------------------------------------------------------
    # `run` is disabled until the preparation/sampling/recovery transaction is accepted. Three
    # concrete gaps make a device run unsafe today, and each is a way to measure a phone this run
    # does not own, or to leave one changed:
    #
    #   1. the sampler (`pss_idle.sh`, driven by `run_legacy_batch`) was not given the serial and
    #      package this run resolved, so "which phone" could differ between preparation and sampling;
    #   2. preparation takes the canonical lock and then hands it back before the sampler takes it
    #      again — a gap in which another task can take the phone;
    #   3. there is no recovery transaction: an abort mid-campaign has no guarantee that the list
    #      selection and the user's rules are restored.
    #
    # A refusal is the honest behaviour: silently running "best effort" is what would change somebody
    # else's phone. The offline paths — `plan-check`, `recompute`, `assemble_evidence.py` — are
    # unaffected and are what this round delivers.
    print(
        "run 入口已禁用：设备事务协议尚未验收。\n"
        "\n"
        "未解决的三项（后续只读观测/事务接口方案另附，尚未实现）：\n"
        "  1. 采样器的 serial/package 未由本进程传入，准备与采样可能不是同一台设备；\n"
        "  2. 准备阶段释放 canonical 锁到采样器重新取锁之间存在空窗；\n"
        "  3. 没有恢复事务：中途失败无法保证列表选择与用户规则被还原。\n"
        "\n"
        "在协议验收前，本命令不会执行任何 adb、安装、切列表或清日志操作。\n"
        "可用的离线入口：\n"
        "  python3 scripts/effectiveness/memory_profile.py plan-check --plan <plan.json>\n"
        "  python3 scripts/effectiveness/memory_profile.py recompute <campaign-dir>\n"
        "  python3 scripts/effectiveness/assemble_evidence.py --campaign <dir> --out <tar.gz> "
        "[--state <cleanup.json>]",
        file=sys.stderr)
    return 2


def device_campaign_draft(plan: Plan, out: Path, issue: str, serial: str, package: str) -> int:
    """The device runner as it stood when it was gated off. **Not reachable from the CLI.**

    What it still does correctly: install the declared build when the phone runs another one, take
    the canonical lock before the first write, hand it back before each sampler run, record an
    attempt per batch.

    What it does not yet do — the three gaps the gate exists for:

    1. the sampler is not handed this call's `serial`/`package`, so "which phone" can differ
       between preparation and sampling;
    2. the lock is released between preparation and the sampler's own `take`, leaving a window;
    3. there is no recovery transaction, so an abort can leave the list selection and the user's
       rules as the campaign left them.

    Callers in the test suite reach this directly, by design: the ordering properties it does have
    stay covered while the entry point refuses.
    """
    out.mkdir(parents=True, exist_ok=True)
    campaigns = out / "campaign.json"
    record: dict[str, object] = {
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "issue": issue,
        "serial": serial,
        "package": package,
        "threshold_mib": THRESHOLD_MIB,
        "plan": {
            "builds": {name: {"apk_sha256": build.apk_sha256, "apk_path": build.apk_path,
                              "legacy": build.legacy,
                              "identity_source": build.identity_source,
                              "identities": build.identities}
                       for name, build in plan.builds.items()},
            "rule_sets": {name: list(lists) for name, lists in plan.rule_sets.items()},
            "batches": plan.batches,
            "samples": plan.samples,
            "interval": plan.interval,
            # Carried so a recompute validates this campaign by the same rules its plan had to pass:
            # without it a probe re-derives as a campaign that merely looks short.
            "diagnostic": plan.diagnostic,
            "select": plan.select,
        },
        # The order actually executed. `Plan.order()` is deterministic, but recording it is what lets
        # a reader — and `check_recorded_order` — see that the alternating order was followed rather
        # than assume it.
        "order": [list(item) for item in plan.order()],
        "batches": [],
    }
    campaigns.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")

    failures = 0
    previous_rule_set: str | None = None
    for build_name, rule_set, index in plan.order():
        build = plan.builds[build_name]
        batch_dir = out / f"{rule_set}--{build_name}--b{index}"
        batch_dir.mkdir(parents=True, exist_ok=True)
        # `None` for a device-pinned cell that has not been pinned yet: the first batch's cold start
        # produces the identity and every later batch of the cell is held to it.
        identity = build.identities.get(rule_set)

        # ---- preparation, under the canonical device lock ------------------------------------
        # Everything in this block changes the phone: installing the APK, toggling the rule set,
        # force-stopping and cold-starting for the identity check. In the first delivery all of it
        # ran before any lock existed, so a run could install an APK or toggle lists on a phone
        # another task owned. The lock is taken here, held across every write, and handed back
        # before the sampler starts — `pss_idle.sh` takes the lock itself and would refuse a phone
        # whose lock this process still holds.
        lock = DeviceLock(issue, serial)
        try:
            lock.take()
        except CampaignError as error:
            # No lock, no write: the batch is void and the phone is untouched.
            message = str(error)
            (batch_dir / "result.txt").write_text(f"FAIL: {message}\n", encoding="utf-8")
            failures += 1
            record["batches"].append({"cell": [build_name, rule_set], "index": index,
                                      "outcome": "void", "reason": message})
            campaigns.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
            continue
        try:
            # Install the declared build when the phone is running a different one. Installing rather
            # than demanding it was installed by hand removes the one step where the wrong APK
            # silently gets measured; the hash is read back from the device either way.
            installed = device_apk_sha(serial, package)
            if installed != build.apk_sha256:
                install = subprocess.run(["adb", "-s", serial, "install", "-r", build.apk_path],
                                         capture_output=True, text=True)
                (batch_dir / "install.txt").write_text(install.stdout + install.stderr,
                                                       encoding="utf-8")
                installed = device_apk_sha(serial, package)
            (batch_dir / "apk-sha256-before.txt").write_text(f"{installed}  {package}\n",
                                                             encoding="utf-8")
            if installed != build.apk_sha256:
                # No identity, no measurement: the phone is not running the build this cell is
                # about, and a batch measured anyway would be attributed to the wrong APK.
                message = (f"the device runs {installed} but cell {build_name!r} is "
                           f"{build.apk_sha256}; install the declared APK before this batch")
                raise CampaignError(message)

            # Select the cell's rule set on the device and prove the selection took effect. Done once
            # per rule-set block: the plan's order groups by rule set, so this costs one recompile
            # per block rather than one per batch, and a compile transient cannot sit inside one
            # build's window and not the other's.
            if previous_rule_set != rule_set:
                if plan.select == "ui":
                    select_rule_set(serial, package, rule_set, plan.rule_sets[rule_set], batch_dir)
                previous_rule_set = rule_set
            if not build.legacy:
                observed = verify_selection_identity(serial, package, identity, batch_dir)
                if build.identity_source == "device":
                    # Pin it for the rest of the cell, and record the pin so the report can say the
                    # cell's identity came from the device rather than from a host compile.
                    build.identities[rule_set] = observed
                    identity = observed
                    record.setdefault("identity_pins", {})[f"{build_name}/{rule_set}"] = observed
                    campaigns.write_text(json.dumps(record, indent=2, ensure_ascii=False),
                                         encoding="utf-8")
        except CampaignError as error:
            (batch_dir / "result.txt").write_text(f"FAIL: {error}\n", encoding="utf-8")
            record["batches"].append({"cell": [build_name, rule_set], "index": index,
                                      "outcome": "void", "reason": str(error)})
            campaigns.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
            failures += 1
            continue
        finally:
            # The sampler takes the lock itself, so it is handed back before the batch starts.
            lock.release()

        if build.legacy:
            # A build that predates `rules identity:` cannot be measured by `pss_idle.sh`, which
            # correctly refuses to sample a launch that never printed one.
            try:
                observed = run_legacy_batch(batch_dir, rule_set, build_name, index,
                                            identity or "",
                                            samples=plan.samples, interval=plan.interval,
                                            serial=serial, package=package, lock_owner=issue)
                if build.identity_source == "device" and observed:
                    build.identities[rule_set] = observed
                    identity = observed
                    record.setdefault("identity_pins", {})[f"{build_name}/{rule_set}"] = observed
                    campaigns.write_text(json.dumps(record, indent=2, ensure_ascii=False),
                                         encoding="utf-8")
            except CampaignError as error:
                (batch_dir / "result.txt").write_text(f"FAIL: {error}\n", encoding="utf-8")
        else:
            command = [
                "bash", str(PSS_IDLE),
                f"{rule_set}-{build_name}-b{index}",
                "--expect-identity", identity,
                "--samples", str(plan.samples),
                "--interval", str(plan.interval),
                "--out", str(batch_dir),
                "--issue", issue,
            ]
            # `pss_idle.sh` keeps a background renewer that `sleep`s for up to 30 minutes, and that
            # child inherits the script's stdout. `capture_output=True` reads until the pipe closes,
            # which the surviving child holds open — so the caller waited for the renewer's sleep,
            # not for the batch, and a 6-sample batch that had finished sat "running" for half an
            # hour. Handing it files instead of pipes removes the reader that can outlive the batch.
            stdout_path = batch_dir / "pss_idle.stdout.txt"
            stderr_path = batch_dir / "pss_idle.stderr.txt"
            with stdout_path.open("w", encoding="utf-8") as out_file, \
                    stderr_path.open("w", encoding="utf-8") as err_file:
                returncode = subprocess.run(command, cwd=REPO, stdout=out_file, stderr=err_file,
                                            stdin=subprocess.DEVNULL).returncode
            produced = batch_dir / f"pss-{rule_set}-{build_name}-b{index}.txt"
            if produced.is_file():
                # The file gets the running log (`tee -a "$FILE"`) and **not** the summary; the
                # `## median` line is printed by a separate `python3 - "$FILE"` invocation whose
                # output only reaches stdout. Keeping only the file therefore loses the one number the
                # batch exists for — an earlier revision did that, and `recompute` voided every batch
                # as "samples but no median". Merely appending the whole of stdout is wrong too,
                # because `tee` already put most of it in the file: the rows then appear twice and the
                # file is two copies of one batch. So exactly the summary lines are taken across.
                result = produced.read_text(encoding="utf-8", errors="replace")
                summary = [line for line in
                           stdout_path.read_text(encoding="utf-8", errors="replace").splitlines()
                           if line.startswith("## median ") or line.startswith("## diagnostic ")]
                if not summary:
                    result += "FAIL: pss_idle.sh wrote its result file but printed no median on stdout\n"
                (batch_dir / "result.txt").write_text(
                    result + "".join(line + "\n" for line in summary), encoding="utf-8")
                produced.unlink()
            else:
                (batch_dir / "result.txt").write_text(
                    f"FAIL: pss_idle.sh exited {returncode} and wrote no result file\n"
                    f"{stderr_path.read_text(encoding='utf-8', errors='replace')[-4000:]}\n",
                    encoding="utf-8")
        after = device_apk_sha(serial, package)
        (batch_dir / "apk-sha256-after.txt").write_text(f"{after}  {package}\n", encoding="utf-8")
        batch = parse_batch(batch_dir, build_name, rule_set, index)
        if after != build.apk_sha256:
            batch.failure = (f"the device's APK changed during the batch ({build.apk_sha256} -> {after})")
        entry = {"cell": [build_name, rule_set], "index": index,
                 "outcome": "ok" if batch.ok else "void",
                 "median_kb": batch.median_kb, "median_mib": batch.median_mib,
                 "samples_kb": batch.samples_kb, "identity": batch.identity,
                 "apk_sha256": batch.apk_sha256, "apk_sha256_after": after,
                 "failure": batch.failure}
        record["batches"].append(entry)
        campaigns.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
        if not batch.ok:
            failures += 1

    record["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    campaigns.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    return 1 if failures else 0


# ---------------------------------------------------------------------------------------------
# The legacy sampler: v0.1.2, which predates the `rules identity:` observation
# ---------------------------------------------------------------------------------------------

#: What a v0.1.2 launch prints instead of an identity line. It carries the *byte count* of the engine
#: payload it deserialized and the rule counts it loaded — numbers, not content. `docs/I2_MEMORY_PROFILE.md`
#: §"身份判据" states exactly how far that goes and where it stops.
LEGACY_ENGINE_LINE = re.compile(
    r"engine loaded in (?P<ms>\d+) ms, (?P<bytes>\d+) B \((?P<redirects>\d+) redirect resources\)")
LEGACY_DNS_LINE = re.compile(r"compiled rules loaded in (?P<ms>\d+) ms")
LEGACY_COUNTS_LINE = re.compile(
    r"loaded compiled rules: (?P<block>\d+) block, (?P<exception>\d+) exception, "
    r"(?P<unsupported>\d+) unsupported, (?P<network>\d+) network-only")
#: `compiled N lists: …` — the app's own recompile, which v0.1.2 also runs on every launch. Its
#: presence **after** the load lines is what tells a batch whether a hot swap landed in its window.
LEGACY_COMPILE_LINE = re.compile(
    r"compiled (?P<lists>\d+) lists: (?P<dns>\d+) dns rules \((?P<block>\d+) block / "
    r"(?P<exception>\d+) exception\), (?P<network>\d+) network, (?P<unsupported>\d+) unsupported, "
    r"dns\.bin (?P<dns_bytes>\d+) B, engine\.bin (?P<engine_bytes>\d+) B, (?P<ms>\d+) ms")
LEGACY_THREADTIME = re.compile(
    r"^\d\d-\d\d\s+\d\d:\d\d:\d\d\.\d+\s+(\d+)\s+(\d+)\s+[VDIWEFA]\s+([^:]*):\s?(.*)$")
LEGACY_MEMINFO_HEADER = re.compile(r"\*\* MEMINFO in pid (\d+) \[([^\]]+)\] \*\*")
LEGACY_MEMINFO_TOTAL = re.compile(r"TOTAL PSS:\s+(\d+)")


def run_legacy_batch(
    batch_dir: Path,
    rule_set: str,
    build: str,
    index: int,
    identity: str,
    *,
    samples: int,
    interval: int,
    serial: str,
    package: str,
    lock_owner: str,
) -> str:
    """Sample a build that has no `rules identity:` event, using the strongest evidence it offers.

    v0.1.2 predates `core/src/rules_identity.rs`, so `pss_idle.sh` cannot measure it: that tool
    correctly refuses a launch that never printed an identity, and relaxing it would weaken the
    judgement for the build that *does* print one. Stage 6 worked around this with an ad-hoc script
    that recorded a *subset* of the protocol (`docs/EFFECTIVENESS.md` §16.2), and that subset is what
    this function replaces with the same protocol stated once.

    What this build can prove, and what it cannot:

    * **can** prove the process is this launch's (pid from `pidof` after a verified force-stop, and
      the same pid on every sample), that the tunnel came up, that every sample came from one
      `dumpsys meminfo` block for that pid, and that the app was still running the same APK;
    * **can** prove the *rule artifacts* the launch loaded, up to the build's own determinism: the
      log reports the engine payload's byte count and the four rule counts, and the compile is
      deterministic — a host compile of the same list bodies by the same core produces byte-identical
      artifacts (verified, `docs/I2_MEMORY_PROFILE.md` §"编译确定性"). The plan's `legacy_expected`
      records those numbers from a host compile, so the batch is refused when they disagree;
    * **cannot** prove the *content* directly. Two different rule sets of the same byte count and the
      same rule counts would pass this check — which is exactly the counter-example the stage-4 review
      produced against byte counts. So a legacy batch is labelled `legacy: true` in the campaign and
      every cell it contributes to is reported as such; no cell mixing a legacy and an identity build
      is compared without saying so.

    The protocol (lock, verified log boundary, force-stop, cold start, tunnel up, background, six
    samples with a state check before and after each) is the same as `pss_idle.sh`'s; only the
    readiness and identity judgement differ, because only that can.
    """
    batch_dir.mkdir(parents=True, exist_ok=True)
    result = batch_dir / "result.txt"
    # The same `pss-<label>.raw/` spelling the candidate sampler uses, so one batch layout serves
    # both and `verify_raw_meminfo` does not need to know which build produced the batch.
    raw = batch_dir / f"pss-{rule_set}-{build}-b{index}.raw"
    raw.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    lines.append(f"# idle PSS (legacy: no `rules identity:` event) — label={rule_set}-{build}-b{index} "
                 f"at={started}")
    lines.append(f"# serial={serial} package={package} samples={samples} interval={interval}s "
                 f"owner={lock_owner}")
    lines.append(f"# declared artifacts (from a host compile of these lists): {identity}")

    def say(message: str) -> None:
        lines.append(message)

    def fail(reason: str) -> None:
        say(f"FAIL: {reason}")
        result.write_text("\n".join(lines) + "\n", encoding="utf-8")
        raise CampaignError(reason)

    # One explicit token for take and release: `lock_release` only removes a lock whose stored token
    # matches, and a token generated separately in a second process would never match, leaving the
    # lock behind for the next task.
    lock_token = f"{os.getpid()}-{int(time.time())}"
    lock_env = {**os.environ, "SERIAL": serial, "LOCK_OWNER": lock_owner, "LOCK_TOKEN": lock_token}
    lock = subprocess.run(
        ["bash", "-c", "source scripts/effectiveness/device-lock.sh; lock_take"],
        cwd=REPO, capture_output=True, text=True, env=lock_env)
    if "device lock: taken" not in lock.stdout and "took over an expired lock" not in lock.stdout:
        fail(f"the device lock is not available: {lock.stdout.strip()} {lock.stderr.strip()}")
    lines.append(f"# device lock taken (token {lock_token})")

    def device(command: str, timeout: float = 60.0) -> subprocess.CompletedProcess:
        return subprocess.run(["adb", "-s", serial, "shell", command],
                              capture_output=True, text=True, timeout=timeout)

    def read_pid() -> str:
        return device(f"pidof {package}").stdout.replace("\r", "").strip().split(" ")[0]

    try:
        # 1. tunnel down. `DEBUG_TOGGLE_VPN` is a *toggle*, so a batch that assumed "off" would
        #    invert the state it is trying to reach (`docs/TESTING.md` §14.8f).
        device(f"am broadcast -a {package}.action.DEBUG_TOGGLE_VPN "
               f"-n {package}/.filters.DebugCommandReceiver")
        time.sleep(4)
        for _ in range(10):
            if "IS_VPN" not in device("dumpsys connectivity").stdout:
                break
            device(f"am broadcast -a {package}.action.DEBUG_TOGGLE_VPN "
                   f"-n {package}/.filters.DebugCommandReceiver")
            time.sleep(3)
        else:
            fail("the tunnel would not go down; the batch cannot start from a known state")
        say("# tunnel down")

        # 2. force-stop, and prove the process is gone. A resume would leave the previous launch's
        #    log lines and PSS in place of this batch's.
        stopped = device(f"am force-stop {package}")
        (raw / "force-stop.txt").write_text(stopped.stdout + stopped.stderr, encoding="utf-8")
        for _ in range(10):
            if not read_pid():
                break
            time.sleep(1)
        else:
            fail(f"am force-stop exited {stopped.returncode} but {package} still has a pid")
        say("# force-stop: pid is gone")

        # 3. verify the log boundary by reading the buffer back, not by trusting `logcat -c`.
        cleared = device("logcat -c")
        (raw / "logcat-clear.txt").write_text(cleared.stdout + cleared.stderr, encoding="utf-8")
        if cleared.returncode != 0:
            fail(f"logcat -c exited {cleared.returncode}: nothing after this could be attributed")
        for _ in range(5):
            leftover = device("logcat -d -b all -v threadtime").stdout
            if "engine loaded in" not in leftover and "compiled rules loaded in" not in leftover:
                break
            time.sleep(1)
        else:
            fail("logcat -c reported success but the buffer still holds a previous load line")
        say("# log start boundary verified")

        # 4. cold start.
        start = device(f"am start -W -n {package}/.ui.MainActivity")
        (raw / "am-start.txt").write_text(start.stdout + start.stderr, encoding="utf-8")
        if start.returncode != 0 or re.search(r"Error|does not exist", start.stdout, re.I):
            fail(f"could not start {package}/.ui.MainActivity: {start.stdout.strip()}")
        time.sleep(10)
        launched = read_pid()
        if not launched:
            fail("am start reported success but the package has no pid")
        device(f"am broadcast -a {package}.action.DEBUG_TOGGLE_VPN "
               f"-n {package}/.filters.DebugCommandReceiver")

        # 5. tunnel up, and prove it carried traffic rather than only being requested.
        up = False
        for _ in range(45):
            if "IS_VPN" in device("dumpsys connectivity").stdout:
                up = True
                break
            time.sleep(2)
        if not up:
            fail("the tunnel did not come up; there is no idle state to sample")
        say(f"# measuring pid={launched}")

        # 6. readiness: this launch's own load lines, in this launch's pid, and — the strongest
        #    statement available — the numbers a host compile of the same lists produced.
        ready = None
        for _ in range(90):
            buffer = device("logcat -d -b all -v threadtime").stdout
            lines_in_pid = []
            for entry in buffer.splitlines():
                match = LEGACY_THREADTIME.match(entry)
                if not match:
                    continue
                if match.group(1) != launched or match.group(3).strip() not in ("ZShieldCore", "ZShield"):
                    continue
                lines_in_pid.append(match.group(4))
            engine = next((m for m in map(LEGACY_ENGINE_LINE.search, lines_in_pid) if m), None)
            dns = next((m for m in map(LEGACY_DNS_LINE.search, lines_in_pid) if m), None)
            counts = next((m for m in map(LEGACY_COUNTS_LINE.search, lines_in_pid) if m), None)
            if engine and dns and counts:
                ready = (engine, dns, counts, lines_in_pid)
                break
            time.sleep(1)
        if ready is None:
            fail(f"within 90 s no launch of pid {launched} printed the load lines this build's "
                 f"readiness is defined by (compiled rules loaded / engine loaded / rule counts)")
        engine, dns, counts, lines_in_pid = ready
        (raw / "readiness.txt").write_text("\n".join(lines_in_pid) + "\n", encoding="utf-8")

        say(f"settled (legacy): compiled rules loaded in {dns.group('ms')} ms")
        say(f"settled (legacy): engine loaded in {engine.group('ms')} ms, "
            f"{engine.group('bytes')} B ({engine.group('redirects')} redirect resources)")
        say(f"# rule counts: {counts.group('block')} block, {counts.group('exception')} exception, "
            f"{counts.group('unsupported')} unsupported, {counts.group('network')} network-only")
        expected = dict(part.split("=", 1) for part in (identity or "").split() if "=" in part)
        if expected.get("engine_bytes") and expected["engine_bytes"] != engine.group("bytes"):
            fail(f"this launch loaded {engine.group('bytes')} B of engine rules but the declared "
                 f"artifacts have {expected['engine_bytes']} B; the measurement would describe a "
                 f"different rule set (a byte count cannot tell two rule sets apart, so a "
                 f"disagreement is fatal while an agreement is only necessary)")
        for name, expected_key, observed_value in (
            ("block", "block_rules", counts.group("block")),
            ("network", "network_rules", counts.group("network")),
        ):
            if expected.get(expected_key) and expected[expected_key] != observed_value:
                fail(f"this launch reports {observed_value} {name} rules but the declared artifacts "
                     f"have {expected[expected_key]}")
        # The canonical content line, in the same spelling `pss_idle.sh` uses, so `recompute` reads a
        # legacy batch the same way it reads a candidate one. The value is the legacy token (engine
        # bytes + rule counts), never a hash: a legacy build cannot produce one, and writing a hash
        # here would claim a content identity it does not have.
        say(f"# effective rule content: {identity}")

        # 7. background, because the debug screen's views are a measurement artefact.
        device("input keyevent KEYCODE_HOME")
        time.sleep(5)

        # 8. samples. Each one is validated before and after: same pid, and no rule install landed in
        #    between (a v0.1.2 launch recompiles on its own, and a swap changes what is being measured
        #    even though this build cannot say so in one line).
        def rule_install_stamps() -> list[str]:
            """The timestamps of this launch's rule installs that are still in the buffer.

            Returns a **set of stamps** rather than a count, because the read is windowed (`-t`) and
            the window slides: a compile line scrolling out of it made the count *drop*, which read
            as "an install landed" and voided a batch that was in fact untouched. v0.1.2 recompiles
            on every launch, so its install line is always close to the window's edge and this fired
            in practice.

            Comparing sets fixes that in the direction that matters: an install that scrolls out is a
            stamp that disappears (harmless — it was already counted before sampling began), while a
            *new* install is a stamp that appears, which is the event the batch must refuse on.
            """
            buffer = device("logcat -d -b all -v threadtime -t 4000").stdout
            stamps: list[str] = []
            for entry in buffer.splitlines():
                match = LEGACY_THREADTIME.match(entry)
                if not match or match.group(1) != launched:
                    continue
                if LEGACY_COMPILE_LINE.search(match.group(4)):
                    stamps.append(entry[:18])   # `MM-DD HH:MM:SS.mmm`
            return stamps

        installs_at_start = set(rule_install_stamps())
        say(f"# rule installs already in this launch's log at the start of sampling: "
            f"{len(installs_at_start)}")
        say("# index\telapsed_s\ttotal_pss_kb\tjava_kb\tnative_kb\tpid")
        values: list[int] = []
        began = time.time()
        for sample_index in range(1, samples + 1):
            if sample_index > 1:
                time.sleep(interval)
            pid_now = read_pid()
            if pid_now != launched:
                fail(f"the measured process changed from {launched} to {pid_now or 'absent'} "
                     f"(before sample {sample_index})")
            dump = device(f"dumpsys meminfo {launched}")
            (raw / f"meminfo-{sample_index}.txt").write_text(dump.stdout, encoding="utf-8")
            if dump.returncode != 0:
                fail(f"dumpsys meminfo exited {dump.returncode} at sample {sample_index}")
            headers = LEGACY_MEMINFO_HEADER.findall(dump.stdout)
            if len(headers) != 1:
                fail(f"the meminfo answer at sample {sample_index} carries {len(headers)} MEMINFO "
                     f"headers; exactly one process is required")
            if headers[0][0] != launched or not (
                    headers[0][1] == package or headers[0][1].startswith(package + ":")):
                fail(f"the meminfo block at sample {sample_index} is for pid {headers[0][0]} "
                     f"[{headers[0][1]}], not {launched} [{package}]")
            totals = LEGACY_MEMINFO_TOTAL.findall(dump.stdout)
            if len(totals) != 1:
                fail(f"the meminfo block at sample {sample_index} carries {len(totals)} TOTAL PSS "
                     f"values; exactly one is required")
            java = re.search(r"Java Heap:\s+(\d+)", dump.stdout)
            native = re.search(r"Native Heap:\s+(\d+)", dump.stdout)
            new_installs = set(rule_install_stamps()) - installs_at_start
            if new_installs:
                fail(f"a rule install landed during sample {sample_index} "
                     f"({', '.join(sorted(new_installs))}); the rule set in force changed and this "
                     f"build cannot report the new generation, so the samples either side describe "
                     f"different content")
            if read_pid() != launched:
                fail(f"the measured process changed during sample {sample_index}")
            values.append(int(totals[0]))
            say(f"{sample_index}\t{int(time.time() - began)}\t{totals[0]}\t"
                f"{java.group(1) if java else '?'}\t{native.group(1) if native else '?'}\t{launched}")

        if len(values) != samples:
            fail(f"only {len(values)} of {samples} samples carried a PSS reading")
        if read_pid() != launched:
            fail("the process changed between the last sample and the summary")
        median = statistics.median(values)
        exact = f"{int(median)}" if float(median).is_integer() else f"{median:.1f}"
        say(f"## median {exact} kB = {median / 1024:.9f} MiB "
            f"(min {min(values)} kB, max {max(values)} kB)")
        say("# note: legacy build — the identity above is byte counts and rule counts, not a content "
            "hash; the cell this batch belongs to is reported as legacy")
        result.write_text("\n".join(lines) + "\n", encoding="utf-8")
        # The numbers this launch reached, in the token form a plan declares, so a `"device"`-pinned
        # legacy cell can hold every later batch to them.
        return (f"engine_bytes={engine.group('bytes')} block_rules={counts.group('block')} "
                f"network_rules={counts.group('network')}")
    finally:
        release = subprocess.run(
            ["bash", "-c", "source scripts/effectiveness/device-lock.sh; lock_release"],
            cwd=REPO, capture_output=True, text=True, env=lock_env)
        lines.append(f"# device lock release: {(release.stdout + release.stderr).strip()}")
        result.write_text("\n".join(lines) + "\n", encoding="utf-8")


def select_rule_set(serial: str, package: str, rule_set: str, wanted: tuple[str, ...],
                    batch_dir: Path) -> None:
    """Enable exactly `wanted` in the app's list UI, and refuse when that could not be verified.

    The list selection is the one part of the protocol that has to go through the app's own screen:
    the release build is not debuggable, `run-as` is refused, and the release build has no broadcast
    that toggles a list. So the toggles are driven through `uiautomator` and then **verified through
    the app's own compiled counts**, not through the switch positions the tapping produced:

    * after toggling, the filters tab must read `条 · N 个列表` with N equal to the number of enabled
      lists the cell asks for;
    * and the core's next cold start must print `compiled N lists:` with the same N.

    A switch that did not move, a list whose download never landed, and a tap that hit the wrong row
    all show up as one of those two disagreeing, and the batch is refused rather than measured
    against a rule set nobody selected.

    The catalog's display names are mapped from list ids here because the UI shows names, and
    matching on a name is the only handle `uiautomator` offers. The mapping is *checked*: a wanted id
    with no name in the catalog is a refusal, so a renamed catalogue entry breaks this loudly.
    """
    batch_dir.mkdir(parents=True, exist_ok=True)
    log: list[str] = [f"# rule set {rule_set}: want {len(wanted)} list(s): {', '.join(wanted)}"]

    def device(command: str, timeout: float = 60.0) -> subprocess.CompletedProcess:
        # Every call is bounded. `uiautomator dump` genuinely hangs on this phone while the UI is
        # animating, and an unbounded call turns "the screen would not settle" into a run that sits
        # silent for hours; a `TimeoutExpired` here reaches the caller as a refusal with a reason.
        try:
            return subprocess.run(["adb", "-s", serial, "shell", command], capture_output=True,
                                  text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise CampaignError(f"`{command}` did not answer within {timeout:.0f}s; the screen state "
                                f"cannot be read, so the selection cannot be driven") from None

    names = catalog_names()
    unknown = [list_id for list_id in wanted if list_id not in names]
    if unknown:
        raise CampaignError(f"the catalog has no entry for {', '.join(unknown)}; the plan names a list "
                            f"this build does not ship, so the selection cannot be made or verified")

    # 1. the filters tab, and prove we are on it before touching anything.
    #
    # A hard-coded tab coordinate is not enough: it is right only on a 1080x1920 screen with the app
    # in its default state, and a run that tapped it while another screen was up went on to scroll
    # and tap that screen for 120 rounds while finding no list at all. So the tab is found by its own
    # label in the dump, and the screen is confirmed by the `` summary line that only the
    # filters tab shows.
    device(f"am start -W -n {package}/.ui.MainActivity")
    time.sleep(3)

    def tap_by_text(label: str) -> bool:
        device("uiautomator dump /sdcard/zs-filters.xml")
        xml = device("cat /sdcard/zs-filters.xml").stdout
        for node in _nodes(xml):
            if node.get("text") == label:
                box = _bounds(node)
                if box is None:
                    continue
                device(f"input tap {(box[0] + box[2]) // 2} {(box[1] + box[3]) // 2}")
                return True
        return False

    # The filters screen is recognised by any of the catalog's own row labels, not by the summary
    # line: the summary is at the top of a scrollable list, so a screen left scrolled down would be
    # misread as "not the filters screen" and the loop would tap the tab and re-check forever.
    on_filters = False
    for _ in range(5):
        if tap_by_text("过滤器"):
            time.sleep(2)
        device("uiautomator dump /sdcard/zs-filters.xml")
        xml = device("cat /sdcard/zs-filters.xml").stdout
        if any(find_row(xml, display) is not None for display in names.values()) \
                or re.search(r"\d+ 个列表", xml):
            on_filters = True
            break
        time.sleep(1)
    if not on_filters:
        raise CampaignError("could not reach the app's filters screen (no catalog row and no list "
                           "summary in five attempts); the list selection cannot be driven and the "
                           "batch is refused rather than measured against an unknown rule set")

    # 2. every row, one scroll at a time, toggled to what the cell wants.
    #
    # The loop scrolls **back to the top first**, then walks down and keeps walking past the end.
    # Both were measured: starting from wherever a previous step left the list found 19 of the 27
    # catalog entries, and stopping at the first page that did not change missed rows that were half
    # scrolled into view. A row is only considered decided when a dump showed it with the state the
    # cell wants — "not seen yet" is never read as "off", because that is what would tap a row the
    # user cannot see.
    def snapshot() -> str:
        dumped = device("uiautomator dump /sdcard/zs-filters.xml", timeout=45)
        text = device("cat /sdcard/zs-filters.xml", timeout=30).stdout
        if not text.strip():
            raise CampaignError(f"the screen dump came back empty (dump said {dumped.stdout.strip()!r}); "
                                f"nothing can be read off this screen")
        return text

    # A fixed number of scrolls, not "until the screen stops changing": a Compose list keeps
    # animating, so two consecutive dumps are almost never byte-identical and that condition never
    # fires. Twelve swipes is more than the 27-entry list needs, and a wasted swipe costs 0.5 s.
    for _ in range(12):
        device("input swipe 540 500 540 1520 200")
        time.sleep(0.5)
    decided: set[str] = set()
    idle_rounds = 0
    for _ in range(120):
        xml = snapshot()
        (batch_dir / "ui-last.xml").write_text(xml, encoding="utf-8")
        # One tap per dump, then re-read. A toggle changes the row's height — the detail line goes
        # from `N 条规则 · …` to `未启用` or back — so every row below it moves. Tapping a second row
        # from the same dump is what produced a wrong final set in the first run: the tap landed on
        # whatever had scrolled into those coordinates.
        pending: tuple[str, tuple[int, int, int, int]] | None = None
        for list_id, display in names.items():
            state = find_row(xml, display)
            if state is None:
                continue
            currently_on, bounds = state
            if currently_on == (list_id in wanted):
                decided.add(list_id)
                continue
            if pending is None:
                pending = (list_id, bounds)
        if pending is not None:
            _, bounds = pending
            device(f"input tap 920 {bounds[1] + (bounds[3] - bounds[1]) // 2}")
            time.sleep(1.2)
            idle_rounds = 0
            continue
        # Nothing left to change on this page: move down. Three consecutive rounds that moved to a
        # page with nothing to change mean the whole list has been walked; one is not evidence,
        # because the list is still animating.
        moved_from = xml
        device("input swipe 540 1500 540 800 300")
        time.sleep(1.2)
        if snapshot() == moved_from:
            idle_rounds += 1
            if idle_rounds >= 3:
                break
        else:
            idle_rounds = 0
    log.append(f"# wanted rows seen in the wanted state: "
               f"{len(set(wanted) & decided)} of {len(wanted)}")

    # 3. verify through the app's own summary line, which lives at the top of the list.
    previous = None
    for _ in range(15):
        device("input swipe 540 500 540 1500 250")
        time.sleep(0.8)
        if snapshot() == previous:
            break
        previous = snapshot()
    for _ in range(20):
        xml = snapshot()
        summary = re.search(r"条 · (\d+) 个列表", xml)
        if summary:
            break
        time.sleep(2)
    else:
        raise CampaignError("after toggling, the filters tab never showed its 「条 · N 个列表」 summary, "
                           "so the selection could not be verified and this batch is refused")
    (batch_dir / "ui-after.xml").write_text(xml, encoding="utf-8")
    got = int(summary.group(1))
    log.append(f"# the app reports {got} enabled list(s)")
    if got != len(wanted):
        raise CampaignError(
            f"the app has {got} enabled list(s) after toggling but {rule_set!r} asks for "
            f"{len(wanted)}; the switch states are not what the cell declares, so nothing measured "
            f"here would describe the declared rule set")
    log.append("# selection counted through the app's summary line (a count is not an identity)")
    (batch_dir / "selection.txt").write_text("\n".join(log) + "\n", encoding="utf-8")


#: The candidate core's identity line, as `pss_idle.sh` parses it.
IDENTITY_LINE = re.compile(
    r"rules identity: event=\w+ ok=(?P<ok>\w+) handle=\d+ generation=\d+ pid=\d+ "
    r"dns=(?P<dns>\S+) engine=(?P<engine>\S+) extras=(?P<extras>\S+)")


def verify_selection_identity(serial: str, package: str, expected: str | None,
                             batch_dir: Path) -> str:
    """Cold-start once and refuse unless the compiled rule content is the cell's declared content.

    The count check in [`select_rule_set`] can only say *how many* lists are enabled; five lists is
    also what a wrong five would give. This is the statement that actually matters, and it is cheap:
    one cold start (~30 s) against the 6-minute batch it guards.

    The sequence is `pss_idle.sh`'s, because `rules identity:` is printed by `Native.start` — that is,
    **only when the tunnel starts**. An earlier revision of this function force-stopped, cleared the
    log and relaunched the activity, and then waited 90 s for a line that a launch without a tunnel
    can never print; it reported "no identity" for a correctly selected rule set. So the tunnel is
    toggled on here exactly as the sampler does it, and the line is read from that launch.
    """
    log = [f"# identity precheck against {expected or '(pin from this launch)'}"]

    def device(command: str) -> subprocess.CompletedProcess:
        return subprocess.run(["adb", "-s", serial, "shell", command], capture_output=True,
                              text=True, timeout=60)

    # The toggle is a *toggle*: start from a known tunnel state rather than assuming one.
    device(f"am broadcast -a {package}.action.DEBUG_TOGGLE_VPN "
           f"-n {package}/.filters.DebugCommandReceiver")
    time.sleep(4)
    for _ in range(10):
        if "IS_VPN" not in device("dumpsys connectivity").stdout:
            break
        device(f"am broadcast -a {package}.action.DEBUG_TOGGLE_VPN "
               f"-n {package}/.filters.DebugCommandReceiver")
        time.sleep(3)
    else:
        raise CampaignError("the tunnel would not go down, so the precheck cannot start from a "
                            "known state")
    device(f"am force-stop {package}")
    time.sleep(2)
    device("logcat -c")
    device(f"am start -W -n {package}/.ui.MainActivity")
    time.sleep(6)
    device(f"am broadcast -a {package}.action.DEBUG_TOGGLE_VPN "
           f"-n {package}/.filters.DebugCommandReceiver")
    observed = None
    for _ in range(90):
        buffer = device("logcat -d -b all -v threadtime").stdout
        matches = [m for m in IDENTITY_LINE.finditer(buffer) if m.group("ok") == "true"]
        if matches:
            match = matches[-1]
            observed = (f"dns={match.group('dns')} engine={match.group('engine')} "
                        f"extras={match.group('extras')}")
            break
        time.sleep(1)
    if observed is None:
        (batch_dir / "identity-precheck.txt").write_text(
            "\n".join(log) + "\n" + buffer[-4000:] + "\n", encoding="utf-8")
        raise CampaignError("no successful `rules identity:` event appeared within 90 s of a cold "
                            "start with the tunnel up, so the selected rule content cannot be "
                            "confirmed")
    log.append(f"# observed: {observed}")
    (batch_dir / "identity-precheck.txt").write_text("\n".join(log) + "\n", encoding="utf-8")
    if expected is not None and observed != expected:
        raise CampaignError(
            f"the app compiled {observed} but the cell declares {expected}; the list selection did "
            f"not produce the declared rule set (a matching list count cannot tell two sets apart)")
    return observed


def catalog_names() -> dict[str, str]:
    """List id → the display name the filters screen shows, from the catalog this build ships."""
    catalog = REPO / "app/src/main/assets/filters/catalog.json"
    try:
        document = json.loads(catalog.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CampaignError(f"{catalog}: cannot read the catalog to map list ids to names: {error}") from None
    return {entry["id"]: entry["name"] for entry in document.get("lists", [])}


#: One `uiautomator` node, as `<node attr="value" …>`. Parsed rather than pattern-matched against a
#: fixed attribute order: `uiautomator` does not promise one, and a version that emits `bounds` before
#: `text` made the earlier ordered regex find nothing at all — which the caller would have read as
#: "this list is not on screen" and then tapped nothing.
NODE = re.compile(r"<node\s+([^>]*?)/?>")
ATTRIBUTE = re.compile(r'([a-z-]+)="([^"]*)"')
BOUNDS = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")


def _nodes(xml: str) -> list[dict[str, str]]:
    """Every node's attributes, as a list of dicts."""
    return [dict(ATTRIBUTE.findall(match.group(1))) for match in NODE.finditer(xml)]


def _bounds(node: dict[str, str]) -> tuple[int, int, int, int] | None:
    match = BOUNDS.search(node.get("bounds", ""))
    if match is None:
        return None
    return tuple(int(match.group(i)) for i in (1, 2, 3, 4))  # type: ignore[return-value]


def find_row(xml: str, name: str) -> tuple[bool, tuple[int, int, int, int]] | None:
    """Whether the row labelled `name` is switched on, and the bounds of its switch.

    Returns `None` when the row is not in the current dump — the list is scrolled out of view, which
    is **not** the same as "off". The switch is the checkable node whose vertical band overlaps the
    label's; the app draws it on the trailing edge of the same row (`FiltersScreen.kt` `FilterRow`).
    """
    nodes = _nodes(xml)
    band: tuple[int, int] | None = None
    for node in nodes:
        if node.get("text") == name:
            box = _bounds(node)
            if box is not None:
                band = (box[1], box[3])
                break
    if band is None:
        return None
    for node in nodes:
        if node.get("checkable") != "true":
            continue
        box = _bounds(node)
        if box is None:
            continue
        left, top, right, bottom = box
        if top <= band[1] and bottom >= band[0]:
            return node.get("checked") == "true", box
    return None


def device_apk_sha(serial: str, package: str) -> str:
    """The SHA-256 of the installed base APK, read on the device.

    Read from the device rather than from a local copy: the question is what the phone is running,
    and `adb install` of a different APK between two batches would leave every local copy looking
    right.
    """
    path = subprocess.run(["adb", "-s", serial, "shell", "pm", "path", package],
                          capture_output=True, text=True).stdout
    match = re.search(r"^package:(.+)$", path, re.MULTILINE)
    if not match:
        raise CampaignError(f"{package} is not installed on {serial} ({path.strip()!r})")
    result = subprocess.run(["adb", "-s", serial, "shell", "sha256sum", match.group(1).strip()],
                           capture_output=True, text=True)
    digest = result.stdout.split()[0] if result.stdout.split() else ""
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise CampaignError(f"could not hash {match.group(1).strip()} on the device: "
                            f"{result.stdout.strip()!r} {result.stderr.strip()!r}")
    return digest


# ---------------------------------------------------------------------------------------------
# Offline recompute
# ---------------------------------------------------------------------------------------------

@dataclass
class Campaign:
    """A finished campaign, re-read from disk and validated against itself."""

    directory: Path
    plan: Plan
    cells: dict[tuple[str, str], CellSummary]
    problems: list[str]
    #: Cells that failed a check, whether in their own batches or in the campaign file's record of
    #: them. A cell here gets no threshold verdict and no comparison: it is not evidence.
    voided: set[tuple[str, str]] = field(default_factory=set)
    #: The four independent verdicts, kept apart on purpose. The card asks for exactly this: sample
    #: numbers being valid says nothing about whether the inputs were the same, nor about whether the
    #: batches ran in a usable order, nor about the threshold. Collapsing them into one "PASS" is how
    #: a campaign that re-ran half its batches after the fact produced a formal comparison.
    samples_valid: bool = False
    inputs_proven: bool = False
    order_proven: bool = False
    #: Why each layer failed, per cell where it is per-cell.
    input_problems: list[str] = field(default_factory=list)
    order_problems: list[str] = field(default_factory=list)
    #: The order the batches actually ran in, from their own stamps — `[]` when it cannot be read.
    executed_order: list[tuple[str, str, int]] = field(default_factory=list)
    #: Per cell, why it cannot join a formal *equivalence* comparison even though its own numbers are
    #: valid — the legacy build's absent content identity is the case in hand.
    equivalence_gaps: dict[tuple[str, str], str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return (not self.problems and all(cell.ok for cell in self.cells.values()))

    @property
    def formally_comparable(self) -> bool:
        """Whether a formal PASS and a version difference may be stated.

        All three layers, and they are not interchangeable: valid sample numbers from an unproven
        input, or from batches that ran in an order nobody can establish, are diagnostic only.
        """
        return self.samples_valid and self.inputs_proven and self.order_proven


def load_campaign(directory: Path) -> Campaign:
    """Re-derive a campaign from its directory, without a device and without trusting the summary.

    Three sources are read and cross-checked, because each can be wrong on its own: the campaign file
    (what was run and in what order), the per-batch result files (the numbers), and the raw device
    answers under each batch's `*.raw/` (what the device actually said). A disagreement between any
    two is a problem, never a preference.

    The first revision trusted the result files alone. That is why a campaign whose own file recorded
    three **void** batches still recomputed to `ok=true` with a PASS: nothing ever compared the
    campaign's verdicts against the evidence, and nothing checked that the batches present were the
    ones the plan ordered, in the order it ordered them.
    """
    campaign_file = directory / "campaign.json"
    if not campaign_file.is_file():
        raise PlanError(f"{directory}: no campaign.json; not a campaign directory")
    try:
        raw = json.loads(campaign_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise PlanError(f"{campaign_file}: not JSON: {error}") from None

    plan_raw = raw.get("plan")
    if not isinstance(plan_raw, dict):
        raise PlanError(f"{campaign_file}: no plan section")

    # The campaign's own plan is validated by the same rules a plan file is, so a campaign cannot be
    # re-derived from a plan the tool would have refused to run.
    plan = plan_from_record(plan_raw, where=str(campaign_file))

    attempts, attempt_problems = parse_attempts(raw, plan)
    attempt_problems.extend(check_attempt_inventory(attempts, plan, directory))
    successful = {(a.build, a.rule_set, a.index): a for a in attempts if a.outcome == "ok"}

    problems: list[str] = []
    cells: dict[tuple[str, str], CellSummary] = {}
    for build_name, rule_set in plan.cells():
        batches: list[BatchResult] = []
        for index in range(1, plan.batches + 1):
            batch_dir = directory / f"{rule_set}--{build_name}--b{batch_dir_suffix(index)}"
            attempt = successful.get((build_name, rule_set, index))
            if attempt and safe_attempt_directory(directory, attempt.directory):
                batch_dir = directory / attempt.directory
            if not batch_dir.is_dir():
                problems.append(f"cell {build_name}/{rule_set}: batch {index} has no directory "
                                f"({batch_dir.name})")
                continue
            batches.append(parse_batch(batch_dir, build_name, rule_set, index,
                                       expected_samples=plan.samples))
        summary = CellSummary(build=build_name, rule_set=rule_set, batches=batches)
        cells[(build_name, rule_set)] = summary

        cell_name = f"{build_name}/{rule_set}"
        expected_identity = builds_identity(plan, build_name, rule_set)
        identities = {batch.identity for batch in batches if batch.identity}
        if len(identities) > 1:
            problems.append(f"cell {cell_name}: the batches ran under {len(identities)} different "
                            f"rule contents")
        elif expected_identity and identities and not plan.builds[build_name].legacy \
                and expected_identity not in identities:
            got = next(iter(identities))
            problems.append(f"cell {cell_name}: the batches ran under {got} but the cell declares "
                            f"{expected_identity}")
        apks = {batch.apk_sha256 for batch in batches if batch.apk_sha256}
        if len(apks) > 1:
            problems.append(f"cell {cell_name}: the batches ran on {len(apks)} different APKs")
        elif apks and plan.builds[build_name].apk_sha256 not in apks:
            problems.append(f"cell {cell_name}: the batches ran on {next(iter(apks))} but the cell "
                            f"declares {plan.builds[build_name].apk_sha256}")
        for batch in batches:
            if not batch.ok:
                problems.append(f"cell {cell_name} batch {batch.index}: {batch.failure}")
        if len(batches) < plan.batches:
            problems.append(f"cell {cell_name}: {len(batches)} of {plan.batches} batches are present")

    executed, executed_problems = executed_order(attempts)
    order_problems = attempt_problems + executed_problems + check_alternation(executed, plan)
    if executed:
        for position, (build_name, rule_set, index) in enumerate(executed, start=1):
            batch = next((b for b in cells.get((build_name, rule_set), CellSummary(
                build_name, rule_set, [])).batches if b.index == index), None)
            if batch is None:
                continue
            cadence = check_sample_cadence(batch, plan.interval)
            if cadence is not None:
                order_problems.append(f"cell {build_name}/{rule_set} batch {index}: {cadence}")
            attempt = next((a for a in attempts if (a.build, a.rule_set, a.index)
                            == (build_name, rule_set, index) and a.outcome == "ok"), None)
            if attempt:
                try:
                    start = parse_stamp(attempt.started_at)
                    finish = parse_stamp(attempt.finished_at)
                    batch_start = parse_stamp(batch.started_at)
                except ValueError as error:
                    order_problems.append(f"attempt {attempt.attempt_id}: {error}")
                    continue
                if batch_start != start:
                    order_problems.append(
                        f"cell {build_name}/{rule_set} batch {index}: the campaign records a start "
                        f"of {attempt.started_at} but the result file says {batch.started_at}; the "
                        f"attempt record does not describe this batch")
                if batch.elapsed_s and (finish - start).total_seconds() < max(batch.elapsed_s):
                    order_problems.append(f"attempt {attempt.attempt_id}: duration does not "
                                          "contain the last recorded sample")

    input_problems: list[str] = []
    equivalence_gaps: dict[tuple[str, str], str] = {}
    for build_name, rule_set in plan.cells():
        input_problems.extend(check_inputs(plan, build_name, rule_set))
        record = plan.inputs.get(f"{build_name}/{rule_set}", {})
        artifacts = record.get("loaded_artifacts_sha256")
        if isinstance(artifacts, dict) and set(artifacts) == {"dns", "engine", "extras"}:
            declared = " ".join(f"{part}={artifacts[part]}" for part in ("dns", "engine", "extras"))
            if any(batch.identity != declared for batch in cells[(build_name, rule_set)].batches):
                input_problems.append(f"cell {build_name}/{rule_set}: loaded artifacts disagree "
                                      "with the batch's observed identity")
        gap = legacy_equivalence_gap(plan, build_name)
        if gap is not None:
            equivalence_gaps[(build_name, rule_set)] = gap
    if not input_problems:
        for rule_set in plan.rule_sets:
            sources = []
            for build_name in plan.builds:
                record = plan.inputs[f"{build_name}/{rule_set}"]
                sources.append((sorted((item["id"], item["enabled"], item["sha256"])
                                       for item in record["lists"]),
                                record["user_rules_sha256"], record["allowlist_sha256"]))
            if any(source != sources[0] for source in sources[1:]):
                input_problems.append(f"rule set {rule_set}: builds measured different source "
                                      "inputs (list bodies, user rules or allowlist)")

    voided = {(name, rule_set) for (name, rule_set), cell in cells.items() if not cell.ok}
    outcome_problems, outcome_voided = check_recorded_outcomes(raw, plan)
    problems.extend(outcome_problems)
    voided |= outcome_voided
    # A cell named in any problem is not evidence, whatever the problem was: a rule-content
    # disagreement, a cell missing a batch, a different APK between batches.
    for problem in problems:
        for name, rule_set in cells:
            if problem.startswith(f"cell {name}/{rule_set}"):
                voided.add((name, rule_set))
    samples_ok = not problems and all(cell.ok for cell in cells.values())
    return Campaign(directory=directory, plan=plan, cells=cells, problems=problems, voided=voided,
                    samples_valid=samples_ok,
                    inputs_proven=samples_ok and not input_problems,
                    order_proven=samples_ok and not order_problems,
                    input_problems=input_problems, order_problems=order_problems,
                    executed_order=executed, equivalence_gaps=equivalence_gaps)


def batch_dir_suffix(index: int) -> str:
    """The `b<N>` spelling the runner uses for a batch directory."""
    return str(index)


def builds_identity(plan: "Plan", build_name: str, rule_set: str) -> str | None:
    """The identity a cell declares, or `None` when it pins from the device instead."""
    build = plan.builds.get(build_name)
    return build.identities.get(rule_set) if build else None


def check_recorded_outcomes(raw: dict, plan: "Plan") -> tuple[list[str], set[tuple[str, str]]]:
    """Require the campaign file's own verdicts to agree with the evidence on disk.

    A campaign that recorded a batch as `void` cannot recompute to a valid cell — but the first
    revision never looked, so three recorded voids still produced `ok=true`. The check runs both
    ways: a batch recorded as void blocks its cell, and a batch recorded as ok must have the result
    files to back it.
    """
    problems: list[str] = []
    voided: set[tuple[str, str]] = set()
    recorded = raw.get("batches")
    if not isinstance(recorded, list) or not recorded:
        return (["the campaign file records no per-batch outcomes; an unattested campaign is not "
                 "evidence"], {(name, rule_set) for name, rule_set in plan.cells()})
    by_cell: dict[tuple[str, str], list[dict]] = {}
    for entry in recorded:
        if not isinstance(entry, dict):
            problems.append("the campaign file has a per-batch entry that is not an object")
            continue
        cell = entry.get("cell")
        if not isinstance(cell, list) or len(cell) != 2:
            problems.append(f"the campaign file has a batch entry with no cell: {entry!r}")
            continue
        by_cell.setdefault((str(cell[0]), str(cell[1])), []).append(entry)
    for build_name, rule_set in plan.cells():
        entries = by_cell.get((build_name, rule_set), [])
        if not entries:
            problems.append(f"cell {build_name}/{rule_set}: the campaign file records no batches "
                            f"for this cell")
            voided.add((build_name, rule_set))
            continue
        indices = [entry.get("index") for entry in entries]
        if (any(not isinstance(index, int) or isinstance(index, bool) for index in indices)
                or sorted(indices) != list(range(1, plan.batches + 1))):
            problems.append(f"cell {build_name}/{rule_set}: per-batch outcomes must cover "
                            f"each batch 1..{plan.batches} exactly once")
            voided.add((build_name, rule_set))
        voids = [entry for entry in entries if entry.get("outcome") != "ok"]
        if voids:
            reasons = "; ".join(f"batch {entry.get('index')}: "
                                f"{entry.get('reason') or entry.get('failure') or 'void'}"
                                for entry in voids)
            problems.append(f"cell {build_name}/{rule_set}: the campaign file itself records "
                            f"{len(voids)} void batch(es) — {reasons}")
            voided.add((build_name, rule_set))
    if set(by_cell) - set(plan.cells()):
        problems.append("the campaign file records outcomes for unknown cells")
    return problems, voided


#: A 60 s cadence with command overhead: the gap between samples may be *longer* than the declared
#: interval (the sampler's own commands take seconds) but never meaningfully shorter. The card fixes
#: 6 × 60 s and explicitly allows command time to stretch it.
MIN_SAMPLE_GAP_S = 60
#: How much shorter than the declared interval a gap may be before it is a different cadence rather
#: than command jitter. Zero in practice: `pss_idle.sh` sleeps the full interval between samples.
SAMPLE_GAP_TOLERANCE_S = 0


def check_sample_cadence(batch: BatchResult, interval: int) -> str | None:
    """Whether one batch really sampled at the declared interval.

    The reviewer's `one_second_samples` probe rewrote every row's elapsed column to 1, 2, 3… and the
    campaign still produced a formal comparison. A batch whose samples are a second apart did not
    follow the 6 × 60 s protocol, so it is not the measurement the card asks for. Enforced here:

    * the batch must declare an interval, and it must be the plan's;
    * the gaps between consecutive elapsed values must be at least the declared interval
      (command overhead may lengthen them — that is expected and allowed);
    * elapsed values must strictly increase (a re-ordered or duplicated row is not a run).
    """
    if batch.declared_interval_s is None:
        return ("the batch header declares no sampling interval, so its cadence cannot be checked")
    if batch.declared_interval_s != interval:
        return (f"the batch declares {batch.declared_interval_s}s but the plan requires {interval}s")
    if len(batch.elapsed_s) < 2:
        return None
    previous = batch.elapsed_s[0]
    for position, value in enumerate(batch.elapsed_s[1:], start=2):
        if value <= previous:
            return (f"sample {position} is at {value}s, not after sample {position - 1} at "
                    f"{previous}s; elapsed time must strictly increase within one batch")
        gap = value - previous
        if gap < batch.declared_interval_s - SAMPLE_GAP_TOLERANCE_S:
            return (f"samples {position - 1}->{position} are {gap}s apart but the batch declares "
                    f"{batch.declared_interval_s}s; this is not the {FORMAL_SAMPLES} × "
                    f"{FORMAL_INTERVAL}s protocol the card fixes")
        previous = value
    return None


@dataclass
class Attempt:
    """One real run of one batch, as the campaign file recorded it.

    The second review's central finding was that a campaign can claim an order it did not run. A
    planned order is an intention; an attempt is a fact with a start, an end and an output directory.
    So the record is a list of attempts, each with its own id, and the *actual* order is derived from
    the attempts' stamps — never from the plan.
    """

    attempt_id: str
    build: str
    rule_set: str
    index: int
    started_at: str | None
    finished_at: str | None
    directory: str
    outcome: str
    reason: str | None = None


def parse_attempts(raw: dict, plan: "Plan") -> tuple[list[Attempt], list[str]]:
    """Read the campaign's attempt list, or explain why it cannot be used as timing evidence."""
    problems: list[str] = []
    recorded = raw.get("attempts")
    if recorded is None:
        # The older shape. It recorded outcomes but not when each batch ran, which is exactly the
        # evidence a re-run after the fact destroys. Kept readable for diagnosis, refused for
        # acceptance.
        return ([], ["the campaign file has no `attempts` list: it records outcomes but not when "
                     "each batch actually ran, so the executed order cannot be established"])
    if not isinstance(recorded, list) or not recorded:
        return ([], ["the campaign file's `attempts` is not a non-empty list"])
    attempts: list[Attempt] = []
    seen_ids: set[str] = set()
    for position, entry in enumerate(recorded):
        if not isinstance(entry, dict):
            problems.append(f"attempt {position} is not an object")
            continue
        cell = entry.get("cell")
        if not isinstance(cell, list) or len(cell) != 2:
            problems.append(f"attempt {position} has no [build, rule_set] cell")
            continue
        attempt_id = str(entry.get("attempt_id") or "")
        if not attempt_id:
            problems.append(f"attempt {position} has no attempt_id; an attempt without an identity "
                            f"cannot be told apart from a re-run of itself")
        elif attempt_id in seen_ids:
            problems.append(f"attempt id {attempt_id!r} appears twice")
        seen_ids.add(attempt_id)
        index = entry.get("index")
        if not isinstance(index, int) or isinstance(index, bool):
            problems.append(f"attempt {attempt_id}: invalid batch index {index!r}")
            continue
        attempts.append(Attempt(
            attempt_id=attempt_id, build=str(cell[0]), rule_set=str(cell[1]),
            index=index,
            started_at=entry.get("started_at"), finished_at=entry.get("finished_at"),
            directory=str(entry.get("directory") or ""),
            outcome=str(entry.get("outcome") or ""), reason=entry.get("reason")))
    return attempts, problems


def safe_attempt_directory(root: Path, name: str) -> bool:
    """Never follow an evidence pointer outside this campaign, including through a symlink."""
    path = Path(name)
    return (bool(name) and not path.is_absolute() and ".." not in path.parts
            and (root / path).resolve().is_relative_to(root.resolve())
            and (root / path).resolve() != root.resolve())


def check_attempt_inventory(attempts: list[Attempt], plan: Plan, root: Path) -> list[str]:
    problems = []
    expected = set(plan.order())
    completed: dict[tuple[str, str, int], int] = {}
    directories: set[Path] = set()
    for attempt in attempts:
        slot = (attempt.build, attempt.rule_set, attempt.index)
        if slot not in expected:
            problems.append(f"attempt {attempt.attempt_id}: unknown cell/index {slot}")
        if attempt.outcome not in ("ok", "void", "failed"):
            problems.append(f"attempt {attempt.attempt_id}: unknown outcome {attempt.outcome!r}")
        if attempt.outcome == "ok":
            completed[slot] = completed.get(slot, 0) + 1
        if not safe_attempt_directory(root, attempt.directory):
            problems.append(f"attempt {attempt.attempt_id}: invalid directory {attempt.directory!r}")
            continue
        path = (root / attempt.directory).resolve()
        if not path.is_dir():
            problems.append(f"attempt {attempt.attempt_id}: directory {attempt.directory!r} is missing")
        if path in directories:
            problems.append(f"attempt {attempt.attempt_id}: reused directory; original attempts "
                            "must be retained separately")
        directories.add(path)
    for slot in sorted(expected):
        if completed.get(slot, 0) != 1:
            problems.append(f"cell {slot}: expected exactly one successful attempt, "
                            f"found {completed.get(slot, 0)}")
    return problems


def executed_order(attempts: list[Attempt]) -> tuple[list[tuple[str, str, int]], list[str]]:
    """The order the batches actually ran in, from their own start stamps.

    Returns the successful attempts sorted by start time, plus any problem that prevents reading a
    real order out of them. A campaign whose attempts have no stamps, or whose stamps do not sort
    into a sequence consistent with the batches on disk, cannot claim an alternating order.
    """
    problems: list[str] = []
    completed = [a for a in attempts if a.outcome == "ok"]
    if not completed:
        return ([], ["no attempt completed successfully"])
    missing = [a.attempt_id for a in attempts if not a.started_at or not a.finished_at]
    if missing:
        return ([], [f"{len(missing)} completed attempt(s) carry no start/finish stamp "
                     f"({', '.join(sorted(missing)[:4])}…); the executed order cannot be "
                     f"established from unstamped attempts"])
    try:
        ordered = sorted(attempts, key=lambda a: parse_stamp(a.started_at))
        intervals = [(parse_stamp(a.started_at), parse_stamp(a.finished_at), a) for a in ordered]
    except ValueError as error:
        return ([], [f"an attempt's stamp cannot be parsed: {error}"])
    # Attempts must not overlap: two batches sampling at once would contend for one phone. This is
    # an interval-intersection question, not an adjacency one — sorting by start time does not make
    # neighbours the only possible overlap (a long batch at 00:00–00:30 contains a short one at
    # 00:05–00:10 further down the list).
    for position, (start, end, attempt) in enumerate(intervals):
        if end <= start:
            problems.append(f"attempt {attempt.attempt_id}: duration must be positive")
        for other_start, other_end, other in intervals[position + 1:]:
            if other_start >= end:
                break
            problems.append(
                f"attempt {other.attempt_id} ({other.started_at}–{other.finished_at}) overlaps "
                f"attempt {attempt.attempt_id} ({attempt.started_at}–{attempt.finished_at}); two "
                f"batches cannot sample at once on one device")
            break
    return ([(a.build, a.rule_set, a.index) for a in ordered if a.outcome == "ok"], problems)


def parse_stamp(value: str) -> datetime.datetime:
    """Parse one ISO-8601 `…Z` stamp. Raises `ValueError` with the offending text."""
    try:
        return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        raise ValueError(f"{value!r} is not an ISO-8601 `YYYY-MM-DDTHH:MM:SSZ` stamp") from None


def check_alternation(order: list[tuple[str, str, int]], plan: "Plan") -> list[str]:
    """Whether the executed order alternates the builds inside each rule-set block.

    The plan's reason for alternating is measured (drift must not be attributable to a build), so an
    order that ran one build's batches together is reported — but the check is made against the
    **executed** order, not against the plan's own list. That distinction is the whole point: the
    delivered campaign satisfied the plan's order on paper while its six v0.1.2 batches all ran
    after all six candidate batches.
    """
    problems: list[str] = []
    if not order:
        return problems
    builds = list(plan.builds)
    if len(builds) < 2:
        return problems
    by_rule_set: dict[str, list[tuple[str, int]]] = {}
    for build, rule_set, index in order:
        by_rule_set.setdefault(rule_set, []).append((build, index))
    for rule_set, sequence in by_rule_set.items():
        # Within one rule set, no build may appear twice in a row while another build still has
        # batches left in that block: that is "one build's batches ran together".
        for position in range(1, len(sequence)):
            previous_build, _ = sequence[position - 1]
            current_build, _ = sequence[position]
            if previous_build == current_build:
                problems.append(
                    f"rule set {rule_set}: `{current_build}` ran two batches consecutively "
                    f"(positions {position} and {position + 1} of the executed order "
                    f"{sequence}); the card requires the two builds to alternate so that drift "
                    f"cannot be attributed to a build")
                break
    blocks = [rule_set for _, rule_set, _ in order]
    for rule_set in set(blocks):
        positions = [i for i, value in enumerate(blocks) if value == rule_set]
        if positions[-1] - positions[0] + 1 != len(positions):
            problems.append(f"rule set {rule_set}: executed order splits one rule-set block")
    return problems


#: The per-cell input proofs a formal comparison needs, and what each one establishes.
#: `device_lists` is the only field that says what the phone actually held; the rest are necessary
#: conditions. The card is explicit that a legacy build's byte counts are not a content identity, so
#: `artifact_identity` is only meaningful for a build that prints `rules identity:`.
REQUIRED_INPUT_FIELDS = (
    "lists",             # [{id, enabled, sha256}] — what the phone had enabled, and their content
    "user_rules_sha256",  # the user rules the compile consumed
    "allowlist_sha256",
    "apk_sha256",
    "loaded_artifacts_sha256",  # the artifacts the tunnel loaded, per component
)


def legacy_equivalence_gap(plan: "Plan", build_name: str) -> str | None:
    """The structural reason a legacy build cannot join a formal equivalence comparison.

    Kept separate from [`check_inputs`] because the consequence differs: a *missing* field is an
    omission that could be filled and therefore blocks the campaign's input verdict; a legacy build's
    absent artifact hash is a property of that build, so it blocks the **comparison** while leaving
    its own sample numbers valid and reportable.
    """
    if not plan.builds[build_name].legacy:
        return None
    return (f"build {build_name}: a legacy build prints engine byte counts and rule counts, not a "
            f"content hash, so its loaded artifacts cannot be identified. Its numbers may not take "
            f"part in a formal equivalence comparison; they are reported as diagnostic only")


def check_inputs(plan: "Plan", build_name: str, rule_set: str) -> list[str]:
    """What is missing from a cell's input proof.

    The second review rejected a formal comparison whose inputs were only argued: the campaign
    declared the catalog's five lists, but nothing recorded what the phone actually had enabled, nor
    the list bodies' hashes, nor the artifacts the tunnel loaded. This function does not invent those
    — it reports what is absent so the comparison can be withheld.

    A legacy build cannot supply `loaded_artifacts_sha256` at all (it prints byte counts, not a
    content hash), and the card says so: its numbers may not take part in a formal equivalence
    comparison. That is reported as a structural gap, not as a transient omission.
    """
    record = plan.inputs.get(f"{build_name}/{rule_set}")
    if not isinstance(record, dict):
        return [f"cell {build_name}/{rule_set}: no input record at all; what the phone held while "
                f"this cell was measured is unknown"]
    missing = [name for name in REQUIRED_INPUT_FIELDS if not record.get(name)]
    problems: list[str] = []
    if missing:
        structural = set(missing) == {"loaded_artifacts_sha256"} and plan.builds[build_name].legacy
        suffix = (" (structural: this build cannot print a content hash, so the cell may be "
                  "reported as diagnostic but never compared formally)"
                  if structural else "")
        problems.append(f"cell {build_name}/{rule_set}: input proof is missing "
                        f"{', '.join(missing)}{suffix}")
    lists = record.get("lists")
    if not isinstance(lists, list) or not all(isinstance(item, dict) for item in lists):
        problems.append(f"cell {build_name}/{rule_set}: invalid lists record")
    else:
        expected = set(plan.rule_sets.get(rule_set, ()))
        recorded = {str(item.get("id")) for item in lists if isinstance(item, dict)}
        if recorded != expected:
            problems.append(
                f"cell {build_name}/{rule_set}: the input record lists {sorted(recorded)} but the "
                f"card's set is {sorted(expected)}; the cell did not measure the declared lists")
        if len(recorded) != len(lists):
            problems.append(f"cell {build_name}/{rule_set}: duplicate list IDs")
        enabled = {str(item.get("id")) for item in lists
                   if item.get("enabled") is True}
        if enabled != expected:
            problems.append(
                f"cell {build_name}/{rule_set}: the input record has {sorted(enabled)} enabled but "
                f"the card's set is {sorted(expected)}")
        devoid = [str(item.get("id")) for item in lists
                  if isinstance(item, dict) and not item.get("sha256")]
        if devoid:
            problems.append(f"cell {build_name}/{rule_set}: no content hash for list(s) "
                            f"{', '.join(sorted(devoid))}")
        if any(not valid_sha256(item.get("sha256")) for item in lists):
            problems.append(f"cell {build_name}/{rule_set}: invalid list content SHA-256")
    for key in ("user_rules_sha256", "allowlist_sha256", "apk_sha256"):
        if not valid_sha256(record.get(key)):
            problems.append(f"cell {build_name}/{rule_set}: invalid {key}")
    artifacts = record.get("loaded_artifacts_sha256")
    if (not isinstance(artifacts, dict) or set(artifacts) != {"dns", "engine", "extras"}
            or any(not isinstance(value, str) or not IDENTITY_TOKEN.fullmatch(value)
                   for value in artifacts.values())
            or all(value == "-" for value in artifacts.values())):
        problems.append(f"cell {build_name}/{rule_set}: invalid loaded_artifacts_sha256")
    if record.get("apk_sha256") and record.get("apk_sha256") != plan.builds[build_name].apk_sha256:
        problems.append(
            f"cell {build_name}/{rule_set}: the input record names APK "
            f"{record.get('apk_sha256')} but the cell measured {plan.builds[build_name].apk_sha256}")
    if plan.builds[build_name].legacy and record.get("loaded_artifacts_sha256"):
        problems.append(
            f"cell {build_name}/{rule_set}: a legacy build cannot produce a content identity for "
            f"the artifacts it loaded; a hash here did not come from the device")
    return problems


def valid_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def report(campaign: Campaign, as_json: bool) -> int:
    """Report the four verdicts separately, and state a formal result only when all of them hold.

    The card is explicit about the layering, because collapsing it is what went wrong twice:

    * **sample numbers valid** — each batch is a real 6 × 60 s run of one process and one rule
      generation, cross-checked against the device's own `dumpsys` answers;
    * **inputs proven** — what the phone held (lists, their content, user rules, artifacts) is known,
      not merely declared;
    * **order valid** — the batches actually ran when the record says they did, alternating, without
      overlap;
    * **threshold** — a separate statement about 84.6 MiB, and only for `fixed-five`.

    Diagnostic numbers are still printed when the later layers fail: a reader may want to see them.
    What is withheld is the two things that need all three — a formal threshold verdict the card
    would accept, and any version difference.
    """
    plan = campaign.plan
    rows: list[dict[str, object]] = []
    for (build_name, rule_set), cell in campaign.cells.items():
        rows.append({
            "build": build_name,
            "rule_set": rule_set,
            "batches": len(cell.batches),
            "ok_batches": sum(1 for batch in cell.batches if batch.ok),
            "batches_kb": cell.medians_kb,
            "centre_kb": cell.centre_kb,
            "centre_mib": (cell.centre_kb / 1024.0) if cell.centre_kb is not None else None,
            "between_batch_range_mib":
                (cell.spread_kb / 1024.0) if cell.spread_kb is not None else None,
            "samples_per_batch": [len(batch.samples_kb) for batch in cell.batches],
            "identity": next((batch.identity for batch in cell.batches if batch.identity), None),
            "identity_source": (plan.builds[build_name].identity_source
                                if build_name in plan.builds else None),
            "apk_sha256": next((batch.apk_sha256 for batch in cell.batches if batch.apk_sha256),
                               None),
            "failure": next((batch.failure for batch in cell.batches if batch.failure), None),
        })

    # Whether this campaign may state a formal result at all.
    formal = campaign.formally_comparable and not plan.diagnostic
    diagnostics_only = plan.diagnostic or not formal

    comparisons: list[dict[str, object]] = []
    excluded: list[dict[str, object]] = []
    build_names = list(plan.builds)
    if len(build_names) == 2:
        left, right = build_names
        for rule_set in plan.rule_sets:
            left_cell = campaign.cells.get((left, rule_set))
            right_cell = campaign.cells.get((right, rule_set))
            if not left_cell or not right_cell:
                continue
            gap = (campaign.equivalence_gaps.get((left, rule_set))
                   or campaign.equivalence_gaps.get((right, rule_set)))
            if gap is not None:
                excluded.append({
                    "rule_set": rule_set, "reason": gap,
                    "diagnostic_values": {
                        "left_mib": (left_cell.centre_kb / 1024.0) if left_cell.centre_kb else None,
                        "right_mib": (right_cell.centre_kb / 1024.0) if right_cell.centre_kb else None,
                    },
                })
                continue
            if (left, rule_set) in campaign.voided or (right, rule_set) in campaign.voided:
                excluded.append({"rule_set": rule_set,
                                 "reason": "a cell in this rule set is voided; there is nothing to "
                                           "compare"})
                continue
            if diagnostics_only:
                excluded.append({
                    "rule_set": rule_set,
                    "reason": ("the campaign declares itself diagnostic"
                               if plan.diagnostic else
                               "the evidence does not support a formal comparison: "
                               + "; ".join(filter(None, [
                                   None if campaign.inputs_proven else
                                   "inputs not proven",
                                   None if campaign.order_proven else
                                   "executed order not established"]))),
                    "diagnostic_values": {
                        "left_mib": (left_cell.centre_kb / 1024.0) if left_cell.centre_kb else None,
                        "right_mib": (right_cell.centre_kb / 1024.0) if right_cell.centre_kb else None,
                    },
                })
                continue
            verdict = compare(left_cell, right_cell)
            verdict.update({"rule_set": rule_set, "left": left, "right": right})
            comparisons.append(verdict)

    # Thresholds are per rule set and the card fixes exactly one: `fixed-five` at 84.6 MiB. A nine
    # list figure has no gate, and applying the five-list gate to it (which the previous revision
    # did) invents a requirement.
    threshold: list[dict[str, object]] = []
    for row in rows:
        if row["rule_set"] not in THRESHOLDS:
            continue
        if (row["build"], row["rule_set"]) in campaign.voided:
            continue
        if row["centre_mib"] is None:
            continue
        entry = {
            "build": row["build"], "rule_set": row["rule_set"],
            "centre_mib": row["centre_mib"],
            "threshold_mib": THRESHOLDS[row["rule_set"]],
        }
        if diagnostics_only:
            entry["verdict"] = "DIAGNOSTIC"
            entry["note"] = ("the number is a real measurement, but it is not acceptance evidence: "
                             + ("the campaign declares itself diagnostic" if plan.diagnostic else
                                "the evidence does not support a formal verdict"))
        else:
            entry["verdict"] = ("PASS" if row["centre_mib"] <= THRESHOLDS[row["rule_set"]]
                                else "FAIL")
        threshold.append(entry)

    # The single acceptance predicate, used by the JSON's `ok` and by the exit status, so the two
    # cannot disagree.
    formal = (campaign.ok and not campaign.input_problems and not campaign.order_problems
              and not plan.diagnostic)
    document = {
        "directory": str(campaign.directory),
        "layer": {
            "samples_valid": campaign.samples_valid,
            "inputs_proven": campaign.inputs_proven,
            "order_proven": campaign.order_proven,
            "formally_comparable": campaign.formally_comparable,
            "diagnostic": plan.diagnostic,
        },
        "thresholds_mib": THRESHOLDS,
        "problems": campaign.problems,
        "input_problems": campaign.input_problems,
        "order_problems": campaign.order_problems,
        "executed_order": [list(item) for item in campaign.executed_order],
        "cells": rows,
        "comparisons": comparisons,
        "comparisons_withheld": excluded,
        "threshold": threshold,
        # One field answers one question: may this campaign be handed in as acceptance evidence?
        # It is the conjunction the exit status uses, because a caller (the reviewer's own probe
        # among them) reads `ok` and a per-cell `ok` would let a layer-failed campaign look accepted.
        "ok": formal,
        "samples_ok": campaign.ok,
    }
    if as_json:
        print(json.dumps(document, indent=2, ensure_ascii=False, sort_keys=True))
    else:
        print_campaign(document)
    # The exit status is a single question: "may this campaign be handed in as acceptance evidence?"
    # So it is 0 only when the three layers hold **and** the campaign does not declare itself
    # diagnostic. A diagnostic run still prints its numbers — the card allows keeping raw per-batch
    # values — but it is not acceptance data, and a script must not be able to read it as such. A
    # per-cell equivalence gap already withholds that one comparison and is reported; it does not by
    # itself invalidate the campaign's other cells.
    return 0 if formal else 1


def print_campaign(document: dict[str, object]) -> None:
    """The human-readable report: the three layers first, then numbers, then what was withheld."""
    layer = document["layer"]
    print(f"## 内存测量结果 — {document['directory']}")
    print()
    print("**证据分层**（三层各自独立，任一层不成立就不输出正式判定）")
    print()
    print(f"- 样本数值有效：{'是' if layer['samples_valid'] else '否'}")
    print(f"- 输入可比：{'是' if layer['inputs_proven'] else '否'}")
    print(f"- 实际顺序有效：{'是' if layer['order_proven'] else '否'}")
    print(f"- 正式对照：{'可用' if layer['formally_comparable'] and not layer['diagnostic'] else '不可用'}"
          f"{'（诊断模式）' if layer['diagnostic'] else ''}")
    print()
    print("| 规则集 | 版本 | 批数 | 各批中位数（kB） | 批间中位数 | MiB | 批间极差（MiB） | 门槛 |")
    print("|---|---|---:|---|---:|---:|---:|---|")
    verdicts = {(row["build"], row["rule_set"]): row["verdict"] for row in document["threshold"]}
    for row in document["cells"]:
        centre = f"{row['centre_kb']:.1f}" if row["centre_kb"] is not None else "—"
        mib = f"{row['centre_mib']:.9f}" if row["centre_mib"] is not None else "—"
        spread = (f"{row['between_batch_range_mib']:.6f}"
                  if row["between_batch_range_mib"] is not None else "—")
        mark = verdicts.get((row["build"], row["rule_set"]), "无门槛")
        print(f"| {row['rule_set']} | {row['build']} | {row['ok_batches']}/{row['batches']} | "
              f"{', '.join(f'{value:.1f}' for value in row['batches_kb']) or '—'} | {centre} | "
              f"{mib} | {spread} | {mark} |")
    print()
    if document["comparisons"]:
        print("### 版本对照（描述，不判定方向）")
        print()
        for verdict in document["comparisons"]:
            print(f"- {verdict['rule_set']}: {verdict['left']} {verdict['left_mib']:.6f} MiB vs "
                  f"{verdict['right']} {verdict['right_mib']:.6f} MiB，差 "
                  f"{verdict['difference_mib']:+.6f} MiB；各批间极差 "
                  f"{verdict['left_range_mib']:.6f} / {verdict['right_range_mib']:.6f} MiB")
    if document["comparisons_withheld"]:
        print()
        print("### 未输出的版本对照")
        print()
        for entry in document["comparisons_withheld"]:
            print(f"- {entry['rule_set']}：{entry['reason']}")
            values = entry.get("diagnostic_values") or {}
            if values.get("left_mib") is not None:
                print(f"  （诊断数值：{values['left_mib']:.6f} / {values['right_mib']:.6f} MiB，"
                      f"仅供参考，不是对照结论）")
    if document["executed_order"]:
        print()
        print("### 实际执行顺序（由每次尝试的开始时间得出）")
        print()
        print(", ".join(f"{build}/{rule_set}/b{index}"
                        for build, rule_set, index in document["executed_order"]))
    for title, key in (("作废与问题", "problems"), ("输入证据缺失", "input_problems"),
                       ("顺序/时间证据缺失", "order_problems")):
        if document[key]:
            print()
            print(f"### {title}")
            print()
            for problem in document[key]:
                print(f"- {problem}")


# ---------------------------------------------------------------------------------------------
# Entries
# ---------------------------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run every batch of a plan against the phone")
    run.add_argument("--plan", required=True, type=Path)
    run.add_argument("--out", required=True, type=Path)
    run.add_argument("--issue", default="MYS-2840")
    run.add_argument("--serial", default=None,
                     help="adb serial; defaults to $SERIAL, else the only attached device")
    run.add_argument("--package", default=DEFAULT_PACKAGE)

    recompute = sub.add_parser("recompute", help="re-derive a finished campaign without a device")
    recompute.add_argument("directory", type=Path)
    recompute.add_argument("--json", action="store_true")

    check = sub.add_parser("plan-check", help="validate a plan without running anything")
    check.add_argument("--plan", required=True, type=Path)

    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "plan-check":
            plan = load_plan(arguments.plan)
            print(f"plan ok: {len(plan.builds)} builds × {len(plan.rule_sets)} rule sets × "
                  f"{plan.batches} batches = {len(plan.order())} batches of {plan.samples} samples")
            for build_name, rule_set, index in plan.order():
                print(f"  {build_name}/{rule_set}/b{index}")
            return 0
        if arguments.command == "run":
            plan = load_plan(arguments.plan)
            # The serial is resolved *lazily*, inside `run_campaign`, and only after that function's
            # own refusal: while the transaction is gated off, `run` must reach its explanation
            # without contacting anything — resolving here would run `adb devices` first and turn a
            # documented refusal into a device error.
            return run_campaign(plan, arguments.out, arguments.issue,
                                device_serial.serial_from, arguments.package)
        campaign = load_campaign(arguments.directory)
        return report(campaign, arguments.json)
    except PlanError as error:
        print(f"plan/evidence error: {error}", file=sys.stderr)
        return 2
    except CampaignError as error:
        print(f"campaign error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
