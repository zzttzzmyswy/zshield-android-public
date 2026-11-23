#!/usr/bin/env python3
"""Build one formally acceptable campaign on disk — the valid reference fixture.

Why this file exists
--------------------
The strict time/input schema made the older positive fixtures fail for reasons unrelated to the rule
under test: they were written as *probes* (short matrices, no attempt records, no input proofs), so
after the schema tightened they stopped reaching the judged criterion at all. A reviewer then cannot
tell "the rule rejects this" from "the fixture never got far enough to be judged". This script
produces the opposite: a campaign built to be genuinely acceptable, so a rejection elsewhere means
something.

Usage:
    build_formal_fixture.py OUTDIR [--recompute]

    默认只生成目录；`--recompute` 会就地跑一次 `recompute --json` 并把结果打印出来。

What it writes (all of it required by the offline contract):
    OUTDIR/campaign.json                  plan + per-attempt records + input proofs
    OUTDIR/<rule_set>--<build>--b<N>/     one batch per cell slot
        result.txt                        header `at=`/`interval=`, six rows 60 s apart, median
        pss-*.raw/meminfo-N.txt           one raw device answer per sample
        apk-sha256-{before,after}.txt     the build the phone ran

Exit status is 0 when the campaign was written and, with `--recompute`, when `recompute` accepts it
as formal evidence. The numbers are synthetic — this fixture is about the *shape* of evidence, and
`provenance.md` in the output says so in the bundle's own words.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent / "memory_profile.py"

APK_CANDIDATE = "a" * 64
APK_V012 = "b" * 64
TOKEN = "sha256:" + "1" * 64 + ":1000"
IDENTITY = f"dns={TOKEN} engine={TOKEN} extras={TOKEN}"

FIXED_FIVE = ("adguard-base", "adguard-tracking", "adguard-mobile", "adguard-url-tracking",
              "adguard-chinese")
DEFAULT_NINE = FIXED_FIVE + ("adguard-dns", "easylist-china", "ublock-unbreak",
                             "ublock-quick-fixes")

#: Per-cell sample values. The fixed-five candidate cell is deliberately over 84.6 MiB (86.9 MiB),
#: so the fixture also exercises a real FAIL rather than a vacuous PASS.
VALUES = {("fixed-five", "candidate"): 89000, ("fixed-five", "v012"): 88500,
          ("default-nine", "candidate"): 99000, ("default-nine", "v012"): 98500}


def starts() -> dict[tuple[str, str, int], str]:
    """Batch start stamps: alternating builds, ten minutes apart, no overlap."""
    table: dict[tuple[str, str, int], str] = {}
    for rule_set, hour in (("fixed-five", 0), ("default-nine", 2)):
        for index in range(1, 4):
            table[("candidate", rule_set, index)] = f"2026-11-13T{hour:02d}:{(index - 1) * 20:02d}:00Z"
            table[("v012", rule_set, index)] = (
                f"2026-11-13T{hour:02d}:{(index - 1) * 20 + 10:02d}:00Z")
    return table


def input_record(lists: tuple[str, ...], apk: str) -> dict:
    """What the phone held while this cell ran: content hashes, enabled state, artifacts."""
    return {
        "lists": [{"id": name, "enabled": True,
                   "sha256": hashlib.sha256(name.encode()).hexdigest()} for name in lists],
        "user_rules_sha256": hashlib.sha256(b"user rules").hexdigest(),
        "allowlist_sha256": hashlib.sha256(b"").hexdigest(),
        "apk_sha256": apk,
        "loaded_artifacts_sha256": {"dns": TOKEN, "engine": TOKEN, "extras": TOKEN},
    }


def write_batch(root: Path, rule_set: str, build: str, index: int, value: int, started: str,
                apk: str) -> Path:
    directory = root / f"{rule_set}--{build}--b{index}"
    raw = directory / f"pss-{rule_set}-{build}-b{index}.raw"
    raw.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# idle PSS — label={rule_set}-{build}-b{index} at={started}",
        f"# serial=stub-device package=top.zztweb.zshield samples=6 interval=60s "
        f"owner=MYS-2840",
        f"# effective rule content: {IDENTITY}",
        "# index\telapsed_s\ttotal_pss_kb\tjava_kb\tnative_kb\tpid\tgeneration\thandle",
    ]
    for offset in range(1, 7):
        lines.append(f"{offset}\t{(offset - 1) * 60}\t{value + offset}\t5336\t60640\t4242\t1\t1")
        (raw / f"meminfo-{offset}.txt").write_text(
            "Applications Memory Usage (in Kilobytes):\n\n"
            "** MEMINFO in pid 4242 [top.zztweb.zshield] **\n"
            "      Native Heap:    60640\n"
            "        Java Heap:     5336\n"
            f"        TOTAL PSS:    {value + offset}            TOTAL RSS:   120000\n",
            encoding="utf-8")
    samples = [value + offset for offset in range(1, 7)]
    median = statistics.median(samples)
    exact = f"{int(median)}" if float(median).is_integer() else f"{median:.1f}"
    lines.append(f"## median {exact} kB = {median / 1024:.9f} MiB "
                 f"(min {min(samples)} kB, max {max(samples)} kB)")
    (directory / "result.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    for name in ("apk-sha256-before.txt", "apk-sha256-after.txt"):
        (directory / name).write_text(f"{apk}  top.zztweb.zshield\n", encoding="utf-8")
    return directory


def build(root: Path) -> Path:
    import datetime

    root.mkdir(parents=True, exist_ok=True)
    table = starts()
    order: list[list[object]] = []
    for rule_set, hour in (("fixed-five", 0), ("default-nine", 2)):
        for index in range(1, 4):
            order.append(["candidate", rule_set, index])
            order.append(["v012", rule_set, index])
    record: dict = {
        "plan": {
            "builds": {
                "candidate": {"apk_sha256": APK_CANDIDATE, "apk_path": "/tmp/candidate.apk",
                              "legacy": False,
                              "identities": {"fixed-five": IDENTITY, "default-nine": IDENTITY}},
                "v012": {"apk_sha256": APK_V012, "apk_path": "/tmp/v012.apk", "legacy": False,
                         "identities": {"fixed-five": IDENTITY, "default-nine": IDENTITY}},
            },
            "rule_sets": {"fixed-five": list(FIXED_FIVE), "default-nine": list(DEFAULT_NINE)},
            "batches": 3, "samples": 6, "interval": 60, "diagnostic": False, "select": "ui",
            "inputs": {},
        },
        "order": order,
        "batches": [],
        "attempts": [],
    }
    for build_name, apk in (("candidate", APK_CANDIDATE), ("v012", APK_V012)):
        for rule_set, lists in (("fixed-five", FIXED_FIVE), ("default-nine", DEFAULT_NINE)):
            record["plan"]["inputs"][f"{build_name}/{rule_set}"] = input_record(lists, apk)
    for position, (build_name, rule_set, index) in enumerate(order):
        started = table[(build_name, rule_set, index)]
        finished = (_stamp(started) + datetime.timedelta(minutes=8)).strftime("%Y-%m-%dT%H:%M:%SZ")
        record["attempts"].append({
            "attempt_id": f"a{position + 1:03d}-{build_name}-{rule_set}-b{index}",
            "cell": [build_name, rule_set], "index": index, "outcome": "ok",
            "started_at": started, "finished_at": finished,
            "directory": f"{rule_set}--{build_name}--b{index}",
        })
        record["batches"].append({"cell": [build_name, rule_set], "index": index,
                                  "outcome": "ok", "reason": None})
        write_batch(root, rule_set, build_name, index,
                    VALUES[(rule_set, build_name)],
                    started, APK_CANDIDATE if build_name == "candidate" else APK_V012)
    (root / "campaign.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    (root / "provenance.md").write_text(
        "# 这个夹具是什么\n\n"
        "一份**构造出来的**正式证据，用于验证 `recompute` 的判据本身：\n\n"
        "- 样本数值是合成的（固定五表候选 89 001 kB ≈ 86.9 MiB，故意高于 84.6 MiB 门槛）；\n"
        "- 只有“证据形状”是真实的：两版×五/九表×3 批、逐次尝试的开始/结束时间、\n"
        "  每格输入记录、每批 `interval=60s` 且样本间隔 60 s、构建真正交替、无重叠。\n\n"
        "它**不是**设备测量结果，不能引用为 ZShield 的内存数据。\n", encoding="utf-8")
    return root


def _stamp(value: str):
    import datetime
    return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("out", type=Path, help="the campaign directory to create")
    parser.add_argument("--recompute", action="store_true",
                        help="run the offline recompute against what was written")
    arguments = parser.parse_args(argv)

    if (arguments.out / "campaign.json").exists():
        raise SystemExit(f"{arguments.out} already holds a campaign; refusing to overwrite")
    build(arguments.out)
    print(f"wrote a formal campaign to {arguments.out} (12 batches, synthetic values)")
    if not arguments.recompute:
        return 0
    result = subprocess.run([sys.executable, str(TOOL), "recompute", str(arguments.out), "--json"],
                            capture_output=True, text=True)
    print(result.stdout.rstrip())
    if result.stderr.strip():
        print(result.stderr.rstrip(), file=sys.stderr)
    document = json.loads(result.stdout) if result.stdout.lstrip().startswith("{") else {}
    layer = document.get("layer") or {}
    print(f"exit={result.returncode} formally_comparable={layer.get('formally_comparable')} "
          f"comparisons={len(document.get('comparisons') or [])}", file=sys.stderr)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
