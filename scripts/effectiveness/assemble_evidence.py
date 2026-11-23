#!/usr/bin/env python3
"""Assemble a self-describing evidence bundle and its MANIFEST.sha256 — strictly offline.

Why a tool and not a `tar` line
-------------------------------
The task card asks for a bundle a reviewer can check **without the phone**, and the first delivery
had none — it referred to `<campaign-dir>`, which nobody else can resolve. A bundle is only worth
attaching if these hold, so each is a step here rather than an assumption:

1. **nothing sensitive leaves.** The app's private key, the CA private key and the release keystore
   are named explicitly and refused if they appear. "We did not include them" is checked, not
   promised.
2. **every file the bundle claims is listed** with its SHA-256, and the manifest itself is verifiable
   with `sha256sum -c`.
3. **the recompute runs from a path inside the bundle.** The bundle carries a relative-path command
   that works after `tar x`, so a reviewer does not have to guess where the campaign lived.

Why it does not touch the phone
-------------------------------
The previous revision called `adb shell` during assembly to describe the device's state (lock, VPN,
logcat size, leftover XML). That is wrong in kind, not just in detail: assembly is an offline
operation over files another process already produced, and a bundling step that reaches for a phone
(a) can report a *different* device than the one measured, (b) can fail for reasons that have nothing
to do with the evidence, and (c) invites reading a transient `adb` error as "no lock present, VPN
off". So the device state is not observed here. It is **read** from a cleanup/state record the run
wrote (`--state`), and when no record is supplied the bundle says `unknown` and keeps the reason —
which is the honest outcome, not a silent omission.

What it deliberately does not do
--------------------------------
It does not decide whether the evidence is any good. That is `memory_profile.py recompute`'s job,
and the bundle's README says so: a manifest proves the bytes did not change in transit, not that
they mean anything. Integrity is not validity, and this tool only ever establishes the former.

Usage:
    assemble_evidence.py --campaign DIR --out BUNDLE.tar.gz \\
        [--state STATE.json] [--host PATH ...] [--command 'CMD=exit:0' ...]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tarfile
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent

#: Names that must never enter a bundle (docs/TESTING.md §"release 签名").
FORBIDDEN = (
    "release.jks",
    "keystore.properties",
    "ca.key",
    "zshield-ca.key",
    "id_rsa",
    "id_ed25519",
    "zshield-release.keystore",
)

#: What a bundle always carries besides the campaign itself.
README = """# ZShield 内存归因证据包（离线装配）

## 这是什么

一份 `memory_profile.py` 跑完后留下的原始证据：计划、每批结果、每批的 `dumpsys meminfo`
原文、日志边界、APK 前后哈希，以及调用方提供的设备清理/状态记录。

## 重要：完整性不等于有效性

`MANIFEST.sha256` 只证明这些字节在传输中没有变化，**不证明内容有效**。内容是否构成验收证据，
由 `memory_profile.py recompute` 判定，它会把「样本数值有效 / 输入可比 / 实际顺序有效 / 门槛结果」
四件事分开报告，任何一层不成立就不输出正式判定，并**非零退出**。

## 怎么复核（无需手机、无需 adb）

在本目录解开后执行：

    python3 scripts/effectiveness/memory_profile.py recompute campaign

校验文件完整性：

    sha256sum -c MANIFEST.sha256

## 设备状态从哪来

本包**不**在装配时连接手机。清理/状态来自调用方用 `--state` 提供的记录文件，原样收进
`state/`；未提供时 `provenance.json.device_state` 为 `unknown` 并写明原因。因此：

- `device_state.available = false` 表示「装配时没有拿到状态记录」，**不代表**「锁不在、VPN 已关」；
- 不要从本包推断设备当前状态，只按记录里写的内容引用。

## 外部命令记录

装配过程中执行过的每一条外部命令（实际命令行与退出码）都记在
`provenance.json.commands`。本工具自身不调用 `adb`；`commands` 为空是正常结果。

## 包内结构

    campaign/            本次实际执行的计划、逐批 outcome 与执行顺序
    host/                宿主归因与 trim 实验的输入哈希与输出（可选）
    state/               调用方提供的清理/状态记录原文（可选）
    scripts/effectiveness/memory_profile.py   复核用的工具
    provenance.json      装配时间、工具哈希、命令、设备状态来源
"""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def refuse_secrets(root: Path) -> None:
    """Fail if anything in `root` is on the forbidden list, at any depth."""
    found = [str(path.relative_to(root)) for path in root.rglob("*")
             if path.is_file() and path.name in FORBIDDEN]
    if found:
        raise SystemExit("refusing to bundle: these look like secrets: " + ", ".join(sorted(found)))


def copy_tree(source: Path, target: Path) -> list[Path]:
    """Copy `source` under `target`, returning the files written."""
    written: list[Path] = []
    for path in sorted(source.rglob("*")):
        if not path.is_file():
            continue
        destination = target / path.relative_to(source)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(path.read_bytes())
        written.append(destination)
    return written


def device_state(record: Path | None) -> dict:
    """The device cleanup/state, **read** from a record — never observed during assembly.

    A bundling step cannot honestly describe the phone: it may be a different device from the one
    measured, and an `adb` failure would be indistinguishable from a real state. So this reads what
    the run wrote and, when there is nothing to read, says so with the reason. `available: false`
    is an absence of evidence about the device, never evidence that the lock is free or the VPN off.
    """
    if record is None:
        return {
            "available": False,
            "reason": ("no --state record was supplied at assembly time; this bundle neither "
                       "connects to the phone nor infers device state from adb errors. Absence "
                       "here does not mean the lock is free or the VPN is off"),
            "source": None,
        }
    if not record.is_file():
        return {
            "available": False,
            "reason": f"--state {record} does not exist; no device state was read",
            "source": str(record),
        }
    try:
        document = json.loads(record.read_text(encoding="utf-8"))
    except ValueError as error:
        return {
            "available": False,
            "reason": f"--state {record} is not readable JSON ({error}); it was not interpreted",
            "source": str(record),
        }
    return {
        "available": True,
        "source": record.name,
        "sha256": sha256(record),
        "recorded": document,
        "note": ("read from the caller's record; it describes the device as that record states, "
                 "which this tool did not verify"),
    }


def parse_command(spec: str) -> dict:
    """`--command 'CMD=exit:0'` → `{command, exit}`.

    The card requires the assembly to record every external command it ran with its exit code. This
    tool runs none, so the list is normally empty; the flag exists so a caller that *did* run a
    preparation step outside this tool can record it in the same place, rather than leaving the
    provenance silent about how the campaign directory came to exist.
    """
    command, separator, tail = spec.rpartition("=")
    if not separator or not command:
        raise SystemExit(f"--command must look like 'CMD=exit:0', got {spec!r}")
    if not tail.startswith("exit:"):
        raise SystemExit(f"--command must end with =exit:<code>, got {spec!r}")
    try:
        code = int(tail[len("exit:"):])
    except ValueError:
        raise SystemExit(f"--command's exit code must be an integer, got {spec!r}") from None
    return {"command": command, "exit": code}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--campaign", required=True, type=Path,
                        help="the directory `memory_profile.py run --out` wrote")
    parser.add_argument("--out", required=True, type=Path, help="the .tar.gz to write")
    parser.add_argument("--host", type=Path, action="append", default=[],
                        help="host profile output to include (repeatable)")
    parser.add_argument("--state", type=Path, default=None,
                        help="a cleanup/state record to include and cite (never read from the "
                             "phone by this tool)")
    parser.add_argument("--command", action="append", default=[], metavar="CMD=exit:N",
                        help="record an external command and its exit code in provenance.json "
                             "(repeatable). This tool runs no external command itself")
    arguments = parser.parse_args(argv)

    if not (arguments.campaign / "campaign.json").is_file():
        raise SystemExit(f"{arguments.campaign}: not a campaign directory (no campaign.json)")

    commands = [parse_command(spec) for spec in arguments.command]
    state = device_state(arguments.state)

    arguments.out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".bundle-", dir=arguments.out.parent) as name:
        staging = Path(name)
        (staging / "campaign").mkdir()
        copy_tree(arguments.campaign, staging / "campaign")
        for extra in arguments.host:
            if extra.is_dir():
                copy_tree(extra, staging / "host")
            elif extra.is_file():
                (staging / "host").mkdir(exist_ok=True)
                (staging / "host" / extra.name).write_bytes(extra.read_bytes())
        if arguments.state is not None and arguments.state.is_file():
            (staging / "state").mkdir(exist_ok=True)
            (staging / "state" / arguments.state.name).write_bytes(arguments.state.read_bytes())

        # The tool the reviewer runs, so the bundle is self-contained. `assemble_evidence.py` is not
        # copied: it is the producer, not part of what a reviewer needs to re-derive the numbers.
        (staging / "scripts" / "effectiveness").mkdir(parents=True)
        for tool in ("memory_profile.py",):
            source = HERE / tool
            if source.is_file():
                (staging / "scripts" / "effectiveness" / tool).write_bytes(source.read_bytes())

        (staging / "README.md").write_text(README, encoding="utf-8")
        provenance = {
            "assembled_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "issue": "MYS-2840",
            "campaign": arguments.campaign.name,
            "tool_sha256": sha256(HERE / "memory_profile.py"),
            "assembler_sha256": sha256(Path(__file__).resolve()),
            "recompute_command":
                "python3 scripts/effectiveness/memory_profile.py recompute campaign",
            "verbatim_command": "assemble_evidence.py " + " ".join(argv),
            "device_contact": "none — assembly is offline and makes no adb call",
            "device_state": state,
            "commands": commands,
            "host_inputs": [path.name for path in arguments.host],
        }
        (staging / "provenance.json").write_text(
            json.dumps(provenance, indent=2, ensure_ascii=False), encoding="utf-8")

        refuse_secrets(staging)

        manifest: list[str] = []
        for path in sorted(staging.rglob("*")):
            if path.is_file() and path.name != "MANIFEST.sha256":
                manifest.append(f"{sha256(path)}  {path.relative_to(staging).as_posix()}")
        (staging / "MANIFEST.sha256").write_text("\n".join(manifest) + "\n", encoding="utf-8")

        with tarfile.open(arguments.out, "w:gz") as archive:
            for path in sorted(staging.iterdir()):
                archive.add(path, arcname=path.name)

    print(f"bundle: {arguments.out} ({arguments.out.stat().st_size} B, {len(manifest)} files)")
    print(f"device state: {'read from ' + str(arguments.state) if state['available'] else 'unknown'}")
    print("verify: tar xzf the bundle && (cd it && sha256sum -c MANIFEST.sha256)")
    print("recompute: python3 scripts/effectiveness/memory_profile.py recompute campaign")
    print("note: a verified manifest proves the bytes are intact, not that the evidence is valid")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
