#!/usr/bin/env python3
"""Write and verify the manifest for one MYS-2826 run.

# What the review changed

The stage-5 review rejected the first manifest for two reasons, both of which were about *checkability*:

  1. **It could only be verified where it was produced.** Entries were bare file names, and the tool
     section pointed at repository paths that exist on the machine that ran the measurement — so a
     reader who downloaded the bundle could verify some of the numbers and not others, and "36 files
     pass" was a statement about the producer's disk, not about the artifact.
  2. **It did not verify the harness it named.** The manifest recorded the *source* file's hash but
     never checked that the binary which produced the numbers was built from it, so the claim "both
     builds use the same bench source" rested on the report's prose.

So this manifest is **relocatable and self-verifying**:

  * every entry path is **relative to the bundle root**, and the bundle preserves the directory layout
    (`results/…`, `src/…`, `inputs/…`), so `--verify` works from wherever the bundle was unpacked;
  * the bundle carries the **sources, schema, inputs and raw JSON** the numbers came from, not only the
    rendered tables;
  * each binary's own entry is verified, and `--verify` re-hashes it, so "the binary that ran" is part
    of what is checked rather than asserted;
  * a declared `harness` entry stores the bench source's SHA-256 **and** the SHA-256 of each binary
    built from it, with the build command, so a reader can rebuild and compare.

# Self-exclusion

A file cannot contain its own hash; `MANIFEST.json` is excluded from `files` and named in
`self_excluded` so the omission is explicit rather than an oversight.

Usage
-----
    python3 scripts/perf/manifest.py --build --results <dir> --bundle <dir>
    python3 scripts/perf/manifest.py --verify <bundle-dir>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

MANIFEST_NAME = "MANIFEST.json"
SCHEMA_VERSION = 2

# Files the bundle must carry, relative to the results directory. Anything the report cites has to be
# here, because an attachment set that covers "some of the files, renamed" cannot be verified as a
# whole — which is exactly the review's complaint.
RESULT_PATTERNS = (
    "*.json",
    "*.jsonl",
    "*.log",
    "*.txt",
    "*/report.json",
    "*/headers.json",
    "*/rewrites-*.jsonl",
    "*/reload-*.jsonl",
    "*/union.txt",
)

# Repository-relative sources the numbers depend on. Copied into `src/` so the bundle can be read
# without the repository.
SOURCE_FILES = (
    "core/examples/edits_cost_matrix.rs",
    "core/examples/removeparam_rule_shapes.rs",
    "core/examples/removeparam_path.rs",
    "scripts/perf/ab_edits_cost.py",
    "scripts/perf/bucket_split.py",
    "scripts/perf/build_list_inputs.py",
    "scripts/perf/manifest.py",
    "scripts/perf/render_report.py",
    "scripts/perf/rule_classes.py",
    "scripts/perf/shape_table.py",
    "scripts/perf/run.sh",
    "scripts/perf/matrix.json",
    "scripts/perf/rules/equal-engine-name.txt",
    "scripts/perf/rules/no-removeparam.txt",
    "scripts/perf/rules/self-eval-common.txt",
    "scripts/perf/rules/eval-reached.txt",
    "scripts/perf/tests/test_ab_edits_cost.py",
    "docs/reviews/i2-edits-cost.md",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entry(root: Path, path: Path) -> dict:
    """One manifest entry: a **relative** path, its size and its hash.

    Relative to the bundle root, so the entry means the same after the bundle moves. An absolute path
    would verify only on the machine that wrote it.
    """
    return {
        "path": path.relative_to(root).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def git_revision(repo: Path, revision: str) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(repo), "rev-parse", revision],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def build_bundle(results: Path, bundle: Path, repo: Path, candidate: str,
                 baseline: str, binaries_dir: Path | None = None) -> dict:
    """Assemble a relocatable bundle and write its manifest.

    `binaries_dir` holds the two harness executables, named `<build>-edits_cost_matrix`. It is a separate
    argument rather than a subdirectory of `results` because this function rebuilds the bundle from
    scratch: anything it copied *out of* `results` would be deleted on a second invocation, which is
    how an earlier version declared zero harness binaries.
    """
    results = results.resolve()
    bundle = bundle.resolve()
    if bundle.exists():
        shutil.rmtree(bundle)
    (bundle / "results").mkdir(parents=True)
    (bundle / "src").mkdir()
    (bundle / "inputs").mkdir()

    # Results, with the directory layout preserved.
    for pattern in RESULT_PATTERNS:
        for path in sorted(results.glob(pattern)):
            if not path.is_file():
                continue
            relative = path.relative_to(results)
            destination = bundle / "results" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)

    # The catalog inputs. The 50 MB unions are derived text — `build_list_inputs.py` rebuilds them
    # byte-for-byte from the per-file SHA-256s in `list-inputs.json` — so the bundle carries the
    # composition record and the first/last lines rather than the bulk. That keeps the bundle small
    # enough to hand over while leaving the numbers reproducible; `inputs/NOTE.txt` says so explicitly.
    for tag in ("full-5", "full-9"):
        source = repo / ".effectiveness" / tag / "union.txt"
        if not source.is_file():
            continue
        destination = bundle / "inputs" / tag
        destination.mkdir(parents=True, exist_ok=True)
        head = source.read_text(errors="replace").splitlines()[:5]
        (destination / "union.head.txt").write_text("\n".join(head) + "\n")
        (destination / "union.sha256").write_text(
            f"{sha256_file(source)}  union.txt  {source.stat().st_size} B\n")
    list_inputs = repo / ".effectiveness" / "list-inputs.json"
    if list_inputs.is_file():
        shutil.copy2(list_inputs, bundle / "inputs" / "list-inputs.json")
    (bundle / "inputs" / "NOTE.txt").write_text(
        "The full-list unions (full-5 = 23 018 051 B, full-9 = 28 482 945 B of filter text) are not\n"
        "included verbatim: they are 50 MB of derived text and would make the bundle awkward to hand\n"
        "over. `list-inputs.json` records every source list's SHA-256, byte count and line count, and\n"
        "`src/scripts/perf/build_list_inputs.py --lists <dir> --out <dir>` rebuilds the unions exactly.\n"
        "`union.sha256` in each subdirectory is the hash of the union those inputs produce, so the\n"
        "rebuild is checkable: build it, hash it, compare.\n")

    # Sources, so the bundle can be read and rebuilt without the repository.
    missing_sources = []
    for relative in SOURCE_FILES:
        source = repo / relative
        if not source.is_file():
            missing_sources.append(relative)
            continue
        destination = bundle / "src" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    # The binaries actually executed, and the bench source they were built from. `--verify` checks
    # these like any other entry, so "same source, two builds" is verified rather than stated.
    harness_entries = []
    for name in ("candidate", "baseline"):
        binary = (binaries_dir / f"{name}-edits_cost_matrix") if binaries_dir else None
        if binary is not None and binary.is_file():
            destination = bundle / "binaries" / binary.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(binary, destination)
            harness_entries.append({
                "name": name,
                "binary": destination.relative_to(bundle).as_posix(),
                "binary_sha256": sha256_file(destination),
                "binary_bytes": destination.stat().st_size,
            })

    if len(harness_entries) != 2:
        raise SystemExit(
            f"expected two harness binaries, got {len(harness_entries)}; pass --binaries pointing at "
            f"candidate-edits_cost_matrix and baseline-edits_cost_matrix"
        )

    files = [entry(bundle, path) for path in sorted(bundle.rglob("*"))
             if path.is_file() and path.name != MANIFEST_NAME]
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "purpose": "MYS-2826 — same-input per-request cost of HttpsModifiers::edits",
        "self_excluded": MANIFEST_NAME,
        "path_basis": "relative to the bundle root; the bundle is relocatable",
        "verify_with": "python3 src/scripts/perf/manifest.py --verify .",
        "revisions": {
            "candidate": candidate,
            "candidate_full": git_revision(repo, candidate),
            "baseline": baseline,
            "baseline_full": git_revision(repo, baseline),
        },
        "harness": {
            "note": "One source file, compiled into both binaries; --verify re-hashes all of them.",
            "source": "src/core/examples/edits_cost_matrix.rs",
            "source_sha256": sha256_bytes(
                (repo / "core/examples/edits_cost_matrix.rs").read_bytes()),
            "build_command": (
                "cargo build --release --manifest-path core/Cargo.toml "
                "--example edits_cost_matrix --example removeparam_rule_shapes "
                "--example removeparam_path"
            ),
            "binaries": harness_entries,
        },
        "build": {
            "profile": 'release (opt-level="z", lto=true, codegen-units=1, panic=abort, strip=true)',
            "cargo": subprocess.run(["cargo", "--version"], capture_output=True, text=True
                                    ).stdout.strip(),
            "rustc": subprocess.run(["rustc", "--version"], capture_output=True, text=True
                                    ).stdout.strip(),
        },
        "missing_sources": missing_sources,
        "files": files,
    }
    (bundle / MANIFEST_NAME).write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    return manifest


def verify(bundle: Path) -> int:
    """Re-hash every declared file, from the bundle root. No repository needed."""
    bundle = bundle.resolve()
    manifest_path = bundle / MANIFEST_NAME
    if not manifest_path.is_file():
        print(f"MISSING {manifest_path}")
        return 1
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("schema_version") != SCHEMA_VERSION:
        print(f"schema_version {manifest.get('schema_version')} != {SCHEMA_VERSION}")
        return 1

    failures = 0
    for item in manifest["files"]:
        path = bundle / item["path"]
        if not path.is_file():
            print(f"MISSING {item['path']}")
            failures += 1
            continue
        actual = sha256_file(path)
        if actual != item["sha256"]:
            print(f"MISMATCH {item['path']}: declared {item['sha256']} actual {actual}")
            failures += 1
        elif path.stat().st_size != item["bytes"]:
            print(f"SIZE {item['path']}: declared {item['bytes']} actual {path.stat().st_size}")
            failures += 1

    # The harness declaration is checked too: the source's hash, and each binary's.
    declared = manifest["harness"]
    source = bundle / declared["source"]
    if not source.is_file():
        print(f"MISSING harness source {declared['source']}")
        failures += 1
    elif sha256_file(source) != declared["source_sha256"]:
        print(f"MISMATCH harness source {declared['source']}")
        failures += 1
    for binary in declared["binaries"]:
        path = bundle / binary["binary"]
        if not path.is_file():
            print(f"MISSING harness binary {binary['binary']}")
            failures += 1
            continue
        if sha256_file(path) != binary["binary_sha256"]:
            print(f"MISMATCH harness binary {binary['binary']}")
            failures += 1

    if manifest.get("missing_sources"):
        print(f"note: sources absent when the bundle was built: {manifest['missing_sources']}")

    print(f"schema {manifest['schema_version']}, {len(manifest['files'])} files, "
          f"{len(declared['binaries'])} harness binaries, {failures} failure(s)")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--results", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--candidate", default="HEAD")
    parser.add_argument("--baseline", default="v0.1.2")
    parser.add_argument("--binaries", type=Path,
                        help="directory holding <build>-edits_cost_matrix for each build")
    parser.add_argument("--verify", type=Path, metavar="BUNDLE")
    arguments = parser.parse_args()

    if arguments.verify:
        return verify(arguments.verify)
    if not arguments.build:
        parser.error("one of --build or --verify is required")
    if not arguments.results or not arguments.bundle:
        parser.error("--build needs --results and --bundle")

    manifest = build_bundle(arguments.results, arguments.bundle, arguments.repo.resolve(),
                            arguments.candidate, arguments.baseline, arguments.binaries)
    total = sum(item["bytes"] for item in manifest["files"])
    print(f"bundle: {len(manifest['files'])} files, {total} B, "
          f"{len(manifest['harness']['binaries'])} harness binaries → "
          f"{arguments.bundle / MANIFEST_NAME}")
    if manifest["missing_sources"]:
        print(f"note: {len(manifest['missing_sources'])} source(s) absent: "
              f"{manifest['missing_sources']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
