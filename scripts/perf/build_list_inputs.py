#!/usr/bin/env python3
"""Build the full-list inputs for the MYS-2826 comparison.

The app compiles nine lists by default. The historical PSS baseline (`docs/EFFECTIVENESS.md` §13.8) is
the first five of them. This script concatenates each set into one file — which is what the app's
compiler effectively produces, an ordered union — and writes a manifest of the individual files'
identity so a reader can check that the union was made from the lists it names.

The catalog snapshot itself is not in git (`.effectiveness/` is ignored: 68 MB of lists would be stale
the next day). The manifest this writes **is** the record of exactly which bytes were used, and the
runner copies it next to the results.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

# The nine lists the catalog enables, in the order the app compiles them (`app/src/main/assets/filters/
# catalog.json`, `defaultEnabled`). The first five are the historical fixed baseline set.
DEFAULT_ORDER = [
    "adguard-base",
    "adguard-tracking",
    "adguard-mobile",
    "adguard-url-tracking",
    "adguard-chinese",
    "adguard-dns",
    "easylist-china",
    "ublock-unbreak",
    "ublock-quick-fixes",
]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lists", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    arguments = parser.parse_args()

    manifest = {"default_order": DEFAULT_ORDER, "sets": {}}
    for tag, count in (("full-5", 5), ("full-9", 9)):
        selected = DEFAULT_ORDER[:count]
        parts = []
        entries = []
        for identifier in selected:
            path = arguments.lists / f"{identifier}.txt"
            if not path.is_file():
                raise SystemExit(f"missing list {path}")
            data = path.read_bytes()
            entries.append({
                "id": identifier,
                "bytes": len(data),
                "lines": data.count(b"\n"),
                "sha256": sha256(data),
            })
            # A separator line makes the union's own hash depend on the set's composition, so two
            # different compositions can never collide on the same union hash.
            parts.append(f"! ==== {identifier} ====\n".encode() + data)
        union = b"".join(parts)
        directory = arguments.out / tag
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "union.txt").write_bytes(union)
        manifest["sets"][tag] = {
            "lists": entries,
            "union_bytes": len(union),
            "union_lines": union.count(b"\n"),
            "union_sha256": sha256(union),
        }
        print(f"{tag}: {count} lists, {len(union)} B, sha256 {manifest['sets'][tag]['union_sha256']}")

    (arguments.out / "list-inputs.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
