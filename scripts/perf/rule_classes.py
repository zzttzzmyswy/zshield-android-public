#!/usr/bin/env python3
"""Classify a set of filter lists by how `RemoveParamRules` evaluates each rule.

The point is to make §6.5 of `docs/reviews/i2-edits-cost.md` checkable: the claim is that the
candidate's cost comes from the `by_value` side (rules with no name index, or a pattern that is not
the `||host^` shortcut), and that is only credible if the classification is reproducible.

The categories mirror `core/src/https/extras.rs`:

  * `host-shortcut`  — pattern is exactly `||host^` and no other option survives stripping. `build()`
    puts it in `by_host`, and `in_force` decides it by hostname comparison (`Scope::Host`), no engine.
  * `by-name`        — the matcher's `only_name()` is `Some`, so `build()` indexes it by parameter
    name. A request that does not carry the name never looks at it.
  * `by-value`       — a regex, an inversion, or the bare form: `only_name()` is `None`, so it lands in
    `by_value` and `in_force` walks it on every request.

and separately notes whether the rule's stripped form is unanchored (`pattern_anchor` returns `None`),
because an unanchored `Scope::Engine` form admits every host and therefore reaches its engine query.

This is a *classification*, not a measurement: it says how many rules sit in each bucket. The cost of a
bucket is measured by `edits_cost_matrix` / `removeparam_rule_shapes`, not here.
"""

from __future__ import annotations

import argparse
import collections
import json
import re
from pathlib import Path

# `CONTENT_TYPES` in extras.rs, plus the aliases the engine canonicalises.
CONTENT_TYPES = {
    "script", "stylesheet", "image", "media", "font", "xmlhttprequest", "websocket", "ping",
    "object", "document", "subdocument", "other", "all",
}


def classify(line: str) -> dict | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("!") or stripped.startswith("["):
        return None
    if stripped.startswith("#"):
        return None
    body = stripped[2:] if stripped.startswith("@@") else stripped
    exception = stripped.startswith("@@")
    if "$" not in body:
        return None
    pattern, _, options_text = body.partition("$")
    options = [option.strip() for option in options_text.split(",") if option.strip()]
    removeparam = [
        option for option in options
        if option == "removeparam" or option.startswith("removeparam=")
    ]
    if not removeparam:
        return None
    others = [option for option in options if option not in removeparam]
    typed = any(option.lstrip("~") in CONTENT_TYPES for option in others)
    value = removeparam[0].partition("=")[2].strip()
    value_dependent = (not value) or value.startswith("/") or value.startswith("~")

    if not value_dependent and re.fullmatch(r"\|\|[A-Za-z0-9.\-]+\^", pattern) and not others:
        bucket = "host-shortcut"
    elif not value_dependent:
        bucket = "by-name"
    else:
        bucket = "by-value"

    # Does the stripped form carry a `||` host anchor? `pattern_anchor` returns `None` when there is no
    # `||` prefix or the host part holds a `*`, and such a form admits every host.
    anchored = pattern.startswith("||") and "*" not in pattern[2:].split("/")[0].split("^")[0]

    return {
        "bucket": bucket,
        "exception": exception,
        "typed": typed,
        "value_dependent": value_dependent,
        "anchored": anchored,
        "badfilter": "badfilter" in options,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("lists", nargs="+", type=Path,
                        help="list files, or a single union file")
    parser.add_argument("--json", action="store_true")
    arguments = parser.parse_args()

    buckets: collections.Counter = collections.Counter()
    typed: collections.Counter = collections.Counter()
    anchored: collections.Counter = collections.Counter()
    exceptions = 0
    total = 0
    for path in arguments.lists:
        for line in path.read_text(errors="replace").splitlines():
            record = classify(line)
            if record is None:
                continue
            total += 1
            buckets[record["bucket"]] += 1
            typed[(record["bucket"], record["typed"])] += 1
            anchored[(record["bucket"], record["anchored"])] += 1
            exceptions += 1 if record["exception"] else 0

    summary = {
        "files": [str(path) for path in arguments.lists],
        "total_removeparam_lines": total,
        "buckets": dict(buckets),
        "typed": {f"{key[0]}/{'typed' if key[1] else 'untyped'}": value
                  for key, value in typed.items()},
        "anchored": {f"{key[0]}/{'anchored' if key[1] else 'unanchored'}": value
                     for key, value in anchored.items()},
        "exceptions": exceptions,
        "by_value_unanchored": anchored[("by-value", False)] + typed.get(("by-value", False), 0) * 0,
    }
    if arguments.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    print(f"{total} $removeparam lines in {len(arguments.lists)} file(s), {exceptions} exceptions")
    print("\nbucket（`RemoveParamRules::build` 会把它放进哪个索引）：")
    for bucket in ("host-shortcut", "by-name", "by-value"):
        print(f"  {bucket:16}{buckets[bucket]:>6}   "
              f"typed {typed[(bucket, True)]:>4} / untyped {typed[(bucket, False)]:>5}   "
              f"锚定 {anchored[(bucket, True)]:>4} / 无锚 {anchored[(bucket, False)]:>4}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
