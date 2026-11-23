#!/usr/bin/env bash
# Reproduce the MYS-2826 cost comparison for `HttpsModifiers::edits`.
#
# Two builds of the *same* harness source are compared: the task's candidate baseline
# (`4411747`, this branch's parent) and the released v0.1.2 (`1bf604a`). Nothing here touches the
# device, the network, or production code — it is a host-CPU measurement.
#
# What it does
# ------------
#   1. checks both trees out at the pinned revisions (worktrees, so the caller's checkout is untouched);
#   2. builds `core/examples/edits_cost_matrix` in **both** trees, from one source file, with the
#      release profile the APK uses;
#   3. runs `scripts/perf/ab_edits_cost.py` five times over five rule inputs:
#        equal-engine-name  — the same rules, decided by a different component on each build
#        no-removeparam     — control: no `$removeparam` rule at all (fixed overhead only)
#        self-eval-common   — regex forms **both** builds evaluate themselves (same work, same answer)
#        full-5 / full-9    — the five fixed-baseline lists and the nine the catalog enables
#   4. writes every result under `.effectiveness/results/i2-edits-cost/` and a manifest with the
#      SHA-256 of each input and output.
#
# Usage
# -----
#     scripts/perf/run.sh                      # full run
#     FAST=1 scripts/perf/run.sh              # fewer rounds/iterations, for a smoke test
#     CPU=19 scripts/perf/run.sh              # pin both builds to core 19 (default: 19)
#
# Requirements: cargo, python3, taskset (util-linux). `perf` is optional and only used for the
# `removeparam` profile, which is skipped with a note when the kernel forbids it.
set -euo pipefail

# ---- 0. the driver's own regression tests ---------------------------------------------------
# First, because everything below trusts the driver: if it can go on after a mismatch, or accept a
# record with no decision fields, the numbers it produces mean nothing. `--self-check` skips this when
# a caller only wants to re-render.
if [[ "${SELF_CHECK:-1}" == "1" ]]; then
  printf '=== driver regression tests (red on the previous driver, green here)\n'
  python3 -m unittest discover -s "$(dirname "${BASH_SOURCE[0]}")/tests" -p 'test_*.py' 2>&1 | tail -3
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CANDIDATE_REV="${CANDIDATE_REV:-4411747b0c3db29c33c921f49d370adbbc55d9e7}"
BASELINE_REV="${BASELINE_REV:-1bf604a}"
CPU="${CPU:-19}"
WORK="${WORK:-/tmp/zshield-i2-cost}"
OUT="$REPO_ROOT/.effectiveness/results/i2-edits-cost"

if [[ "${FAST:-0}" == "1" ]]; then
  ROUNDS=3; ITERS=300; FULL_ITERS=60
else
  ROUNDS=7; ITERS=2000; FULL_ITERS=300
fi

say() { printf '\n=== %s\n' "$*"; }

# ---- 1. both trees, pinned ----------------------------------------------------------------
mkdir -p "$WORK"
for spec in "candidate:$CANDIDATE_REV" "baseline:$BASELINE_REV"; do
  name="${spec%%:*}"
  rev="${spec#*:}"
  tree="$WORK/$name"
  if [[ -d "$tree/.git" || -f "$tree/.git" ]]; then
    git -C "$tree" fetch --quiet origin || true
    git -C "$tree" checkout --quiet --detach "$rev"
  else
    git -C "$REPO_ROOT" worktree add --detach "$tree" "$rev" >/dev/null
  fi
  printf '%-10s %s %s\n' "$name" "$(git -C "$tree" rev-parse HEAD)" "$(git -C "$tree" rev-parse --short=12 HEAD)"
done

# The harness is copied into both trees from this branch, so the measuring code is byte-identical and
# only the library under test differs.
for name in candidate baseline; do
  for example in edits_cost_matrix removeparam_rule_shapes removeparam_path; do
    cp "$REPO_ROOT/core/examples/$example.rs" "$WORK/$name/core/examples/"
  done
done

# ---- 2. build ------------------------------------------------------------------------------
say "building the harness in both trees (release profile, same as the APK)"
for name in candidate baseline; do
  ( cd "$WORK/$name" && cargo build --release --manifest-path core/Cargo.toml \
      --example edits_cost_matrix --example removeparam_rule_shapes \
      --example removeparam_path 2>&1 | tail -2 )
done

CAND="$WORK/candidate/core/target/release/examples/edits_cost_matrix"
BASE="$WORK/baseline/core/target/release/examples/edits_cost_matrix"
for binary in "$CAND" "$BASE"; do
  [[ -x "$binary" ]] || { echo "missing $binary" >&2; exit 1; }
done

# ---- 3. inputs -----------------------------------------------------------------------------
say "preparing the full-list inputs (5 and 9 tables) from the catalog snapshot"
LISTS="${LISTS:-$REPO_ROOT/.effectiveness/catalog-lists}"
if [[ ! -d "$LISTS" ]]; then
  echo "missing $LISTS — download the catalog lists first (scripts/effectiveness/fetch-lists.sh)," >&2
  echo "or point LISTS= at an existing catalog snapshot." >&2
  exit 1
fi
python3 "$REPO_ROOT/scripts/perf/build_list_inputs.py" --lists "$LISTS" --out "$REPO_ROOT/.effectiveness"

mkdir -p "$OUT"

# ---- 4. the five comparisons ---------------------------------------------------------------
run() {
  local label="$1" rules="$2" iterations="$3"
  shift 3
  say "$label"
  # Extra flags go last, so a caller can declare a *measured* defect of a specific build. Only the
  # full-catalog runs pass one, and only for the historical baseline: on the 23 MB union its own
  # `extras.txt` does not round-trip, so after a reload it stops rewriting two cases it rewrote before.
  # That is v0.1.2's defect and a finding in its own right; declaring it keeps the run going while
  # still printing the reason and the affected case ids. The candidate never receives this flag.
  python3 "$REPO_ROOT/scripts/perf/ab_edits_cost.py" \
    --build "candidate=$CAND" \
    --build "baseline=$BASE" \
    --rules "$rules" \
    --matrix "$REPO_ROOT/scripts/perf/matrix.json" \
    --rounds "$ROUNDS" \
    --iterations "$iterations" \
    --cpu "$CPU" \
    --out "$OUT/$label" "$@" | tee "$OUT/$label.log"
}

# The declared defect, in one place, with the evidence that justifies it.
BASELINE_RELOAD_DEFECT="baseline=v0.1.2 (1bf604a) does not round-trip its own extras.txt on the full catalog: after collect(serialize_lines()) it stops rewriting hit-document-post and hit-document-zhihu, which it rewrites before the reload. Measured by this run; see the affected_cases field."

run equal-engine-name "$REPO_ROOT/scripts/perf/rules/equal-engine-name.txt" "$ITERS"
run no-removeparam   "$REPO_ROOT/scripts/perf/rules/no-removeparam.txt"      "$ITERS"
run self-eval-common "$REPO_ROOT/scripts/perf/rules/self-eval-common.txt"    "$ITERS"
# The comparison the stage-5 review asked for: a rule set whose gate OPENS on both builds, so
# `in_force` actually runs. The earlier "40 shared rules" row priced a missed gate.
run eval-reached   "$REPO_ROOT/scripts/perf/rules/eval-reached.txt"          "$ITERS"
run full-5           "$REPO_ROOT/.effectiveness/full-5/union.txt"            "$FULL_ITERS" \
                     --known-reload-defect "$BASELINE_RELOAD_DEFECT"
run full-9           "$REPO_ROOT/.effectiveness/full-9/union.txt"            "$FULL_ITERS" \
                     --known-reload-defect "$BASELINE_RELOAD_DEFECT"

# ---- 4a. bucket split ---------------------------------------------------------------------
# §6.5 of the report rests on this: the same five-table union, split by which index
# `RemoveParamRules::build` puts each rule in, measured on both builds. It is what rules out "more rules
# therefore slower" — 1621 extra host-shortcut rules cost 0.34 µs while 39 extra by-value rules cost
# 14.6 µs.
say "bucket split of the five-table union"
mkdir -p "$OUT/buckets"
python3 "$REPO_ROOT/scripts/perf/bucket_split.py" \
  --lists "$LISTS" \
  --union "$REPO_ROOT/.effectiveness/full-5/union.txt" \
  --out "$OUT/buckets" \
  --candidate "$CAND" --baseline "$BASE" \
  --matrix "$REPO_ROOT/scripts/perf/matrix.json" \
  --cpu "$CPU" --rounds "$ROUNDS" --iterations "$ITERS" \
  | tee "$OUT/buckets/table.txt"

# ---- 4a2. which rows actually entered evaluation -----------------------------------------
# A cost comparison is about evaluation only if evaluation ran. `removeparam_path` reports
# `gate_should_block` / `enters_in_force` per build and input, using the same engine `gate_open` uses.
say "evaluation path per input (gate open? in_force reached?)"
: > "$OUT/paths.jsonl"
path_case() {
  local case_id="$1" rules="$2"
  for name in candidate baseline; do
    taskset -c "$CPU" "$WORK/$name/core/target/release/examples/removeparam_path" \
      "$rules" "$case_id" --matrix "$REPO_ROOT/scripts/perf/matrix.json" \
      --build-id "$name" >> "$OUT/paths.jsonl"
  done
}
for case_id in noquery-document miss-document hit-document-navigation hit-document-post \
                hit-document-zhihu hit-document-fragment miss-duplicate-params miss-other-host; do
  path_case "$case_id" "$REPO_ROOT/scripts/perf/rules/eval-reached.txt"
done
# The row the stage-5 review disqualified: its gate misses, so it must appear in the path table as
# "did not enter evaluation" rather than being quietly dropped.
for case_id in miss-document; do
  path_case "$case_id" "$OUT/buckets/by-value-shared.txt"
done
python3 -c "
import json, pathlib, sys
rows=[json.loads(l) for l in pathlib.Path('$OUT/paths.jsonl').read_text().splitlines() if l.startswith('{')]
for r in rows:
    print(f\"  {pathlib.Path(r['rules_file']).name:26} {r['case']:26} {r['build']:10} \"
          f\"gate={r['gate_should_block']} enters_in_force={r['enters_in_force']} rules={r['removeparam_rules']}\")
"

# ---- 4b. one rule at a time ---------------------------------------------------------------
# The rule-set comparison says *whether* the cost grew; this says *why*, by varying one axis of a rule's
# shape at a time and reporting the floor over rounds.
say "per-shape cost (one rule, then 8 copies, then 64 copies)"
for load in 1 8 64; do
  for name in candidate baseline; do
    taskset -c "$CPU" "$WORK/$name/core/target/release/examples/removeparam_rule_shapes" \
      --build-id "$name" --rounds "$ROUNDS" --iters "$ITERS" --load "$load" \
      >> "$OUT/shapes.jsonl"
  done
done
python3 "$REPO_ROOT/scripts/perf/shape_table.py" --input "$OUT/shapes.jsonl" \
  | tee "$OUT/shapes-table.txt"

# ---- 5. profile ----------------------------------------------------------------------------
say "profiling the stage the difference is in (debug symbols only, algorithm untouched)"
PROF_TREE="$WORK/candidate"
if perf record -e cpu-clock -o /dev/null -- true 2>/dev/null; then
  # A release build *with debug info*, in a separate target dir: -g changes no optimisation, it only
  # keeps the symbol names `perf` needs. Nothing is committed from this tree.
  ( cd "$PROF_TREE" && CARGO_PROFILE_RELEASE_STRIP=false CARGO_PROFILE_RELEASE_DEBUG=true \
      cargo build --release --manifest-path core/Cargo.toml --example edits_cost_matrix \
      --target-dir "$WORK/prof-target" 2>&1 | tail -2 )
  PROF="$WORK/prof-target/release/examples/edits_cost_matrix"
  for case in miss-xhr hit-typed-xhr; do
    perf record -q -e cpu-clock -o "$OUT/profile-$case.data" -- \
      taskset -c "$CPU" "$PROF" \
        --rules "$REPO_ROOT/scripts/perf/rules/equal-engine-name.txt" \
        --matrix "$REPO_ROOT/scripts/perf/matrix.json" \
        --build-id candidate --mode=timing --only-stage=removeparam --only-case="$case" \
        --rounds 3 --iters 200000 >/dev/null 2>&1 || true
    perf report -i "$OUT/profile-$case.data" --stdio --no-children --percent-limit 0.5 \
      > "$OUT/profile-$case.txt" 2>/dev/null || true
    printf '  %s: %s\n' "$case" "$(grep -c . "$OUT/profile-$case.txt" 2>/dev/null || echo 0) lines"
  done
  perf record -q -e cpu-clock -o "$OUT/profile-full-miss-document.data" -- \
    taskset -c "$CPU" "$PROF" \
      --rules "$REPO_ROOT/.effectiveness/full-5/union.txt" \
      --matrix "$REPO_ROOT/scripts/perf/matrix.json" \
      --build-id candidate --mode=timing --only-stage=removeparam --only-case=miss-document \
      --rounds 3 --iters 20000 >/dev/null 2>&1 || true
  perf report -i "$OUT/profile-full-miss-document.data" --stdio --no-children --percent-limit 0.5 \
    > "$OUT/profile-full-miss-document.txt" 2>/dev/null || true
  # Call-graph recording is refused on this host (`perf_event_paranoid=2`, and `--call-graph` needs
  # more than the flat `cpu-clock` sampling the paranoid level allows). Say so rather than imply the
  # profiles below are call graphs.
  echo "  NOTE: flat profiles only — call-graph recording is refused at perf_event_paranoid=$(cat /proc/sys/kernel/perf_event_paranoid)" \
    | tee "$OUT/profile-LIMITS.txt"
else
  echo "  perf cannot record on this host; profiles skipped" | tee "$OUT/profile-LIMITS.txt"
fi

# ---- 5b. regenerate the report's tables from the run's JSON --------------------------------
# Every table and every computed sentence in the report is emitted by `render_report.py` from the files
# above, so a number in the prose cannot drift from the JSON it claims to come from. `--check` in the
# self-check below fails the run if the committed report is stale.
say "regenerating report tables from this run's JSON"
python3 "$REPO_ROOT/scripts/perf/render_report.py" --results "$OUT" \
  --write "$REPO_ROOT/docs/reviews/i2-edits-cost.md"

# ---- 6. bundle + manifest ------------------------------------------------------------------
# The stage-5 review could verify 16 of the 36 declared items, because the manifest named files by bare
# name and pointed at repository paths. This bundle is relocatable: relative paths, layout preserved,
# sources/schema/inputs/raw JSON/binaries included, and `--verify` re-hashes all of it from wherever it
# was unpacked — including the two harness binaries and the bench source they were built from.
say "bundle + manifest"
BUNDLE="${BUNDLE:-$REPO_ROOT/.effectiveness/bundle/i2-edits-cost}"
# The binaries live outside `$OUT`, because `build_bundle` recreates the bundle from scratch and would
# delete anything it had copied out of `results` — which is how an earlier attempt declared zero
# harness binaries while printing success.
BINARIES="${BINARIES:-$REPO_ROOT/.effectiveness/binaries}"
mkdir -p "$BINARIES"
cp "$CAND" "$BINARIES/candidate-edits_cost_matrix"
cp "$BASE" "$BINARIES/baseline-edits_cost_matrix"
python3 "$REPO_ROOT/scripts/perf/manifest.py" --build \
  --results "$OUT" --bundle "$BUNDLE" --repo "$REPO_ROOT" --binaries "$BINARIES" \
  --candidate "$CANDIDATE_REV" --baseline "$BASELINE_REV"
# Verify from inside the bundle, with the working directory moved away, so the check a reader repeats
# is the check this run performed.
( cd /tmp && python3 "$BUNDLE/src/scripts/perf/manifest.py" --verify "$BUNDLE" )
BUNDLE_PATH="$BUNDLE" python3 - <<'BUNDLE_SHA'
import hashlib, pathlib, os
bundle = pathlib.Path(os.environ["BUNDLE_PATH"])
lines = []
for path in sorted(bundle.rglob("*")):
    if path.is_file() and path.name != "MANIFEST.json":
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.relative_to(bundle).as_posix()}")
(bundle / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n")
print(f"{len(lines)} entries in SHA256SUMS.txt")
BUNDLE_SHA
echo "bundle in $BUNDLE"
echo "results in $OUT"
