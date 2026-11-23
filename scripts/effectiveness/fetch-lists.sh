#!/usr/bin/env bash
# Download every filter list named in the built-in catalog (app/src/main/assets/filters/catalog.json).
#
# Usage: scripts/effectiveness/fetch-lists.sh [<out-dir>]
#
# The download is a normal part of the measurement: the coverage report must describe the lists the
# app would actually compile, not a stale snapshot. Each list is stored as `<id>.txt` in the output
# directory, and primary URLs are tried before mirrors exactly like `FilterRepository` does on the
# device. All downloads carry `If-Modified-Since` so a re-run inside the same cache window is cheap.
#
# Output: <out-dir>/<id>.txt, plus <out-dir>/manifest.json recording url, bytes, HTTP status and the
# UTC timestamp for each list — the coverage report quotes it, so a reader can tell which day's lists
# the numbers describe.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

OUT="${1:-.effectiveness/lists}"
mkdir -p "$OUT"

CATALOG="app/src/main/assets/filters/catalog.json"
[ -f "$CATALOG" ] || { echo "missing $CATALOG" >&2; exit 1; }

# One `<id>\t<url>\t<mirror>` line per list, in catalog order. `jq` is used when present because it
# is exact; the python fallback keeps the script runnable on a machine without it.
if command -v jq >/dev/null 2>&1; then
    rows="$(jq -r '.lists[] | [.id, .url, ((.mirrors // []) | join(" "))] | @tsv' "$CATALOG")"
else
    rows="$(python3 - "$CATALOG" <<'PY'
import json, sys
catalog = json.load(open(sys.argv[1]))
for entry in catalog["lists"]:
    print("\t".join([entry["id"], entry["url"], " ".join(entry.get("mirrors", []))]))
PY
)"
fi

fetched=0
failed=0
manifest="$OUT/manifest.json"
echo "[" >"$manifest"
first=1
while IFS=$'\t' read -r id url mirrors; do
    [ -n "$id" ] || continue
    dest="$OUT/$id.txt"
    status=""
    used=""
    for candidate in $url $mirrors; do
        # `-z` re-downloads only when the file changed; the coverage report is about content, and a
        # list that did not change must not churn the working tree.
        code="$(curl -sS -L -z "$dest" --max-time 180 -o "$dest" -w '%{http_code}' "$candidate" 2>/dev/null || echo 000)"
        if [ "$code" = "200" ] || [ "$code" = "304" ]; then
            status="$code"
            used="$candidate"
            break
        fi
    done
    if [ -z "$status" ]; then
        echo "  FAILED  $id (tried $url $mirrors)" >&2
        failed=$((failed + 1))
    else
        bytes="$(stat -c %s "$dest" 2>/dev/null || echo 0)"
        echo "  ok      $id  $code  $bytes B  $used"
        fetched=$((fetched + 1))
    fi
    [ $first -eq 1 ] || printf ',\n' >>"$manifest"
    first=0
    printf '  {"id": "%s", "url": "%s", "httpStatus": "%s", "bytes": %s, "fetchedAt": "%s"}' \
        "$id" "$used" "$status" "$bytes" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$manifest"
done <<<"$rows"
echo "" >>"$manifest"
echo "]" >>"$manifest"

echo
echo "fetched $fetched, failed $failed → $OUT"
[ "$failed" -eq 0 ]
