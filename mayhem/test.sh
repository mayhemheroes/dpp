#!/usr/bin/env bash
#
# dpp/mayhem/test.sh — RUN the self-contained golden parse oracle (dpp_oracle, built by
# mayhem/build.sh) and emit a CTRF summary. exit 0 iff every check passed.
#
# WHY a custom oracle and not DPP's own suite: src/unittest needs a live DISCORD_TOKEN and
# network access (it connects a real shard), so it cannot run offline in the build container.
# dpp_oracle instead drives the EXACT fuzzed path — Discord JSON -> message/user::fill_from_json
# — over known payloads and asserts the extracted fields, plus asserts malformed JSON is
# rejected. It is PATCH-grade: a no-op/early-return change to the parser flips the assertions.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${OUT:=/mayhem}"

ORACLE="$OUT/dpp_oracle"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-${SRC:-/mayhem}/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -x "$ORACLE" ]; then
  echo "missing $ORACLE — run mayhem/build.sh first" >&2
  emit_ctrf "dpp-json-oracle" 0 1 0; exit 2
fi

echo "=== running $ORACLE ==="
out="$("$ORACLE" 2>&1)"; rc=$?
echo "$out"

# Count TAP-ish "ok -" / "not ok -" lines emitted by the oracle.
PASSED=$(printf '%s\n' "$out" | grep -c '^ok - ')
FAILED=$(printf '%s\n' "$out" | grep -c '^not ok - ')
: "${PASSED:=0}" "${FAILED:=0}"

# If nothing parsed, fall back to the exit code (oracle returns #failures).
if [ "$(( PASSED + FAILED ))" -eq 0 ]; then
  echo "could not parse oracle output; using exit code $rc" >&2
  [ "$rc" -eq 0 ] && { emit_ctrf "dpp-json-oracle" 1 0 0; exit 0; }
  emit_ctrf "dpp-json-oracle" 0 1 0; exit 1
fi

# Cross-check the parsed tally against the process exit code (oracle returns the failure count).
if [ "$rc" -ne 0 ] && [ "$FAILED" -eq 0 ]; then
  FAILED=1   # exit code disagrees with parsed output — treat as a failure
fi

emit_ctrf "dpp-json-oracle" "$PASSED" "$FAILED" 0
