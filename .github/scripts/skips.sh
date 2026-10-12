#!/usr/bin/env bash
# Lists skipped tests in the job summary, failing on a reason matching $2.
set -euo pipefail

json=$1
forbid=${2:-}

skips=$(jq -rs '
  map(select(.Test != null))
  | group_by([.Package, .Test])
  | map(select(any(.[]; .Action == "skip")))
  | .[]
  | [.[0].Package, .[0].Test,
     ([.[] | select(.Action == "output") | .Output
       | select(test("^\\s+\\S+\\.go:\\d+: ")) | sub("^\\s+"; "") | rtrimstr("\n")]
      | join(" "))]
  | @tsv' "$json")

{
	echo "### Skipped tests"
	if [ -z "$skips" ]; then
		echo "None."
	else
		echo "| Package | Test | Reason |"
		echo "|---|---|---|"
		while IFS=$'\t' read -r pkg test reason; do
			echo "| ${pkg} | ${test} | ${reason//|/\\|} |"
		done <<<"$skips"
	fi
} >>"$GITHUB_STEP_SUMMARY"

[ -n "$forbid" ] || exit 0
failed=0
while IFS=$'\t' read -r _ test reason; do
	echo "::error::$test should run in this job but was skipped: $reason"
	failed=1
done < <(grep -E -- "$forbid" <<<"$skips" || true)
exit "$failed"
