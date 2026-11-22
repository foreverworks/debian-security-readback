#!/bin/sh
# The readback against the Debian security tracker's real, current data, on the Debian system it
# runs on: it must download, parse and report, and stay within its memory budget. It catches a
# change in the tracker's formats. Read-only, but it downloads about 90 MB.
#
#   tests/integration/live.sh <command that runs the readback>...
set -eu

[ $# -gt 0 ] || { echo "usage: $0 <command that runs the readback>..." >&2; exit 2; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

status=0
"$@" --cache-dir "$work/cache" --out-dir "$work/out" > "$work/stdout" 2> "$work/stderr" || status=$?
if [ "$status" != 0 ]; then
  echo "the readback failed on live data (exit $status)" >&2
  cat "$work/stderr" >&2
  exit 1
fi
python3 -I - "$work/out/report.json" <<'EOF'
import json, sys
report = json.load(open(sys.argv[1]))
assert report["schema"] == 1 and "error" not in report, report
assert set(report["counts"]) == {"blocked", "installed_pending_activation", "available", "active"}, report["counts"]
assert report["peak_rss_mb"] < 512, "peak RSS %d MB" % report["peak_rss_mb"]
print("live: %s, %d fixes concern this system, peak %d MB" % (report["counts"], len(report["fixes"]), report["peak_rss_mb"]))
EOF
