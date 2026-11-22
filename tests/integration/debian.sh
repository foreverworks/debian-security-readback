#!/bin/sh
# The readback on a real Debian system, as root, in a throwaway container or VM: real dpkg, apt,
# holds and a process still running an upgraded binary. The tracker's data is a local fixture, so the
# states to expect are known. It installs test packages and an apt source: never run it on a host
# you care about.
#
#   tests/integration/debian.sh <command that runs the readback>...
#   e.g. tests/integration/debian.sh python3 dist/debian-security-readback-0.1.0.pyz
set -eu

[ "$(id -u)" = 0 ] || { echo "run as root, in a throwaway Debian container" >&2; exit 2; }
[ $# -gt 0 ] || { echo "usage: $0 <command that runs the readback>..." >&2; exit 2; }
# shellcheck disable=SC1091
release=$(. /etc/os-release && echo "$VERSION_CODENAME")
work=$(mktemp -d)
chmod 755 "$work"  # apt reads the local source as its own unprivileged user
sleeper="" contained="" cg=""
cleanup() {
  for pid in $sleeper $contained; do kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; done
  [ -z "$cg" ] || rmdir "$cg" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT
mkdir -p "$work/build" "$work/repo" "$work/old"

# A package that ships one executable, so a process can keep running the old one after an upgrade.
mk_deb() {  # name version outdir
  d="$work/build/$1-$2"
  mkdir -p "$d/DEBIAN" "$d/usr/bin"
  cp /bin/sleep "$d/usr/bin/$1"
  printf 'Package: %s\nVersion: %s\nArchitecture: all\nMaintainer: Nobody <nobody@example.com>\nDescription: readback test package\n' \
    "$1" "$2" > "$d/DEBIAN/control"
  dpkg-deb --root-owner-group --build "$d" "$3/$1_$2_all.deb" > /dev/null
}

for p in demo-avail demo-held demo-short demo-pending demo-contained; do mk_deb "$p" 1.0-1 "$work/old"; done
mk_deb demo-active 1.0-2 "$work/old"
for p in demo-avail demo-held demo-pending demo-contained; do mk_deb "$p" 1.0-2 "$work/repo"; done
dpkg -i "$work"/old/*.deb > /dev/null
apt-mark hold demo-held > /dev/null

# A local apt source offering the 1.0-2 builds.
for deb in "$work"/repo/*.deb; do
  dpkg-deb -f "$deb"
  printf 'Filename: ./%s\nSize: %s\nSHA256: %s\n\n' "$(basename "$deb")" "$(stat -c %s "$deb")" "$(sha256sum "$deb" | cut -d' ' -f1)"
done > "$work/repo/Packages"
echo "deb [trusted=yes] file:$work/repo ./" > /etc/apt/sources.list.d/readback-test.list
apt-get update -qq -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/readback-test.list -o Dir::Etc::sourceparts=- \
  -o APT::Get::List-Cleanup=0

# A process that keeps the 1.0-1 binary of demo-pending, then the upgrade that deletes it.
/usr/bin/demo-pending 600 &
sleeper=$!

# The same, for a process moved into a cgroup named like a Docker container's, where the container
# lets us create one: the readback must leave it out. Where cgroups are read-only it stays a host
# process, and its fix reads as pending like the other.
/usr/bin/demo-contained 600 &
contained=$!
contained_state=installed_pending_activation
cg="/sys/fs/cgroup/docker-$(printf '%064d' 0).scope"
if mkdir "$cg" 2>/dev/null && echo "$contained" > "$cg/cgroup.procs" 2>/dev/null; then
  contained_state=active
  echo "integration: a process sits in $cg"
else
  rmdir "$cg" 2>/dev/null || true
  cg=""
  echo "integration: cgroups are read-only here, so the container exclusion is not exercised on a real cgroup"
fi
dpkg -i "$work/repo/demo-pending_1.0-2_all.deb" "$work/repo/demo-contained_1.0-2_all.deb" > /dev/null

# The tracker's data: the five fixes, plus filler so it passes the size checks.
{
  n=0
  for p in demo-avail demo-held demo-short demo-active demo-pending demo-contained; do
    n=$((n + 1))
    printf '[20 Nov 2026] DSA-990%s-1 %s - security update\n\t{CVE-2026-990%s}\n\t[%s] - %s 1.0-2\n' \
      "$n" "$p" "$n" "$release" "$p"
  done
  i=0
  while [ $i -lt 120 ]; do
    printf '[01 Nov 2026] DSA-%s-1 filler%s - security update\n\t[%s] - filler%s 1-1\n' "$i" "$i" "$release" "$i"
    i=$((i + 1))
  done
} > "$work/dsa-list"
{
  printf '{\n "demo-held": {"CVE-2026-9902": {"releases": {"%s": {"urgency": "high"}}}}' "$release"
  i=0
  while [ $i -lt 1100 ]; do
    printf ',\n "filler%s": {"CVE-1-%s": {"releases": {"%s": {"urgency": "low"}}}}' "$i" "$i" "$release"
    i=$((i + 1))
  done
  printf '\n}\n'
} > "$work/tracker.json"

cat > "$work/config.toml" <<EOF
host = "integration.example.org"
cache_dir = "$work/cache"
out_dir = "$work/out"
dsa_list_url = "file://$work/dsa-list"
tracker_url = "file://$work/tracker.json"
# The container's own processes sit at the root of its cgroup namespace and count as host processes;
# the default patterns stay, so a process moved into a cgroup named like a container's is left out.
EOF

status=0
"$@" --config "$work/config.toml" --fail-on blocked > "$work/stdout" 2> "$work/stderr" || status=$?
if [ "$status" != 3 ]; then
  echo "expected exit 3 (a blocked fix), got $status" >&2
  cat "$work/stdout" "$work/stderr" >&2
  exit 1
fi
python3 -I - "$work/out/report.json" "$release" "$contained_state" <<'EOF'
import json, sys
report = json.load(open(sys.argv[1]))
states = {f["source"]: (f["state"], f["reason"]) for f in report["fixes"] if f["source"].startswith("demo-")}
want = {
    "demo-avail": "available",
    "demo-held": "blocked",
    "demo-short": "blocked",
    "demo-active": "active",
    "demo-pending": "installed_pending_activation",
    "demo-contained": sys.argv[3],
}
got = {k: v[0] for k, v in states.items()}
assert got == want, (got, states)
assert states["demo-held"][1] == "on hold: demo-held", states
assert states["demo-short"][1].startswith("archive offers no 1.0-2"), states
assert "demo-pending(" in states["demo-pending"][1], states
assert report["release"] == sys.argv[2] and report["host"] == "integration.example.org", report
assert report["notes"] == [], report["notes"]
assert [f["urgency"] for f in report["fixes"] if f["source"] == "demo-held"] == ["high"]
print("integration: every state as expected:", ", ".join("%s %s" % kv for kv in sorted(got.items())))
EOF
grep -q '^SECURITY_READBACK counts=' "$work/stdout"

# Bad source data and no cache: a failed readback, and a failure report in place of the old one.
sed -i "s|^dsa_list_url = .*|dsa_list_url = \"file://$work/missing\"|; s|^cache_dir = .*|cache_dir = \"$work/cache2\"|" \
  "$work/config.toml"
status=0
"$@" --config "$work/config.toml" > /dev/null 2>&1 || status=$?
[ "$status" = 1 ] || { echo "expected exit 1 on missing source data, got $status" >&2; exit 1; }
grep -q '"signature": "failed"' "$work/out/report.json"
echo "integration: a failed readback is reported as failed"
