# debian-security-readback

**Know which Debian security fixes each host really runs.** For every Debian Security Advisory
that touches a package on the host, it tells you one of four things: the fix is **available** and
not installed yet, it is **installed but not active** because a process or the kernel still runs the
old code, it is **active**, or it is **blocked** by a hold or by an archive that does not carry it.
Report only: it never installs, restarts or removes anything.

For people who run Debian servers and want an honest answer to "are we patched?", one that does not
stop at "the package is installed".

One file, Python standard library only, runs as root on Debian 13. Typed. MIT.

## The problem

`apt list --upgradable` says what could be upgraded. Unattended upgrades say what was installed.
Neither says what is running:

- **Installed is not patched.** A daemon started before the upgrade keeps the old library mapped
  until it restarts. A new kernel does nothing until the next reboot. The package database says
  "fixed" while the vulnerable code is still in memory.
- **A held package fails quietly.** `apt-mark hold` keeps a package back, and then nothing reminds
  you that it is also keeping a security fix out.
- **The archive can lag.** A mirror or a snapshot that does not carry the fixed version yet makes
  `apt upgrade` report nothing to do, which looks exactly like being up to date.
- **Tools that find stale processes tend to fix them too.** `needrestart` is the usual answer, and
  its apt hook restarts services during upgrades unless you configure it not to. On a host where
  restarts are planned, that is not wanted.

debian-security-readback puts the advisory, the package, the archive, the running processes and the
kernel side by side and gives each fix one state, so nothing held back or still running old code
ever reads as patched.

## What it checks

It reads the [Debian security tracker](https://security-tracker.debian.org/): the DSA list (each
advisory's date, source package, fixed version for your release and CVEs) and the tracker's JSON (the
urgency of each CVE). Then, on the host:

| State | Means |
|---|---|
| `blocked` | Not installed and not installable: the package is on hold, or the archive this host sees offers no version at or above the fix. |
| `installed_pending_activation` | Installed, but a running process still maps a deleted file of the package, or the running kernel is older than the fixed one. |
| `available` | The fixed version is in the archive and installable here, and not installed yet. |
| `active` | Installed, and nothing running still holds the old code. |

The rules behind them:

- **Every binary package counts.** A source package builds several binaries; the fix is only
  installed when every one of them on the host is at or above the fixed version. One old library
  is enough to keep the fix from being installed.
- **Versions compare the way dpkg compares them** (epochs, `~`, revisions), using the source
  version, so binNMUs and binaries with their own version numbers are handled.
- **Pending restarts come from `/proc`.** It scans `/proc/<pid>/maps` and `/proc/<pid>/exe` for
  files that no longer exist on disk, asks dpkg which package owns each path, and names the processes
  in the report. Nothing is installed for this and nothing can be restarted by it.
- **Containers are not the host.** A process inside a Docker, Podman, Incus, LXC, systemd-nspawn or
  Kubernetes container is recognised by its cgroup and left out: its libraries are the container's.
  A host service with its own mount namespace (`PrivateTmp`, `ProtectSystem`) is still a host process.
- **The kernel is a package like the others,** compared through the installed `linux-image-*`
  packages: the newest installed one decides installed or not, and the one matching `uname -r`
  decides whether it is active. A held kernel metapackage blocks the fix.
- **Containers behind their image.** It also lists running Docker containers whose image tag now
  points to a newer image, and running Incus instances that have a newer local image of the same
  release. These are reported separately: a rebuilt userland image never counts as activation of a
  host kernel fix.
- **Bad data fails loudly.** A DSA list or tracker file that does not look like the real thing
  (an error page, a captive portal, a truncated download) fails the readback. It is never read as
  "no fixes". A download that fails keeps the previous copy and the report says how old it is.
- **Downloads are bounded.** Only `https://` and `file://` URLs are accepted, a redirect never
  leaves https, every read waits at most the time left before the deadline, and a file larger than
  its cap is refused.
- **It writes carefully.** Reports and downloads go through a fresh temporary file renamed into
  place, never through a symlink, and only into directories that belong to the running user and
  that nobody else can write to. A lock in the cache directory keeps two runs from overlapping.

## Quick start

**1. Download a release and check it.** One file, any Python 3.13 or newer:

```sh
v=0.1.0
curl -fsSLO "https://github.com/foreverworks/debian-security-readback/releases/download/v$v/debian-security-readback-$v.pyz"
curl -fsSLO "https://github.com/foreverworks/debian-security-readback/releases/download/v$v/debian-security-readback-$v.pyz.sha256"
sha256sum -c "debian-security-readback-$v.pyz.sha256"
sudo install -D -m 0755 "debian-security-readback-$v.pyz" /usr/local/lib/debian-security-readback/debian-security-readback.pyz
```

**2. Run it as root.** Root is needed to read every process's memory map; without it, the report
says that pending restarts may be missing.

```sh
sudo python3 -I /usr/local/lib/debian-security-readback/debian-security-readback.pyz
```

Within a state, the oldest advisory comes first. The first run downloads the tracker's files (about 90 MB, kept for 20 hours in
`/var/cache/debian-security-readback`). It prints the report and writes `report.md` and `report.json`
to `/var/lib/debian-security-readback`:

```
Security readback: web1, 2026-11-21

Kernel: running 6.12.57+deb13-amd64 (package 6.12.57-1), installed newest 6.12.70-1

| state | fixes |
|---|---|
| blocked | 1 |
| installed_pending_activation | 2 |
| available | 0 |
| active | 41 |

### Not active

| state | DSA | date | package | fixed in | urgency | detail |
|---|---|---|---|---|---|---|
| blocked | DSA-6646-1 | 2026-11-20 | gpgme1.0 | 1.24.2-3+deb13u1 | medium | on hold: libgpgme11t64 |
| installed_pending_activation | DSA-6612-1 | 2026-11-08 | openssl | 3.5.4-1~deb13u2 | high | stale processes: nginx(812), sshd(655) |
| installed_pending_activation | DSA-6630-1 | 2026-11-17 | linux | 6.12.70-1 | high | running kernel 6.12.57-1 older than 6.12.70-1; reboot pending |
```

**3. Run it every day.** The `examples/` directory has a systemd service and timer:

```sh
sudo install -m 0644 examples/debian-security-readback.service examples/debian-security-readback.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now debian-security-readback.timer
```

**4. Get told.** Point your monitoring at `report.json`, use `--fail-on` to turn findings into an
exit code, or keep one GitHub issue per host with `contrib/github-issue-report` (below).

## Configuration

Everything works without a configuration file. To change something, write
`/etc/debian-security-readback.toml` (or pass `--config <file>`). [examples/config.toml](examples/config.toml)
lists every key at its default. A key the tool does not know, or a value of the wrong type, is an
error (exit 2), never ignored.

| Key | Default | Meaning |
|---|---|---|
| `host` | the kernel's node name | The name the report carries. |
| `release` | `VERSION_CODENAME` from `/etc/os-release` | The Debian release to read fixes for, such as `trixie`. On a system that is not Debian it must be set, and it only makes sense if the system really uses that Debian release's packages. |
| `cache_dir` | `/var/cache/debian-security-readback` | Where the tracker's files and the lock are kept between runs. An absolute path. |
| `out_dir` | `/var/lib/debian-security-readback` | Where `report.json` and `report.md` are written. An absolute path. |
| `dsa_list_url` | the tracker's `data/DSA/list` on salsa.debian.org | The DSA list. An `https://` mirror works, and so does a `file://` URL. Nothing else is accepted. |
| `tracker_url` | `https://security-tracker.debian.org/tracker/data/json` | The tracker's JSON, from the same kinds of URL. |
| `cache_max_age_hours` | `20` | A cached copy younger than this is used without downloading. |
| `download_deadline_seconds` | `300` | A download that takes longer counts as failed (the cached copy is then used, with a warning). 1 or more. |
| `dsa_list_max_mib`, `tracker_max_mib` | `64`, `512` | The largest download accepted. The real files are about 1.3 MB and 90 MB. |
| `command_timeout_seconds` | `120` | How long each dpkg, apt, docker or incus call may take. A dpkg or apt call that runs out fails the readback; a docker or incus one skips that check. 1 or more. |
| `report_mode` | `0o640` | The file mode of `report.json` and `report.md`. |
| `recent_days` | `30` | The report counts the active fixes published in this many days. |
| `container_cgroup_patterns` | Docker, Podman, Incus and LXC, systemd-nspawn, Kubernetes, CRI-O | Regular expressions searched in each path of `/proc/<pid>/cgroup` that mark a container's process. Each matches whole path components (`docker-<id>.scope`, `lxc.payload.<name>`), so `docker.service` or `incus.service` never match. Setting the key replaces the list; [examples/config.toml](examples/config.toml) shows the defaults. |
| `docker` | `true` | List running Docker containers behind their image tag. Skipped quietly when Docker is not there. |
| `incus` | `true` | List running Incus instances behind their newest local image. Skipped quietly when Incus is not there. |
| `fail_on` | `[]` | States that turn the exit code into 3, for example `["blocked", "available"]`. |

Flags win over the file: `--host`, `--release`, `--cache-dir`, `--out-dir`, and `--fail-on
STATE[,STATE]`. `--version` prints the version.

For a host without internet access, copy the two files there by any means and point the URLs at
them with `file:///path/to/dsa-list` and `file:///path/to/json`. Behind a proxy, `https_proxy` and
`no_proxy` in the environment are honoured.

Every command it runs (dpkg-query, apt-cache, apt-mark, docker, incus) runs in the C locale, because
their output is parsed.

## Output

**`report.md`** is the report above, for people: counts per state, every fix that is not active with
its reason, how many active fixes are recent, the containers behind their image, and a warning line
for each thing that may make the report incomplete (a stale cached download, not running as root).

**`report.json`** carries the same, for programs:

| Field | Holds |
|---|---|
| `schema` | `1`. A later release that changes the meaning of a field raises it. |
| `tool`, `version` | `debian-security-readback` and its version. |
| `host`, `release`, `date` | What was read, and the day (UTC). |
| `counts` | `{"blocked": n, "installed_pending_activation": n, "available": n, "active": n}` |
| `fixes` | One object per fix that concerns the host, worst state first: `state`, `reason`, `dsa`, `date`, `age_days`, `source`, `fixed_version`, `cves`, `urgency` (the highest the tracker gives any of its CVEs for the release, or `unknown`). |
| `kernel` | `installed` (newest linux-image version), `running` (the version of the running one's package, or null), `release` (`uname -r`). |
| `docker_stale`, `incus_stale` | Lists of containers behind their image, or null when the tool is not there or did not answer. |
| `notes` | The warnings shown in the Markdown. |
| `signature` | 12 hex digits that change when the set of fixes not yet active changes (a fix appears, changes state or becomes active). Compare it with the last run's to alert on change instead of on every run. |
| `peak_rss_mb` | The readback's own peak memory, in MB (usually around 200). |

Both files are written with `report_mode` (0640 by default). When the readback fails, both are
replaced by a failure report, so an old clean report is never left behind (the error appears as an
indented code block in `report.md`): `report.json` is `{"schema": 1, ..., "error": "<what went wrong>", "signature":
"failed"}`.

The last line on standard output is one line for log scrapers:
`SECURITY_READBACK counts={...} signature=<12 hex digits>`.

## Exit codes

| Code | Means |
|---|---|
| `0` | The report is written. |
| `1` | The readback failed (bad or missing source data, dpkg or apt failing or not answering). A failure report is written in place of the report, and the error goes to standard error. Two cases leave the reports alone: another run holds the lock, or the output directory is unsafe (not the running user's, or writable by others). |
| `2` | The command line or the configuration is wrong. Nothing is written. |
| `3` | The report is written, and at least one fix is in a state named by `fail_on`. |

## One GitHub issue per host

`contrib/github-issue-report` turns reports into GitHub issues, for a set of hosts whose nightly CI job
collects each host's `report.md` and `report.json`. It keeps one open issue per host, updated in
place, closes it once every fix is active, and keeps it open (and says so) when a readback failed.
It needs `gh` and `jq`.

```sh
contrib/github-issue-report --repo acme/ops --notify /usr/local/bin/notify-chat \
  web1 web1.report.md web1.report.json "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
```

`--notify COMMAND` runs only when the picture changed, or when the readback started failing (once
per failure streak), as `COMMAND <title> <priority> <tag> <message>`: priority `high` with tag
`warning` for a failure, `default` with `shield` otherwise. `--label` (default `security-readback`)
and `--title-prefix` (default `Security readback: `) name the issues.

## Supported systems

- **Debian 13 (trixie)** is the target and the system every release is tested on, as root, against
  a fixture with known states and against the tracker's live data.
- **Python 3.13 and newer.** The tests run on 3.13, 3.14 and 3.15 before every release; Debian 13
  ships 3.13.
- **Debian 12 (bookworm) and older** are out of scope: their fixes are now published as Debian LTS
  advisories (DLAs), which this tool does not read, and bookworm's Python 3.11 is below the floor.
- **Debian testing and unstable** get no DSAs, so there is nothing to read. On testing the readback
  fails with `the DSA list has no fixes for forky: DSAs are published for Debian stable releases
  only, not for testing or unstable`. On unstable, whose `/etc/os-release` often names no
  `VERSION_CODENAME`, it fails saying so. Debian 14 should work once it is released and has DSAs of
  its own.
- **Derivatives** (Ubuntu and others) publish their own advisories. The tool refuses to guess on a
  system whose `/etc/os-release` is not Debian, unless `release` is set.
- amd64 and arm64 make no difference to the readback; it reads package versions, not binaries.

## Limitations

- **DSAs only.** Fixes published only in a point release, through `bookworm-updates`, or as a DLA are
  not read. A CVE the security team decided not to fix with a DSA is not reported.
- **"Active" is about mapped files.** Code read from an interpreter's source files (a Python or
  Perl daemon whose modules were upgraded) is not mapped, so a running interpreter that has not
  reloaded them is not seen. A library loaded from outside `/usr`, `/lib`, `/bin`, `/sbin` and
  `/opt` is not counted either, unless it is the process's own executable.
- **Processes are seen from the host.** A container's own pending restarts are not reported; run
  the readback inside the container, or rebuild its image.
- **The kernel needs a package.** A host booted from a kernel no `linux-image-*` package installed
  (a cloud provider's kernel, a container) has its kernel fixes left out.
- **Containers behind their image** are a hint: a Docker tag that moved, or an Incus image with a
  newer serial. Whether the new image carries the fix is the image's business.
- **Unowned paths go unnoticed.** `dpkg-query -S` exits 1 when any path it is asked about belongs
  to no package, so its exit status cannot tell a failure from that. A deleted file it gives no owner
  for is left out of the pending restarts.
- **Trust.** The tracker's files are fetched over HTTPS and checked for shape, not signature: the
  DSA list and the tracker's JSON are not signed by Debian.

## Verify a release

Each release has one asset, `debian-security-readback-X.Y.Z.pyz`, and its sha256 in
`debian-security-readback-X.Y.Z.pyz.sha256`. The asset is built by `scripts/build-pyz`, which is
reproducible: the same commit gives the same bytes. To check that a release is the code it says it is:

```sh
git clone https://github.com/foreverworks/debian-security-readback
git -C debian-security-readback checkout v0.1.0
debian-security-readback/scripts/build-pyz /tmp/rebuilt
cat /tmp/rebuilt/debian-security-readback-0.1.0.pyz.sha256   # the same sha256 as the release's
```

A release is published only from a tag on `main`, and only after the full test matrix passed.

## Development

```sh
python3 -m unittest discover -s tests -t .              # unit and end-to-end tests, no root needed
pip install -r requirements-dev.txt
ruff check && ruff format --check && mypy               # lint and types, at the Python 3.13 floor
shellcheck contrib/github-issue-report scripts/build-pyz tests/integration/*.sh
```

`tests/integration/debian.sh` and `tests/integration/live.sh` run the readback on a real Debian
system as root. The first installs test packages and an apt source, so run it only in a throwaway
container (with `--privileged` it also puts a process into a container's cgroup and checks that it
is left out): `docker run --rm -v "$PWD:/src:ro" debian:trixie sh -c 'apt-get update && apt-get install
-y python3 && cp -r /src /w && /w/tests/integration/debian.sh python3 -I /w/bin/debian-security-readback'`.

Every push runs the tests on the newest stable Python and checks types and lint against 3.13. Every
week, and before each release, the tests run on every supported Python and on Debian 13 as root.

## License

MIT. See [LICENSE](LICENSE).
