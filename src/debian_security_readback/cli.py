"""debian-security-readback: the state of every Debian security fix on this host. Report only.

Exit codes: 0 the report is written; 1 the readback failed (a failure report is written in its
place); 2 the command line or the configuration is wrong; 3 the report is written and a fix is in
one of the states named by fail_on.
"""

import argparse
import datetime
import json
import os
import resource
import sys

from debian_security_readback import __version__
from debian_security_readback.collect import (
    collect_candidates,
    collect_docker,
    collect_holds,
    collect_incus,
    collect_installed,
    collect_pending,
    fetch,
)
from debian_security_readback.config import Config, ConfigError, from_mapping, load
from debian_security_readback.decide import classify, counts, relevant_packages
from debian_security_readback.facts import kernel_state, parse_os_release
from debian_security_readback.model import STATES, ReadbackError
from debian_security_readback.report import build, failed, render, render_failed
from debian_security_readback.sources import load_urgencies, validate_dsa_text

EXIT_OK, EXIT_FAILED, EXIT_USAGE, EXIT_FINDINGS = 0, 1, 2, 3


def detect_release(os_release_text: str) -> str:
    """The codename of a Debian release, from /etc/os-release. DSAs cover Debian only."""
    info = parse_os_release(os_release_text)
    if info.get("ID") != "debian":
        raise ReadbackError(
            "this is not Debian (ID=%s): DSAs cover Debian only; set `release` to read a derivative anyway"
            % info.get("ID", "unknown")
        )
    codename = info.get("VERSION_CODENAME", "")
    if not codename:
        raise ReadbackError("/etc/os-release names no VERSION_CODENAME; set `release`")
    return codename


def _write(path: str, text: str) -> None:
    with open(path + ".tmp", "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(path + ".tmp", path)


def readback(cfg: Config, host: str, today: datetime.date, proc_root: str = "/proc") -> int:
    """Gather, decide, write report.json and report.md, print the Markdown. Raises on any failure."""
    release = cfg.release
    if not release:
        with open("/etc/os-release", encoding="utf-8") as f:
            release = detect_release(f.read())
    os.makedirs(cfg.cache_dir, exist_ok=True)
    max_age_s = cfg.cache_max_age_hours * 3600

    def check_dsa(path: str) -> None:
        with open(path, encoding="utf-8", errors="replace") as f:
            validate_dsa_text(f.read(), release)

    def check_tracker(path: str) -> None:
        with open(path, encoding="utf-8") as f:
            load_urgencies(f, set(), release)

    notes: list[str] = []
    if os.geteuid() != 0:
        notes.append("not run as root: processes of other users were not read, so pending restarts may be missing")
    dsa_path, note = fetch(
        cfg.dsa_list_url, os.path.join(cfg.cache_dir, "dsa-list"), check_dsa, max_age_s, cfg.download_deadline_seconds
    )
    notes += [note] if note else []
    with open(dsa_path, encoding="utf-8", errors="replace") as f:
        fixes = validate_dsa_text(f.read(), release)
    tracker_path, note = fetch(
        cfg.tracker_url, os.path.join(cfg.cache_dir, "tracker.json"), check_tracker, max_age_s, cfg.download_deadline_seconds
    )
    notes += [note] if note else []
    with open(tracker_path, encoding="utf-8") as f:
        urgencies = load_urgencies(f, {x["source"] for x in fixes}, release)

    installed = collect_installed()
    kernel = kernel_state(installed, os.uname().release)
    holds = collect_holds()
    names = relevant_packages(fixes, installed) + [p["name"] for p in installed if p["name"].startswith("linux-image-")]
    candidates = collect_candidates(sorted(set(names)))
    pending = collect_pending(proc_root, cfg.container_cgroup_markers)
    rows = classify(fixes, installed, candidates, holds, pending, kernel, urgencies, today)
    docker = collect_docker() if cfg.docker else None
    incus = collect_incus() if cfg.incus else None

    peak_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024
    report = build(host, release, rows, kernel, docker, incus, today, notes, peak_mb)
    md = render(host, rows, kernel, docker, incus, today, notes, cfg.recent_days)
    os.makedirs(cfg.out_dir, exist_ok=True)
    _write(os.path.join(cfg.out_dir, "report.json"), json.dumps(report, indent=1) + "\n")
    _write(os.path.join(cfg.out_dir, "report.md"), md)
    print(md)
    print("SECURITY_READBACK counts=%s signature=%s" % (json.dumps(counts(rows)), report["signature"]))
    hit = [s for s in cfg.fail_on if report["counts"][s]]
    if hit:
        print("fail_on: %s" % ", ".join("%d %s" % (report["counts"][s], s) for s in hit), file=sys.stderr)
        return EXIT_FINDINGS
    return EXIT_OK


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="debian-security-readback",
        description="The state of every Debian security fix on this host: available, installed but not "
        "active yet, active, or blocked. Report only: it installs, restarts and removes nothing.",
        epilog="Exit codes: 0 report written, 1 readback failed, 2 usage or configuration error, "
        "3 report written and a fix is in a --fail-on state.",
    )
    ap.add_argument("--version", action="version", version="debian-security-readback " + __version__)
    ap.add_argument("--config", help="a TOML file (default: /etc/debian-security-readback.toml when it exists)")
    ap.add_argument("--host", help="the name in the report (default: the kernel's node name)")
    ap.add_argument("--release", help="the Debian codename (default: VERSION_CODENAME from /etc/os-release)")
    ap.add_argument("--cache-dir", help="where the tracker's files are kept between runs")
    ap.add_argument("--out-dir", help="where report.json and report.md are written")
    ap.add_argument(
        "--fail-on", metavar="STATE[,STATE]", help="exit 3 when a fix is in one of these states (%s)" % ", ".join(STATES)
    )
    return ap


def main(argv: list[str]) -> int:
    args = parser().parse_args(argv)
    flags: dict[str, object] = {
        k: v
        for k, v in (("host", args.host), ("release", args.release), ("cache_dir", args.cache_dir), ("out_dir", args.out_dir))
        if v is not None
    }
    if args.fail_on is not None:
        flags["fail_on"] = [s.strip() for s in str(args.fail_on).split(",") if s.strip()]
    try:
        cfg = from_mapping(flags, load(args.config))
    except ConfigError as e:
        print("debian-security-readback: configuration: %s" % e, file=sys.stderr)
        return EXIT_USAGE
    host = cfg.host or os.uname().nodename
    today = datetime.datetime.now(datetime.UTC).date()
    try:
        return readback(cfg, host, today)
    except Exception as e:  # any failure is a failed readback, never a clean one
        error = "%s: %s" % (type(e).__name__, e)
        print("security readback failed: %s" % error, file=sys.stderr)
        try:
            os.makedirs(cfg.out_dir, exist_ok=True)
            _write(os.path.join(cfg.out_dir, "report.json"), json.dumps(failed(host, today, error), indent=1) + "\n")
            _write(os.path.join(cfg.out_dir, "report.md"), render_failed(host, error))
        except OSError as w:
            print("and the failure report could not be written: %s" % w, file=sys.stderr)
        return EXIT_FAILED


def entry(argv: list[str] | None = None) -> int:
    return main(sys.argv[1:] if argv is None else argv)
