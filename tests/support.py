"""Shared fixtures: made-up tracker data and a fake host, nothing from a real machine."""

import datetime
import json
import os
import stat
from pathlib import Path

from debian_security_readback.model import Fix, Kernel, Package

ROOT = Path(__file__).resolve().parents[1]

DSA = """[20 Nov 2026] DSA-6646-1 gpgme1.0 - security update
\t{CVE-2026-1 CVE-2026-2}
\t[bookworm] - gpgme1.0 1.18.0-3+deb12u2
\t[trixie] - gpgme1.0 1.24.2-3+deb13u1
[19 Nov 2026] DSA-6600-1 linux - security update
\t{CVE-2026-9}
\t[trixie] - linux 6.12.70-1
[18 Nov 2026] DSA-6500-1 oldthing - security update
\t[bookworm] - oldthing 1.0-1
\t[trixie] - oldthing <not-affected> (Vulnerable code not present)
"""
TODAY = datetime.date(2026, 11, 21)
NOKERNEL: Kernel = {"installed": None, "running": None, "release": "x"}


def filler_dsa(n: int = 120) -> str:
    """n more DSA entries for packages no host has, so a fixture passes the size check."""
    return "".join("[01 Nov 2026] DSA-%d-1 p%d - security update\n\t[trixie] - p%d 1-1\n" % (i, i, i) for i in range(n))


def tracker_text(n: int = 1500, extra: dict[str, dict[str, str]] | None = None) -> str:
    """A tracker JSON of n made-up packages, plus `extra` {source: {cve: urgency}}."""
    d = {"pkg%d" % i: {"CVE-%d" % i: {"description": "x" * 50, "releases": {"trixie": {"urgency": "high"}}}} for i in range(n)}
    for src, cves in (extra or {}).items():
        d[src] = {cve: {"releases": {"trixie": {"urgency": u}}} for cve, u in cves.items()}
    return json.dumps(d, indent=1)


def pkg(name: str, sv: str, source: str | None = None) -> Package:
    return {"name": name, "version": sv, "source": source or name, "source_version": sv}


def fix(source: str = "gpgme1.0", fixed: str = "1.24.2-3+deb13u1") -> Fix:
    return {"source": source, "fixed_version": fixed, "dsa": "DSA-1", "date": "2026-11-20", "cves": []}


def executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def env_with_path(bindir: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["PATH"] = "%s:%s" % (bindir, env.get("PATH", "/usr/bin:/bin"))
    return env
