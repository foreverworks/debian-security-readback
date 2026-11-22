"""The report, as Markdown for people and JSON for programs. Pure."""

import datetime
from typing import TypedDict

from debian_security_readback import __version__
from debian_security_readback.decide import counts, signature
from debian_security_readback.model import STATES, Kernel, Row, StaleDocker, StaleIncus, State

SCHEMA = 1


class Report(TypedDict):
    schema: int
    tool: str
    version: str
    host: str
    release: str
    date: str
    notes: list[str]
    peak_rss_mb: int
    kernel: Kernel
    counts: dict[State, int]
    signature: str
    fixes: list[Row]
    docker_stale: list[StaleDocker] | None
    incus_stale: list[StaleIncus] | None


class FailedReport(TypedDict):
    schema: int
    tool: str
    version: str
    host: str
    date: str
    error: str
    signature: str


def build(
    host: str,
    release: str,
    rows: list[Row],
    kernel: Kernel,
    docker: list[StaleDocker] | None,
    incus: list[StaleIncus] | None,
    today: datetime.date,
    notes: list[str],
    peak_rss_mb: int,
) -> Report:
    return {
        "schema": SCHEMA,
        "tool": "debian-security-readback",
        "version": __version__,
        "host": host,
        "release": release,
        "date": today.isoformat(),
        "notes": notes,
        "peak_rss_mb": peak_rss_mb,
        "kernel": kernel,
        "counts": counts(rows),
        "signature": signature(rows),
        "fixes": rows,
        "docker_stale": docker,
        "incus_stale": incus,
    }


def failed(host: str, today: datetime.date, error: str) -> FailedReport:
    """What a failed readback leaves behind: an error, and a signature that never reads as clean."""
    return {
        "schema": SCHEMA,
        "tool": "debian-security-readback",
        "version": __version__,
        "host": host,
        "date": today.isoformat(),
        "error": error,
        "signature": "failed",
    }


def render_failed(host: str, error: str) -> str:
    return "Security readback failed on %s:\n\n%s\n" % (host, error)


def _containers(name: str, items: list[StaleDocker] | list[StaleIncus] | None, lines: list[str]) -> list[str]:
    head = ["", "### %s containers behind their image" % name]
    if items is None:
        return [*head, "Not present or not readable on this host."]
    if not items:
        return [*head, "None: every running one is on the image its tag points to."]
    return head + lines


def render(
    host: str,
    rows: list[Row],
    kernel: Kernel,
    docker: list[StaleDocker] | None,
    incus: list[StaleIncus] | None,
    today: datetime.date,
    notes: list[str] | tuple[str, ...] = (),
    recent_days: int = 30,
) -> str:
    """The report as Markdown: counts, every fix not yet active, the recent active ones as a count."""
    c = counts(rows)
    lines = [
        "Security readback: %s, %s" % (host, today.isoformat()),
        "",
        "Kernel: running `%s` (package %s), installed newest %s"
        % (kernel["release"], kernel["running"] or "unknown", kernel["installed"] or "none"),
        "",
        "| state | fixes |",
        "|---|---|",
    ]
    lines += ["| %s | %d |" % (s, c[s]) for s in STATES]
    lines += ["", *("**Warning:** " + n for n in notes)]
    lines += [
        "",
        "A fix counts as `active` only when installed and no running process holds the old code; "
        "held or blocked packages are never shown as patched.",
        "",
    ]
    open_rows = [r for r in rows if r["state"] != "active"]
    if open_rows:
        lines += [
            "### Not active",
            "",
            "| state | DSA | date | package | fixed in | urgency | detail |",
            "|---|---|---|---|---|---|---|",
        ]
        lines += [
            "| %s | %s | %s | %s | %s | %s | %s |"
            % (r["state"], r["dsa"], r["date"], r["source"], r["fixed_version"], r["urgency"], r["reason"])
            for r in open_rows
        ]
        lines.append("")
    recent = [r for r in rows if r["state"] == "active" and r["age_days"] <= recent_days]
    lines.append(
        "Active in the last %d days: %d of %d (the full list is in report.json)." % (recent_days, len(recent), c["active"])
    )
    lines += _containers(
        "Docker",
        docker,
        [
            "- %s runs %s %.19s, the tag is now %.19s" % (d["name"], d["image"], d["image_id"], d["current_id"])
            for d in docker or []
        ],
    )
    lines += _containers(
        "Incus",
        incus,
        [
            "- %s/%s runs image %.12s, newer local image %.12s" % (i["project"], i["name"], i["fingerprint"], i["newer"])
            for i in incus or []
        ],
    )
    lines += ["", "A rebuilt userland image never counts as activation of a host kernel fix."]
    return "\n".join(lines) + "\n"
